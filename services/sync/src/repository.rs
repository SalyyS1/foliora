use crate::{
    OpaqueSyncStore, ServiceError, StorageLimits, StoreOutcome, VaultStatus,
    MAX_PAIRING_CONFIRMATION_ATTEMPTS,
};
use async_trait::async_trait;
use foliora_sync::{DeviceRecord, EncryptedObject, SignedManifest, SignedPairingGrant};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Mutex};
use subtle::ConstantTimeEq;

#[derive(Debug)]
pub enum RepositoryError {
    Service(ServiceError),
    TokenConflict,
    Unauthorized,
    Unavailable,
}

impl From<ServiceError> for RepositoryError {
    fn from(value: ServiceError) -> Self {
        Self::Service(value)
    }
}

#[derive(Clone)]
pub struct Principal {
    pub vault_id: String,
    pub device_id: String,
}

#[async_trait]
pub trait SyncRepository: Send + Sync {
    async fn ready(&self) -> Result<(), RepositoryError>;
    async fn authenticate(&self, token_hash: [u8; 32]) -> Result<Principal, RepositoryError>;
    async fn create_vault(
        &self,
        vault_id: String,
        device: DeviceRecord,
        quota_bytes: u64,
        token_hash: [u8; 32],
    ) -> Result<(), RepositoryError>;
    async fn status(&self, principal: &Principal) -> Result<VaultStatus, RepositoryError>;
    async fn pair_device(
        &self,
        principal: &Principal,
        grant: SignedPairingGrant,
        token_hash: [u8; 32],
        expires_at_unix: u64,
    ) -> Result<(), RepositoryError>;
    async fn activate_pairing(
        &self,
        vault_id: &str,
        token_hash: [u8; 32],
        confirmation_hash: [u8; 32],
        now_unix: u64,
    ) -> Result<Principal, RepositoryError>;
    async fn cleanup_expired_pairings(&self, now_unix: u64) -> Result<u64, RepositoryError>;
    async fn revoke_device(
        &self,
        principal: &Principal,
        device_id: &str,
    ) -> Result<u64, RepositoryError>;
    async fn upload_object(
        &self,
        principal: &Principal,
        object: EncryptedObject,
    ) -> Result<StoreOutcome, RepositoryError>;
    async fn object(
        &self,
        principal: &Principal,
        object_id: &str,
    ) -> Result<Option<EncryptedObject>, RepositoryError>;
    async fn commit_manifest(
        &self,
        principal: &Principal,
        manifest: SignedManifest,
    ) -> Result<StoreOutcome, RepositoryError>;
    async fn manifest(
        &self,
        principal: &Principal,
        revision_id: &str,
    ) -> Result<Option<SignedManifest>, RepositoryError>;
    async fn device_authorization(
        &self,
        principal: &Principal,
        device_id: &str,
    ) -> Result<Option<SignedPairingGrant>, RepositoryError>;
}

#[derive(Default)]
pub struct MemoryRepository {
    inner: Mutex<MemoryState>,
}

impl MemoryRepository {
    pub fn with_storage_limits(limits: StorageLimits) -> Result<Self, ServiceError> {
        Ok(Self {
            inner: Mutex::new(MemoryState {
                store: OpaqueSyncStore::with_storage_limits(limits)?,
                principals: BTreeMap::new(),
                pending_pairings: BTreeMap::new(),
            }),
        })
    }
}

#[derive(Default)]
struct MemoryState {
    store: OpaqueSyncStore,
    principals: BTreeMap<[u8; 32], Principal>,
    pending_pairings: BTreeMap<[u8; 32], PendingRegistration>,
}

#[derive(Clone)]
struct PendingRegistration {
    vault_id: String,
    grant: SignedPairingGrant,
    confirmation_hash: [u8; 32],
    expires_at_unix: u64,
    failed_attempts: u8,
}

#[async_trait]
impl SyncRepository for MemoryRepository {
    async fn ready(&self) -> Result<(), RepositoryError> {
        Ok(())
    }

    async fn authenticate(&self, token_hash: [u8; 32]) -> Result<Principal, RepositoryError> {
        self.inner
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?
            .principals
            .get(&token_hash)
            .cloned()
            .ok_or(RepositoryError::Unauthorized)
    }

    async fn create_vault(
        &self,
        vault_id: String,
        device: DeviceRecord,
        quota_bytes: u64,
        token_hash: [u8; 32],
    ) -> Result<(), RepositoryError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        if state.principals.contains_key(&token_hash)
            || state.pending_pairings.contains_key(&token_hash)
        {
            return Err(RepositoryError::TokenConflict);
        }
        state
            .store
            .create_vault(vault_id.clone(), device.clone(), quota_bytes)?;
        state.principals.insert(
            token_hash,
            Principal {
                vault_id,
                device_id: device.device_id,
            },
        );
        Ok(())
    }

    async fn status(&self, principal: &Principal) -> Result<VaultStatus, RepositoryError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?
            .store
            .status(&principal.vault_id, &principal.device_id)?)
    }

    async fn pair_device(
        &self,
        principal: &Principal,
        grant: SignedPairingGrant,
        token_hash: [u8; 32],
        expires_at_unix: u64,
    ) -> Result<(), RepositoryError> {
        let expires_at_unix = crate::normalize_pairing_expiry(expires_at_unix)?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        if state.principals.contains_key(&token_hash)
            || state.pending_pairings.contains_key(&token_hash)
        {
            return Err(RepositoryError::TokenConflict);
        }
        state.store.validate_pairing(&grant)?;
        if state.pending_pairings.values().any(|pending| {
            pending.vault_id == principal.vault_id
                && pending.grant.grant.recipient.device_id == grant.grant.recipient.device_id
        }) {
            return Err(ServiceError::DeviceExists.into());
        }
        let code = grant.confirmation_code().map_err(ServiceError::from)?;
        state.pending_pairings.insert(
            token_hash,
            PendingRegistration {
                vault_id: principal.vault_id.clone(),
                grant,
                confirmation_hash: Sha256::digest(code.as_bytes()).into(),
                expires_at_unix,
                failed_attempts: 0,
            },
        );
        Ok(())
    }

    async fn activate_pairing(
        &self,
        vault_id: &str,
        token_hash: [u8; 32],
        confirmation_hash: [u8; 32],
        now_unix: u64,
    ) -> Result<Principal, RepositoryError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        if let Some(active) = state.principals.get(&token_hash) {
            return if active.vault_id == vault_id {
                Ok(active.clone())
            } else {
                Err(RepositoryError::Unauthorized)
            };
        }
        let pending = state
            .pending_pairings
            .get(&token_hash)
            .cloned()
            .ok_or(RepositoryError::Unauthorized)?;
        if pending.vault_id != vault_id {
            return Err(RepositoryError::Unauthorized);
        }
        if now_unix >= pending.expires_at_unix {
            state.pending_pairings.remove(&token_hash);
            return Err(ServiceError::PairingExpired.into());
        }
        if !bool::from(pending.confirmation_hash.ct_eq(&confirmation_hash)) {
            let attempts = pending.failed_attempts.saturating_add(1);
            if attempts >= MAX_PAIRING_CONFIRMATION_ATTEMPTS {
                state.pending_pairings.remove(&token_hash);
            } else if let Some(stored) = state.pending_pairings.get_mut(&token_hash) {
                stored.failed_attempts = attempts;
            }
            return Err(RepositoryError::Unauthorized);
        }
        let device_id = pending.grant.grant.recipient.device_id.clone();
        state.store.pair_device(pending.grant)?;
        let principal = Principal {
            vault_id: pending.vault_id,
            device_id,
        };
        state.principals.insert(token_hash, principal.clone());
        state.pending_pairings.remove(&token_hash);
        Ok(principal)
    }

    async fn cleanup_expired_pairings(&self, now_unix: u64) -> Result<u64, RepositoryError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        let before = state.pending_pairings.len();
        state
            .pending_pairings
            .retain(|_, pending| pending.expires_at_unix > now_unix);
        u64::try_from(before - state.pending_pairings.len())
            .map_err(|_| RepositoryError::Unavailable)
    }

    async fn revoke_device(
        &self,
        principal: &Principal,
        device_id: &str,
    ) -> Result<u64, RepositoryError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        if let Some(token_hash) = state
            .pending_pairings
            .iter()
            .find(|(_, pending)| {
                pending.vault_id == principal.vault_id
                    && pending.grant.grant.recipient.device_id == device_id
            })
            .map(|(token_hash, _)| *token_hash)
        {
            state.pending_pairings.remove(&token_hash);
            return Ok(state
                .store
                .status(&principal.vault_id, &principal.device_id)?
                .epoch);
        }
        let epoch =
            state
                .store
                .revoke_device(&principal.vault_id, &principal.device_id, device_id)?;
        state.principals.retain(|_, candidate| {
            !(candidate.vault_id == principal.vault_id && candidate.device_id == device_id)
        });
        Ok(epoch)
    }

    async fn upload_object(
        &self,
        principal: &Principal,
        object: EncryptedObject,
    ) -> Result<StoreOutcome, RepositoryError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?
            .store
            .upload_object(&principal.device_id, object)?)
    }

    async fn object(
        &self,
        principal: &Principal,
        object_id: &str,
    ) -> Result<Option<EncryptedObject>, RepositoryError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?
            .store
            .object(&principal.vault_id, &principal.device_id, object_id)?
            .cloned())
    }

    async fn commit_manifest(
        &self,
        _principal: &Principal,
        manifest: SignedManifest,
    ) -> Result<StoreOutcome, RepositoryError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?
            .store
            .commit_manifest(manifest)?)
    }

    async fn manifest(
        &self,
        principal: &Principal,
        revision_id: &str,
    ) -> Result<Option<SignedManifest>, RepositoryError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?
            .store
            .manifest(&principal.vault_id, &principal.device_id, revision_id)?
            .cloned())
    }

    async fn device_authorization(
        &self,
        principal: &Principal,
        device_id: &str,
    ) -> Result<Option<SignedPairingGrant>, RepositoryError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?
            .store
            .device_authorization(&principal.vault_id, &principal.device_id, device_id)?
            .cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foliora_sync::{DeviceIdentity, EpochKey};

    fn hash(value: &str) -> [u8; 32] {
        Sha256::digest(value.as_bytes()).into()
    }

    #[tokio::test]
    async fn expired_pending_pairings_are_removed_without_activating_a_device() {
        let repository = MemoryRepository::default();
        let owner_identity = DeviceIdentity::generate().unwrap();
        let recipient_identity = DeviceIdentity::generate().unwrap();
        let owner = owner_identity.record("Owner").unwrap();
        let recipient = recipient_identity.record("Recipient").unwrap();
        let vault_id = "vault:0123456789abcdef";
        let owner_token = hash("owner-token");
        let recipient_token = hash("recipient-token");
        repository
            .create_vault(vault_id.into(), owner.clone(), 4096, owner_token)
            .await
            .unwrap();
        let principal = repository.authenticate(owner_token).await.unwrap();
        let grant = owner_identity
            .grant_epoch_key(vault_id, 1, &EpochKey::from_bytes([5; 32]), recipient)
            .unwrap();
        let confirmation_hash = hash(&grant.confirmation_code().unwrap());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        repository
            .pair_device(&principal, grant, recipient_token, now + 1)
            .await
            .unwrap();

        assert!(matches!(
            repository
                .activate_pairing(vault_id, recipient_token, hash("wrong-code"), now + 1)
                .await,
            Err(RepositoryError::Service(ServiceError::PairingExpired))
        ));
        assert_eq!(
            repository.cleanup_expired_pairings(now + 2).await.unwrap(),
            0
        );
        assert!(matches!(
            repository
                .activate_pairing(vault_id, recipient_token, confirmation_hash, now + 2)
                .await,
            Err(RepositoryError::Unauthorized)
        ));
        assert_eq!(
            repository.status(&principal).await.unwrap().active_devices,
            1
        );
    }

    #[tokio::test]
    async fn pairing_confirmation_locks_after_five_failures_but_not_four() {
        async fn pending() -> (MemoryRepository, Principal, String, [u8; 32], [u8; 32], u64) {
            let repository = MemoryRepository::default();
            let owner_identity = DeviceIdentity::generate().unwrap();
            let recipient_identity = DeviceIdentity::generate().unwrap();
            let owner = owner_identity.record("Owner").unwrap();
            let recipient = recipient_identity.record("Recipient").unwrap();
            let vault_id = format!("vault:lockout-{}", recipient.device_id);
            let owner_token = hash(&format!("owner-{}", recipient.device_id));
            let recipient_token = hash(&format!("recipient-{}", recipient.device_id));
            repository
                .create_vault(vault_id.clone(), owner, 4096, owner_token)
                .await
                .unwrap();
            let principal = repository.authenticate(owner_token).await.unwrap();
            let grant = owner_identity
                .grant_epoch_key(&vault_id, 1, &EpochKey::from_bytes([8; 32]), recipient)
                .unwrap();
            let confirmation_hash = hash(&grant.confirmation_code().unwrap());
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            repository
                .pair_device(&principal, grant, recipient_token, now + 600)
                .await
                .unwrap();
            (
                repository,
                principal,
                vault_id,
                recipient_token,
                confirmation_hash,
                now,
            )
        }

        let (repository, principal, vault_id, token, correct, now) = pending().await;
        let mut wrong = correct;
        wrong[0] ^= 0xff;
        for _ in 0..MAX_PAIRING_CONFIRMATION_ATTEMPTS - 1 {
            assert!(matches!(
                repository
                    .activate_pairing(&vault_id, token, wrong, now)
                    .await,
                Err(RepositoryError::Unauthorized)
            ));
        }
        repository
            .activate_pairing(&vault_id, token, correct, now)
            .await
            .unwrap();
        assert_eq!(
            repository.status(&principal).await.unwrap().active_devices,
            2
        );

        let (repository, principal, vault_id, token, correct, now) = pending().await;
        let mut wrong = correct;
        wrong[0] ^= 0xff;
        for _ in 0..MAX_PAIRING_CONFIRMATION_ATTEMPTS {
            assert!(matches!(
                repository
                    .activate_pairing(&vault_id, token, wrong, now)
                    .await,
                Err(RepositoryError::Unauthorized)
            ));
        }
        assert!(matches!(
            repository
                .activate_pairing(&vault_id, token, correct, now)
                .await,
            Err(RepositoryError::Unauthorized)
        ));
        assert_eq!(
            repository.status(&principal).await.unwrap().active_devices,
            1
        );
        assert_eq!(repository.cleanup_expired_pairings(now).await.unwrap(), 0);
    }
}
