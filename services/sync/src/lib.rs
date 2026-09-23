//! Opaque sync storage semantics. Network/database adapters must preserve these
//! invariants and never receive vault epoch keys or plaintext objects.

use foliora_sync::{
    validate_vault_id, DeviceRecord, EncryptedObject, SignedManifest, SignedPairingGrant, SyncError,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub const SERVICE_NAME: &str = "foliora-sync-service";
pub const MAX_PAIRING_LIFETIME_SECONDS: u64 = 10 * 60;
pub const MAX_PAIRING_CLOCK_SKEW_SECONDS: u64 = 5 * 60;
pub const MAX_PAIRING_CONFIRMATION_ATTEMPTS: u8 = 5;
pub const DEFAULT_MAX_OBJECTS_PER_VAULT: u64 = 100_000;
pub const DEFAULT_MAX_MANIFESTS_PER_VAULT: u64 = 100_000;
pub const DEFAULT_MAX_MANIFEST_BYTES_PER_VAULT: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageLimits {
    pub max_objects_per_vault: u64,
    pub max_manifests_per_vault: u64,
    pub max_manifest_bytes_per_vault: u64,
}

impl Default for StorageLimits {
    fn default() -> Self {
        Self {
            max_objects_per_vault: DEFAULT_MAX_OBJECTS_PER_VAULT,
            max_manifests_per_vault: DEFAULT_MAX_MANIFESTS_PER_VAULT,
            max_manifest_bytes_per_vault: DEFAULT_MAX_MANIFEST_BYTES_PER_VAULT,
        }
    }
}

impl StorageLimits {
    pub fn validate(self) -> Result<Self, ServiceError> {
        if self.max_objects_per_vault == 0
            || self.max_manifests_per_vault == 0
            || self.max_manifest_bytes_per_vault == 0
            || self.max_objects_per_vault > i64::MAX as u64
            || self.max_manifests_per_vault > i64::MAX as u64
            || self.max_manifest_bytes_per_vault > i64::MAX as u64
        {
            return Err(ServiceError::InvalidStorageLimits);
        }
        Ok(self)
    }
}

pub(crate) fn normalize_pairing_expiry(expires_at_unix: u64) -> Result<u64, ServiceError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ServiceError::InvalidPairingExpiry)?
        .as_secs();
    normalize_pairing_expiry_at(expires_at_unix, now)
}

pub(crate) fn normalize_pairing_expiry_at(
    expires_at_unix: u64,
    now_unix: u64,
) -> Result<u64, ServiceError> {
    let maximum_requested = now_unix
        .checked_add(MAX_PAIRING_LIFETIME_SECONDS)
        .and_then(|value| value.checked_add(MAX_PAIRING_CLOCK_SKEW_SECONDS))
        .ok_or(ServiceError::InvalidPairingExpiry)?;
    if expires_at_unix <= now_unix || expires_at_unix > maximum_requested {
        return Err(ServiceError::InvalidPairingExpiry);
    }
    Ok(expires_at_unix.min(
        now_unix
            .checked_add(MAX_PAIRING_LIFETIME_SECONDS)
            .ok_or(ServiceError::InvalidPairingExpiry)?,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum StoreOutcome {
    Inserted,
    AlreadyPresent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceError {
    Protocol(SyncError),
    VaultExists,
    VaultNotFound,
    DeviceNotFound,
    DeviceRevoked,
    DeviceExists,
    PairingExpired,
    InvalidPairingExpiry,
    EpochMismatch,
    ObjectConflict,
    ManifestConflict,
    MissingObject(String),
    MissingParent(String),
    RootAlreadyExists,
    SequenceReplay,
    QuotaExceeded,
    InvalidQuota,
    StorageMetadataExceeded,
    InvalidStorageLimits,
}

impl From<SyncError> for ServiceError {
    fn from(error: SyncError) -> Self {
        Self::Protocol(error)
    }
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(error) => error.fmt(formatter),
            Self::VaultExists => write!(formatter, "sync vault already exists"),
            Self::VaultNotFound => write!(formatter, "sync vault was not found"),
            Self::DeviceNotFound => write!(formatter, "sync device was not found"),
            Self::DeviceRevoked => write!(formatter, "sync device is revoked"),
            Self::DeviceExists => write!(formatter, "sync device already exists"),
            Self::PairingExpired => write!(formatter, "device pairing registration expired"),
            Self::InvalidPairingExpiry => write!(formatter, "device pairing expiry is invalid"),
            Self::EpochMismatch => write!(formatter, "sync key epoch is stale or invalid"),
            Self::ObjectConflict => {
                write!(formatter, "object identifier conflicts with stored bytes")
            }
            Self::ManifestConflict => {
                write!(formatter, "manifest identifier conflicts with stored data")
            }
            Self::MissingObject(id) => write!(formatter, "manifest references missing object {id}"),
            Self::MissingParent(id) => write!(formatter, "manifest references missing parent {id}"),
            Self::RootAlreadyExists => {
                write!(formatter, "sync history already has a root revision")
            }
            Self::SequenceReplay => write!(formatter, "device sequence was replayed"),
            Self::QuotaExceeded => write!(formatter, "sync storage quota exceeded"),
            Self::InvalidQuota => write!(formatter, "sync storage quota must be positive"),
            Self::StorageMetadataExceeded => {
                write!(formatter, "sync metadata or object-count limit exceeded")
            }
            Self::InvalidStorageLimits => write!(formatter, "sync storage limits are invalid"),
        }
    }
}

impl std::error::Error for ServiceError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    pub epoch: u64,
    pub used_bytes: u64,
    pub quota_bytes: u64,
    pub heads: Vec<String>,
    pub active_devices: usize,
    pub object_count: u64,
    pub manifest_count: u64,
    pub manifest_bytes: u64,
}

#[derive(Default)]
pub struct OpaqueSyncStore {
    vaults: BTreeMap<String, VaultStore>,
    limits: StorageLimits,
}

struct VaultStore {
    epoch: u64,
    quota_bytes: u64,
    used_bytes: u64,
    devices: BTreeMap<String, StoredDevice>,
    objects: BTreeMap<String, EncryptedObject>,
    manifests: BTreeMap<String, SignedManifest>,
    manifest_bytes: u64,
    heads: BTreeSet<String>,
}

struct StoredDevice {
    record: DeviceRecord,
    authorization: Option<SignedPairingGrant>,
    active: bool,
    last_sequence: u64,
}

impl OpaqueSyncStore {
    pub fn with_storage_limits(limits: StorageLimits) -> Result<Self, ServiceError> {
        Ok(Self {
            vaults: BTreeMap::new(),
            limits: limits.validate()?,
        })
    }

    pub fn create_vault(
        &mut self,
        vault_id: String,
        initial_device: DeviceRecord,
        quota_bytes: u64,
    ) -> Result<(), ServiceError> {
        validate_vault_id(&vault_id)?;
        initial_device.validate()?;
        if quota_bytes == 0 {
            return Err(ServiceError::InvalidQuota);
        }
        if self.vaults.contains_key(&vault_id) {
            return Err(ServiceError::VaultExists);
        }
        let device_id = initial_device.device_id.clone();
        self.vaults.insert(
            vault_id,
            VaultStore {
                epoch: 1,
                quota_bytes,
                used_bytes: 0,
                devices: BTreeMap::from([(
                    device_id,
                    StoredDevice {
                        record: initial_device,
                        authorization: None,
                        active: true,
                        last_sequence: 0,
                    },
                )]),
                objects: BTreeMap::new(),
                manifests: BTreeMap::new(),
                manifest_bytes: 0,
                heads: BTreeSet::new(),
            },
        );
        Ok(())
    }

    pub fn pair_device(&mut self, signed: SignedPairingGrant) -> Result<(), ServiceError> {
        self.validate_pairing(&signed)?;
        let vault_id = signed.grant.vault_id.clone();
        let device = signed.grant.recipient.clone();
        let vault = self
            .vaults
            .get_mut(&vault_id)
            .ok_or(ServiceError::VaultNotFound)?;
        vault.devices.insert(
            device.device_id.clone(),
            StoredDevice {
                record: device,
                authorization: Some(signed),
                active: true,
                last_sequence: 0,
            },
        );
        Ok(())
    }

    pub fn validate_pairing(&self, signed: &SignedPairingGrant) -> Result<(), ServiceError> {
        let vault_id = &signed.grant.vault_id;
        let authorizing_device_id = &signed.grant.authorizing_device_id;
        let vault = self.active_vault(vault_id, authorizing_device_id)?;
        let authorizer = &vault.devices.get(authorizing_device_id).unwrap().record;
        signed.verify(authorizer)?;
        if signed.grant.epoch != vault.epoch {
            return Err(ServiceError::EpochMismatch);
        }
        let device = &signed.grant.recipient;
        if vault.devices.contains_key(&device.device_id) {
            return Err(ServiceError::DeviceExists);
        }
        Ok(())
    }

    pub fn revoke_device(
        &mut self,
        vault_id: &str,
        authorizing_device_id: &str,
        revoked_device_id: &str,
    ) -> Result<u64, ServiceError> {
        let vault = self.active_vault_mut(vault_id, authorizing_device_id)?;
        let target = vault
            .devices
            .get_mut(revoked_device_id)
            .ok_or(ServiceError::DeviceNotFound)?;
        if !target.active {
            return Err(ServiceError::DeviceRevoked);
        }
        target.active = false;
        vault.epoch = vault
            .epoch
            .checked_add(1)
            .ok_or(ServiceError::EpochMismatch)?;
        Ok(vault.epoch)
    }

    pub fn upload_object(
        &mut self,
        device_id: &str,
        object: EncryptedObject,
    ) -> Result<StoreOutcome, ServiceError> {
        object.validate()?;
        let limits = self.limits;
        let vault = self.active_vault_mut(&object.vault_id, device_id)?;
        if object.epoch != vault.epoch {
            return Err(ServiceError::EpochMismatch);
        }
        if let Some(existing) = vault.objects.get(&object.object_id) {
            return if existing == &object {
                Ok(StoreOutcome::AlreadyPresent)
            } else {
                Err(ServiceError::ObjectConflict)
            };
        }
        if vault.objects.len() as u64 >= limits.max_objects_per_vault {
            return Err(ServiceError::StorageMetadataExceeded);
        }
        let bytes = object.ciphertext.len() as u64;
        if vault.used_bytes.saturating_add(bytes) > vault.quota_bytes {
            return Err(ServiceError::QuotaExceeded);
        }
        vault.used_bytes += bytes;
        vault.objects.insert(object.object_id.clone(), object);
        Ok(StoreOutcome::Inserted)
    }

    pub fn commit_manifest(
        &mut self,
        signed: SignedManifest,
    ) -> Result<StoreOutcome, ServiceError> {
        let vault_id = signed.manifest.vault_id.clone();
        let device_id = signed.manifest.device_id.clone();
        let limits = self.limits;
        let vault = self.active_vault_mut(&vault_id, &device_id)?;
        let device = vault.devices.get(&device_id).unwrap();
        signed.verify(&device.record)?;
        if signed.manifest.epoch != vault.epoch {
            return Err(ServiceError::EpochMismatch);
        }
        if let Some(existing) = vault.manifests.get(&signed.manifest.revision_id) {
            return if existing == &signed {
                Ok(StoreOutcome::AlreadyPresent)
            } else {
                Err(ServiceError::ManifestConflict)
            };
        }
        let signed_bytes = serde_json::to_vec(&signed)
            .map_err(|_| ServiceError::Protocol(SyncError::Serialize))?
            .len() as u64;
        if vault.manifests.len() as u64 >= limits.max_manifests_per_vault
            || vault
                .manifest_bytes
                .checked_add(signed_bytes)
                .filter(|bytes| *bytes <= limits.max_manifest_bytes_per_vault)
                .is_none()
        {
            return Err(ServiceError::StorageMetadataExceeded);
        }
        if signed.manifest.sequence <= device.last_sequence {
            return Err(ServiceError::SequenceReplay);
        }
        for object_id in &signed.manifest.object_ids {
            let object = vault
                .objects
                .get(object_id)
                .ok_or_else(|| ServiceError::MissingObject(object_id.clone()))?;
            if object.epoch != signed.manifest.epoch {
                return Err(ServiceError::EpochMismatch);
            }
        }
        if vault.manifests.is_empty() && !signed.manifest.parents.is_empty() {
            return Err(ServiceError::MissingParent(
                signed.manifest.parents[0].clone(),
            ));
        }
        if !vault.manifests.is_empty() && signed.manifest.parents.is_empty() {
            return Err(ServiceError::RootAlreadyExists);
        }
        for parent in &signed.manifest.parents {
            if !vault.manifests.contains_key(parent) {
                return Err(ServiceError::MissingParent(parent.clone()));
            }
        }
        for parent in &signed.manifest.parents {
            vault.heads.remove(parent);
        }
        vault.heads.insert(signed.manifest.revision_id.clone());
        vault.devices.get_mut(&device_id).unwrap().last_sequence = signed.manifest.sequence;
        vault
            .manifests
            .insert(signed.manifest.revision_id.clone(), signed);
        vault.manifest_bytes += signed_bytes;
        Ok(StoreOutcome::Inserted)
    }

    pub fn status(&self, vault_id: &str, device_id: &str) -> Result<VaultStatus, ServiceError> {
        let vault = self.active_vault(vault_id, device_id)?;
        Ok(VaultStatus {
            epoch: vault.epoch,
            used_bytes: vault.used_bytes,
            quota_bytes: vault.quota_bytes,
            heads: vault.heads.iter().cloned().collect(),
            active_devices: vault
                .devices
                .values()
                .filter(|device| device.active)
                .count(),
            object_count: vault.objects.len() as u64,
            manifest_count: vault.manifests.len() as u64,
            manifest_bytes: vault.manifest_bytes,
        })
    }

    pub fn object(
        &self,
        vault_id: &str,
        device_id: &str,
        object_id: &str,
    ) -> Result<Option<&EncryptedObject>, ServiceError> {
        Ok(self
            .active_vault(vault_id, device_id)?
            .objects
            .get(object_id))
    }

    pub fn manifest(
        &self,
        vault_id: &str,
        device_id: &str,
        revision_id: &str,
    ) -> Result<Option<&SignedManifest>, ServiceError> {
        Ok(self
            .active_vault(vault_id, device_id)?
            .manifests
            .get(revision_id))
    }

    pub fn device_authorization(
        &self,
        vault_id: &str,
        device_id: &str,
        target_device_id: &str,
    ) -> Result<Option<&SignedPairingGrant>, ServiceError> {
        Ok(self
            .active_vault(vault_id, device_id)?
            .devices
            .get(target_device_id)
            .and_then(|device| device.authorization.as_ref()))
    }

    fn active_vault(&self, vault_id: &str, device_id: &str) -> Result<&VaultStore, ServiceError> {
        let vault = self
            .vaults
            .get(vault_id)
            .ok_or(ServiceError::VaultNotFound)?;
        let device = vault
            .devices
            .get(device_id)
            .ok_or(ServiceError::DeviceNotFound)?;
        if !device.active {
            return Err(ServiceError::DeviceRevoked);
        }
        Ok(vault)
    }

    fn active_vault_mut(
        &mut self,
        vault_id: &str,
        device_id: &str,
    ) -> Result<&mut VaultStore, ServiceError> {
        let vault = self
            .vaults
            .get_mut(vault_id)
            .ok_or(ServiceError::VaultNotFound)?;
        let device = vault
            .devices
            .get(device_id)
            .ok_or(ServiceError::DeviceNotFound)?;
        if !device.active {
            return Err(ServiceError::DeviceRevoked);
        }
        Ok(vault)
    }
}

pub mod api;
pub mod durable;
pub mod metrics;
pub mod rate_limit;
pub mod repository;
#[cfg(test)]
mod tests;
