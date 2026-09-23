use crate::{
    client::SyncHttpClient, DeviceIdentity, DeviceRecord, EpochKey, SignedPairingGrant, SyncError,
    SyncResult, MAX_TRUSTED_DEVICES,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use zeroize::Zeroize;

pub const SYNC_PROFILE_VERSION: u16 = 1;
pub const PAIRING_PACKAGE_VERSION: u16 = 1;
pub const PAIRING_LIFETIME_SECONDS: u64 = 10 * 60;
pub const PAIRING_CLOCK_SKEW_SECONDS: u64 = 5 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingRequest {
    pub schema_version: u16,
    pub endpoint: String,
    pub vault_id: String,
    pub recipient: DeviceRecord,
    pub recipient_token: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    #[serde(default)]
    pub allow_insecure_loopback: bool,
}

impl PairingRequest {
    fn validate_structure(&self) -> SyncResult<()> {
        if self.schema_version != PAIRING_PACKAGE_VERSION {
            return Err(SyncError::UnsupportedVersion);
        }
        crate::validate_vault_id(&self.vault_id)?;
        self.recipient.validate()?;
        let _ = SyncHttpClient::new(
            &self.endpoint,
            self.recipient_token.clone(),
            self.allow_insecure_loopback,
        )
        .map_err(|_| SyncError::InvalidDevice)?;
        Ok(())
    }

    pub fn validate(&self) -> SyncResult<()> {
        let now = unix_time_seconds()?;
        self.validate_at(now)
    }

    fn validate_at(&self, now: u64) -> SyncResult<()> {
        self.validate_structure()?;
        if self.created_at_unix == 0
            || self.expires_at_unix <= self.created_at_unix
            || self.expires_at_unix - self.created_at_unix > PAIRING_LIFETIME_SECONDS
            || self.created_at_unix > now.saturating_add(PAIRING_CLOCK_SKEW_SECONDS)
            || now >= self.expires_at_unix
        {
            return Err(SyncError::InvalidPairingGrant);
        }
        Ok(())
    }

    pub fn is_expired(&self) -> bool {
        unix_time_seconds()
            .map(|now| now >= self.expires_at_unix)
            .unwrap_or(true)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingGrantPackage {
    pub schema_version: u16,
    pub authorizer: DeviceRecord,
    pub signed_grant: SignedPairingGrant,
}

impl PairingGrantPackage {
    pub fn new(authorizer: DeviceRecord, signed_grant: SignedPairingGrant) -> SyncResult<Self> {
        authorizer.validate()?;
        signed_grant.grant.validate()?;
        signed_grant.verify(&authorizer)?;
        Ok(Self {
            schema_version: PAIRING_PACKAGE_VERSION,
            authorizer,
            signed_grant,
        })
    }

    pub fn validate(&self) -> SyncResult<()> {
        if self.schema_version != PAIRING_PACKAGE_VERSION {
            return Err(SyncError::UnsupportedVersion);
        }
        self.signed_grant.verify(&self.authorizer)
    }
}

/// Private recipient material held only inside the encrypted local vault until
/// a signed grant is accepted. Its request projection is safe to transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingPairing {
    pub request: PairingRequest,
    pub recipient_secret: Vec<u8>,
}

impl Drop for PendingPairing {
    fn drop(&mut self) {
        self.recipient_secret.zeroize();
    }
}

impl PendingPairing {
    pub fn new(
        endpoint: String,
        vault_id: String,
        device_label: String,
        allow_insecure_loopback: bool,
    ) -> SyncResult<Self> {
        let identity = DeviceIdentity::generate()?;
        let mut token_bytes = [0_u8; 32];
        getrandom::getrandom(&mut token_bytes).map_err(|_| SyncError::Randomness)?;
        let recipient_token = crate::crypto::hex(&token_bytes);
        let recipient = identity.record(device_label)?;
        let created_at_unix = unix_time_seconds()?;
        let request = PairingRequest {
            schema_version: PAIRING_PACKAGE_VERSION,
            endpoint,
            vault_id,
            recipient,
            recipient_token,
            created_at_unix,
            expires_at_unix: created_at_unix
                .checked_add(PAIRING_LIFETIME_SECONDS)
                .ok_or(SyncError::InvalidPairingGrant)?,
            allow_insecure_loopback,
        };
        request.validate()?;
        Ok(Self {
            request,
            recipient_secret: identity.secret_bytes().to_vec(),
        })
    }

    pub fn validate(&self) -> SyncResult<()> {
        self.request.validate_structure()?;
        if self.recipient_secret.len() != 64 {
            return Err(SyncError::InvalidDevice);
        }
        let identity = DeviceIdentity::from_secret_bytes(&self.recipient_secret)?;
        if identity.record("pending")?.device_id != self.request.recipient.device_id {
            return Err(SyncError::DeviceMismatch);
        }
        Ok(())
    }

    pub fn request(&self) -> &PairingRequest {
        &self.request
    }

    pub fn complete(
        &self,
        package: &PairingGrantPackage,
        authorizer: &DeviceRecord,
        confirmed_code: &str,
    ) -> SyncResult<SyncProfile> {
        self.validate()?;
        self.request.validate()?;
        package.validate()?;
        if package.signed_grant.grant.vault_id != self.request.vault_id
            || package.signed_grant.grant.recipient != self.request.recipient
            || package.signed_grant.grant.epoch == 0
        {
            return Err(SyncError::InvalidPairingGrant);
        }
        let identity = DeviceIdentity::from_secret_bytes(&self.recipient_secret)?;
        let epoch_key =
            identity.accept_epoch_key(&package.signed_grant, authorizer, confirmed_code)?;
        SyncProfile::from_pairing(
            self.request.endpoint.clone(),
            self.request.vault_id.clone(),
            self.request.recipient.clone(),
            &identity,
            self.request.recipient_token.clone(),
            package.signed_grant.grant.epoch,
            &epoch_key,
            self.request.allow_insecure_loopback,
            if package.signed_grant.grant.trusted_devices.is_empty() {
                vec![authorizer.clone()]
            } else {
                package.signed_grant.grant.trusted_devices.clone()
            },
            package.signed_grant.grant.heads.clone(),
        )
    }
}

fn unix_time_seconds() -> SyncResult<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| SyncError::InvalidPairingGrant)
}

/// Sync configuration stored inside the encrypted local vault. Private device
/// keys and bearer credentials never leave this encrypted boundary in clear.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncProfile {
    pub schema_version: u16,
    pub endpoint: String,
    pub vault_id: String,
    pub device: DeviceRecord,
    pub device_secret: Vec<u8>,
    pub device_token: String,
    pub epoch: u64,
    pub epoch_key: Vec<u8>,
    pub next_sequence: u64,
    #[serde(default)]
    pub heads: Vec<String>,
    #[serde(default)]
    pub last_snapshot_sha256: Option<String>,
    #[serde(default)]
    pub initial_download_pending: bool,
    #[serde(default)]
    pub allow_insecure_loopback: bool,
    #[serde(default)]
    pub trusted_devices: Vec<DeviceRecord>,
    #[serde(default)]
    pub pairing_heads: Vec<String>,
}

impl Drop for SyncProfile {
    fn drop(&mut self) {
        self.device_secret.zeroize();
        self.device_token.zeroize();
        self.epoch_key.zeroize();
    }
}

impl SyncProfile {
    pub fn new(
        endpoint: String,
        vault_id: String,
        device: DeviceRecord,
        identity: &DeviceIdentity,
        device_token: String,
        epoch_key: &EpochKey,
        allow_insecure_loopback: bool,
    ) -> Result<Self, SyncError> {
        Self::build(
            endpoint,
            vault_id,
            device,
            identity,
            device_token,
            1,
            epoch_key,
            1,
            Vec::new(),
            None,
            false,
            allow_insecure_loopback,
            Vec::new(),
            Vec::new(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_pairing(
        endpoint: String,
        vault_id: String,
        device: DeviceRecord,
        identity: &DeviceIdentity,
        device_token: String,
        epoch: u64,
        epoch_key: &EpochKey,
        allow_insecure_loopback: bool,
        trusted_devices: Vec<DeviceRecord>,
        pairing_heads: Vec<String>,
    ) -> Result<Self, SyncError> {
        Self::build(
            endpoint,
            vault_id,
            device,
            identity,
            device_token,
            epoch,
            epoch_key,
            1,
            Vec::new(),
            None,
            true,
            allow_insecure_loopback,
            trusted_devices,
            pairing_heads,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        endpoint: String,
        vault_id: String,
        device: DeviceRecord,
        identity: &DeviceIdentity,
        device_token: String,
        epoch: u64,
        epoch_key: &EpochKey,
        next_sequence: u64,
        heads: Vec<String>,
        last_snapshot_sha256: Option<String>,
        initial_download_pending: bool,
        allow_insecure_loopback: bool,
        trusted_devices: Vec<DeviceRecord>,
        pairing_heads: Vec<String>,
    ) -> Result<Self, SyncError> {
        let profile = Self {
            schema_version: SYNC_PROFILE_VERSION,
            endpoint,
            vault_id,
            device,
            device_secret: identity.secret_bytes().to_vec(),
            device_token,
            epoch,
            epoch_key: epoch_key.secret_bytes().to_vec(),
            next_sequence,
            heads,
            last_snapshot_sha256,
            initial_download_pending,
            allow_insecure_loopback,
            trusted_devices,
            pairing_heads,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<(), SyncError> {
        if self.schema_version != SYNC_PROFILE_VERSION
            || self.epoch == 0
            || self.next_sequence == 0
            || self.device_secret.len() != 64
            || self.epoch_key.len() != 32
        {
            return Err(SyncError::InvalidDevice);
        }
        crate::validate_vault_id(&self.vault_id)?;
        self.device.validate()?;
        let mut trusted_ids = BTreeSet::new();
        if self.trusted_devices.len() > MAX_TRUSTED_DEVICES {
            return Err(SyncError::InvalidDevice);
        }
        for device in &self.trusted_devices {
            device.validate()?;
            if device.device_id == self.device.device_id
                || !trusted_ids.insert(device.device_id.as_str())
            {
                return Err(SyncError::InvalidDevice);
            }
        }
        let identity = DeviceIdentity::from_secret_bytes(&self.device_secret)?;
        if identity.record("profile")?.device_id != self.device.device_id {
            return Err(SyncError::DeviceMismatch);
        }
        let _ = EpochKey::from_bytes(self.epoch_key.as_slice().try_into().unwrap());
        let _ = SyncHttpClient::new(
            &self.endpoint,
            self.device_token.clone(),
            self.allow_insecure_loopback,
        )
        .map_err(|_| SyncError::InvalidDevice)?;
        if self.heads.len() > 32
            || self.pairing_heads.len() > 32
            || !self.heads.windows(2).all(|pair| pair[0] < pair[1])
            || !self.pairing_heads.windows(2).all(|pair| pair[0] < pair[1])
            || !self.heads.iter().chain(&self.pairing_heads).all(|id| {
                id.len() == 73
                    && id.starts_with("revision:")
                    && id[9..]
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
        {
            return Err(SyncError::InvalidManifest);
        }
        if let Some(digest) = &self.last_snapshot_sha256 {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(SyncError::InvalidManifest);
            }
        }
        Ok(())
    }

    pub fn identity(&self) -> Result<DeviceIdentity, SyncError> {
        self.validate()?;
        DeviceIdentity::from_secret_bytes(&self.device_secret)
    }

    pub fn epoch_key(&self) -> Result<EpochKey, SyncError> {
        self.validate()?;
        Ok(EpochKey::from_bytes(
            self.epoch_key.as_slice().try_into().unwrap(),
        ))
    }

    pub fn client(&self) -> Result<SyncHttpClient, crate::client::ClientError> {
        SyncHttpClient::new(
            &self.endpoint,
            self.device_token.clone(),
            self.allow_insecure_loopback,
        )
    }

    pub fn trusted_device(&self, device_id: &str) -> Option<&DeviceRecord> {
        if self.device.device_id == device_id {
            Some(&self.device)
        } else {
            self.trusted_devices
                .iter()
                .find(|device| device.device_id == device_id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_round_trip_preserves_identity() {
        let identity = DeviceIdentity::generate().unwrap();
        let device = identity.record("Test").unwrap();
        let profile = SyncProfile::new(
            "https://sync.example".into(),
            "vault:0123456789abcdef".into(),
            device.clone(),
            &identity,
            "device-token-with-at-least-32-bytes".into(),
            &EpochKey::from_bytes([8; 32]),
            false,
        )
        .unwrap();
        let encoded = serde_json::to_vec(&profile).unwrap();
        let restored: SyncProfile = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(restored.device, device);
        assert_eq!(
            restored
                .identity()
                .unwrap()
                .record("restored")
                .unwrap()
                .device_id,
            device.device_id
        );
    }

    #[test]
    fn malformed_profile_is_rejected_before_use() {
        let profile = SyncProfile {
            schema_version: SYNC_PROFILE_VERSION,
            endpoint: "https://sync.example".into(),
            vault_id: "vault:bad".into(),
            device: DeviceRecord {
                device_id: "device:bad".into(),
                label: "bad".into(),
                public_key: [0; 32],
                exchange_public_key: [0; 32],
            },
            device_secret: vec![],
            device_token: String::new(),
            epoch: 1,
            epoch_key: vec![],
            next_sequence: 1,
            heads: vec![],
            last_snapshot_sha256: None,
            initial_download_pending: false,
            allow_insecure_loopback: false,
            trusted_devices: vec![],
            pairing_heads: vec![],
        };
        assert!(profile.validate().is_err());
    }

    #[test]
    fn profile_rejects_an_unbounded_trust_snapshot() {
        let identity = DeviceIdentity::generate().unwrap();
        let device = identity.record("Owner").unwrap();
        let mut profile = SyncProfile::new(
            "https://sync.example".into(),
            "vault:0123456789abcdef".into(),
            device,
            &identity,
            "device-token-with-at-least-32-bytes".into(),
            &EpochKey::from_bytes([9; 32]),
            false,
        )
        .unwrap();
        profile.trusted_devices = (0..=MAX_TRUSTED_DEVICES)
            .map(|index| {
                DeviceIdentity::generate()
                    .unwrap()
                    .record(format!("Trusted {index}"))
                    .unwrap()
            })
            .collect();
        profile
            .trusted_devices
            .sort_by(|left, right| left.device_id.cmp(&right.device_id));

        assert_eq!(profile.validate(), Err(SyncError::InvalidDevice));
    }

    #[test]
    fn pairing_request_is_expiring_and_public_projection_has_no_private_key() {
        let pending = PendingPairing::new(
            "https://sync.example".into(),
            "vault:0123456789abcdef".into(),
            "New device".into(),
            false,
        )
        .unwrap();
        let request = serde_json::to_string(pending.request()).unwrap();
        assert!(!request.contains("recipientSecret"));
        assert!(pending.request().expires_at_unix > pending.request().created_at_unix);

        let mut expired = pending.request().clone();
        expired.expires_at_unix = 1;
        assert!(expired.validate().is_err());
        let mut stale_pending = pending.clone();
        stale_pending.request.expires_at_unix = 1;
        assert!(stale_pending.validate().is_ok());
    }

    #[test]
    fn pairing_request_accepts_only_bounded_clock_skew_and_expires_at_boundary() {
        let pending = PendingPairing::new(
            "https://sync.example".into(),
            "vault:0123456789abcdef".into(),
            "Clock test".into(),
            false,
        )
        .unwrap();
        let now = 1_700_000_000;
        let mut request = pending.request().clone();
        request.created_at_unix = now + PAIRING_CLOCK_SKEW_SECONDS;
        request.expires_at_unix = request.created_at_unix + PAIRING_LIFETIME_SECONDS;
        assert!(request.validate_at(now).is_ok());

        request.created_at_unix += 1;
        request.expires_at_unix += 1;
        assert!(request.validate_at(now).is_err());

        request.created_at_unix = now - PAIRING_LIFETIME_SECONDS;
        request.expires_at_unix = now;
        assert!(request.validate_at(now).is_err());
    }
}
