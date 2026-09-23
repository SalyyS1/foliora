use crate::crypto::hex;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{
    de::{Error as _, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use sha2::{Digest, Sha256};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_OBJECT_BYTES: usize = 25 * 1024 * 1024;
pub const MAX_OBJECT_JSON_BYTES: usize = 36 * 1024 * 1024;
pub const MAX_MANIFEST_OBJECTS: usize = 10_000;
const MAX_ID_BYTES: usize = 160;
const MAX_DEVICE_LABEL_BYTES: usize = 80;
pub const MAX_TRUSTED_DEVICES: usize = 64;

pub type SyncResult<T> = Result<T, SyncError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncError {
    Randomness,
    AuthenticationFailed,
    UnsupportedVersion,
    InvalidVaultId,
    InvalidObject,
    InvalidManifest,
    InvalidDevice,
    DeviceMismatch,
    InvalidSignature,
    InvalidPairingGrant,
    PairingConfirmationMismatch,
    Serialize,
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::Randomness => "operating-system randomness unavailable",
            Self::AuthenticationFailed => "encrypted sync object authentication failed",
            Self::UnsupportedVersion => "unsupported sync protocol version",
            Self::InvalidVaultId => "invalid sync vault identifier",
            Self::InvalidObject => "invalid encrypted sync object",
            Self::InvalidManifest => "invalid sync manifest",
            Self::InvalidDevice => "invalid sync device",
            Self::DeviceMismatch => "manifest signer does not match device",
            Self::InvalidSignature => "sync manifest signature is invalid",
            Self::InvalidPairingGrant => "device pairing grant is invalid",
            Self::PairingConfirmationMismatch => "device pairing confirmation code does not match",
            Self::Serialize => "sync message serialization failed",
        };
        write!(formatter, "{message}")
    }
}

impl std::error::Error for SyncError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedObject {
    pub protocol_version: u16,
    pub vault_id: String,
    pub epoch: u64,
    pub object_id: String,
    pub nonce: [u8; 24],
    #[serde(with = "ciphertext_base64")]
    pub ciphertext: Vec<u8>,
}

mod ciphertext_base64 {
    use super::*;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CiphertextVisitor;

        impl<'de> Visitor<'de> for CiphertextVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("canonical base64 ciphertext or a bounded legacy byte array")
            }

            fn visit_str<E>(self, encoded: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if encoded.len() > (MAX_OBJECT_BYTES + 16).div_ceil(3) * 4 {
                    return Err(E::custom("ciphertext exceeds the protocol limit"));
                }
                let decoded = STANDARD
                    .decode(encoded)
                    .map_err(|_| E::custom("ciphertext is not canonical base64"))?;
                if STANDARD.encode(&decoded) != encoded {
                    return Err(E::custom("ciphertext is not canonical base64"));
                }
                Ok(decoded)
            }

            fn visit_string<E>(self, encoded: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&encoded)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let limit = MAX_OBJECT_BYTES + 16;
                let capacity = sequence.size_hint().unwrap_or(0).min(limit);
                let mut bytes = Vec::with_capacity(capacity);
                while let Some(byte) = sequence.next_element::<u8>()? {
                    if bytes.len() == limit {
                        return Err(A::Error::custom("ciphertext exceeds the protocol limit"));
                    }
                    bytes.push(byte);
                }
                Ok(bytes)
            }
        }

        deserializer.deserialize_any(CiphertextVisitor)
    }
}

impl EncryptedObject {
    pub fn validate(&self) -> SyncResult<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(SyncError::UnsupportedVersion);
        }
        validate_vault_id(&self.vault_id)?;
        if self.epoch == 0
            || self.ciphertext.len() <= 16
            || self.ciphertext.len() > MAX_OBJECT_BYTES + 16
            || self.object_id
                != object_digest(&self.vault_id, self.epoch, &self.nonce, &self.ciphertext)
        {
            return Err(SyncError::InvalidObject);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRecord {
    pub device_id: String,
    pub label: String,
    pub public_key: [u8; 32],
    pub exchange_public_key: [u8; 32],
}

impl DeviceRecord {
    pub fn validate(&self) -> SyncResult<()> {
        if !valid_prefixed_hash(&self.device_id, "device:")
            || self.label.trim().is_empty()
            || self.label.len() > MAX_DEVICE_LABEL_BYTES
            || self.device_id != device_digest(&self.public_key, &self.exchange_public_key)
            || VerifyingKey::from_bytes(&self.public_key).is_err()
        {
            return Err(SyncError::InvalidDevice);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingGrant {
    pub protocol_version: u16,
    pub vault_id: String,
    pub epoch: u64,
    pub authorizing_device_id: String,
    pub recipient: DeviceRecord,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_devices: Vec<DeviceRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub heads: Vec<String>,
    pub nonce: [u8; 24],
    pub encrypted_epoch_key: Vec<u8>,
}

impl PairingGrant {
    pub fn validate(&self) -> SyncResult<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(SyncError::UnsupportedVersion);
        }
        validate_vault_id(&self.vault_id)?;
        self.recipient.validate()?;
        let trusted_valid = self.trusted_devices.is_empty()
            || (self.trusted_devices.len() <= MAX_TRUSTED_DEVICES
                && self
                    .trusted_devices
                    .iter()
                    .all(|device| device.validate().is_ok())
                && self
                    .trusted_devices
                    .windows(2)
                    .all(|pair| pair[0].device_id < pair[1].device_id)
                && self
                    .trusted_devices
                    .iter()
                    .any(|device| device.device_id == self.authorizing_device_id)
                && self
                    .trusted_devices
                    .iter()
                    .all(|device| device.device_id != self.recipient.device_id));
        let heads_valid = self.heads.len() <= 32
            && sorted_unique(&self.heads)
            && self
                .heads
                .iter()
                .all(|id| valid_prefixed_hash(id, "revision:"));
        if self.epoch == 0
            || !valid_prefixed_hash(&self.authorizing_device_id, "device:")
            || self.authorizing_device_id == self.recipient.device_id
            || !trusted_valid
            || !heads_valid
            || self.encrypted_epoch_key.len() != 48
        {
            return Err(SyncError::InvalidPairingGrant);
        }
        Ok(())
    }

    pub fn confirmation_code(&self) -> SyncResult<String> {
        self.validate()?;
        let digest = Sha256::digest(canonical_pairing_bytes(self)?);
        let value = hex(&digest[..4]).to_uppercase();
        Ok(format!("{}-{}", &value[..4], &value[4..]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPairingGrant {
    pub grant: PairingGrant,
    pub signature: Vec<u8>,
}

impl SignedPairingGrant {
    pub fn verify(&self, authorizer: &DeviceRecord) -> SyncResult<()> {
        self.grant.validate()?;
        authorizer.validate()?;
        if self.grant.authorizing_device_id != authorizer.device_id {
            return Err(SyncError::DeviceMismatch);
        }
        let key = VerifyingKey::from_bytes(&authorizer.public_key)
            .map_err(|_| SyncError::InvalidDevice)?;
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| SyncError::InvalidSignature)?;
        key.verify(&canonical_pairing_bytes(&self.grant)?, &signature)
            .map_err(|_| SyncError::InvalidSignature)
    }

    pub fn confirmation_code(&self) -> SyncResult<String> {
        self.grant.confirmation_code()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestDraft {
    pub vault_id: String,
    pub epoch: u64,
    pub parents: Vec<String>,
    pub object_ids: Vec<String>,
    pub tombstones: Vec<String>,
    pub device_id: String,
    pub sequence: u64,
}

impl ManifestDraft {
    pub fn finalize(mut self) -> SyncResult<Manifest> {
        self.parents.sort();
        self.parents.dedup();
        self.object_ids.sort();
        self.object_ids.dedup();
        self.tombstones.sort();
        self.tombstones.dedup();
        let mut manifest = Manifest {
            protocol_version: PROTOCOL_VERSION,
            revision_id: String::new(),
            vault_id: self.vault_id,
            epoch: self.epoch,
            parents: self.parents,
            object_ids: self.object_ids,
            tombstones: self.tombstones,
            device_id: self.device_id,
            sequence: self.sequence,
        };
        manifest.revision_id = revision_digest(&manifest)?;
        manifest.validate()?;
        Ok(manifest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub protocol_version: u16,
    pub revision_id: String,
    pub vault_id: String,
    pub epoch: u64,
    pub parents: Vec<String>,
    pub object_ids: Vec<String>,
    pub tombstones: Vec<String>,
    pub device_id: String,
    pub sequence: u64,
}

impl Manifest {
    pub fn validate(&self) -> SyncResult<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(SyncError::UnsupportedVersion);
        }
        validate_vault_id(&self.vault_id)?;
        if self.epoch == 0
            || self.sequence == 0
            || self.parents.len() > 32
            || self.object_ids.len() > MAX_MANIFEST_OBJECTS
            || self.tombstones.len() > MAX_MANIFEST_OBJECTS
            || !sorted_unique(&self.parents)
            || !sorted_unique(&self.object_ids)
            || !sorted_unique(&self.tombstones)
            || !self
                .parents
                .iter()
                .all(|id| valid_prefixed_hash(id, "revision:"))
            || !self
                .object_ids
                .iter()
                .all(|id| valid_prefixed_hash(id, "object:"))
            || !self.tombstones.iter().all(|id| valid_opaque_id(id))
            || !valid_prefixed_hash(&self.device_id, "device:")
            || self.revision_id != revision_digest(self)?
        {
            return Err(SyncError::InvalidManifest);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedManifest {
    pub manifest: Manifest,
    pub signature: Vec<u8>,
}

impl SignedManifest {
    pub fn verify(&self, device: &DeviceRecord) -> SyncResult<()> {
        self.manifest.validate()?;
        device.validate()?;
        if self.manifest.device_id != device.device_id {
            return Err(SyncError::DeviceMismatch);
        }
        let key =
            VerifyingKey::from_bytes(&device.public_key).map_err(|_| SyncError::InvalidDevice)?;
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| SyncError::InvalidSignature)?;
        key.verify(&canonical_manifest_bytes(&self.manifest)?, &signature)
            .map_err(|_| SyncError::InvalidSignature)
    }
}

pub fn validate_vault_id(id: &str) -> SyncResult<()> {
    if valid_opaque_id(id) && id.starts_with("vault:") && id.len() > "vault:".len() {
        Ok(())
    } else {
        Err(SyncError::InvalidVaultId)
    }
}

pub(crate) fn object_aad(vault_id: &str, epoch: u64) -> Vec<u8> {
    format!("foliora-sync-object-v1\0{vault_id}\0{epoch}").into_bytes()
}

pub(crate) fn object_digest(
    vault_id: &str,
    epoch: u64,
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> String {
    let mut digest = Sha256::new();
    digest.update(object_aad(vault_id, epoch));
    digest.update(nonce);
    digest.update(ciphertext);
    format!("object:{}", hex(&digest.finalize()))
}

pub(crate) fn canonical_manifest_bytes(manifest: &Manifest) -> SyncResult<Vec<u8>> {
    serde_json::to_vec(manifest).map_err(|_| SyncError::Serialize)
}

pub(crate) fn canonical_pairing_bytes(grant: &PairingGrant) -> SyncResult<Vec<u8>> {
    serde_json::to_vec(grant).map_err(|_| SyncError::Serialize)
}

pub(crate) fn pairing_aad(
    vault_id: &str,
    epoch: u64,
    authorizing_device_id: &str,
    recipient_device_id: &str,
) -> Vec<u8> {
    format!(
        "foliora-pairing-grant-v1\0{vault_id}\0{epoch}\0{authorizing_device_id}\0{recipient_device_id}"
    )
    .into_bytes()
}

pub(crate) fn device_digest(signing: &[u8; 32], exchange: &[u8; 32]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"foliora-device-v1\0");
    digest.update(signing);
    digest.update(exchange);
    format!("device:{}", hex(&digest.finalize()))
}

fn revision_digest(manifest: &Manifest) -> SyncResult<String> {
    let mut unsigned = manifest.clone();
    unsigned.revision_id.clear();
    let bytes = canonical_manifest_bytes(&unsigned)?;
    Ok(format!("revision:{}", hex(&Sha256::digest(bytes))))
}

fn sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_prefixed_hash(value: &str, prefix: &str) -> bool {
    value.len() == prefix.len() + 64
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_' | b'.'))
}
