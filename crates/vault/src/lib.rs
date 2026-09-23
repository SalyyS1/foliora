//! Offline encrypted persistence for Foliora sources.

mod crypto;
mod recovery;
mod storage;

use foliora_domain::{BundleDraft, Claim, ClaimStatus, Provenance, Source, SourceLocator};
use foliora_sync::{PendingPairing, SyncProfile};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

pub use crypto::KdfPolicy;
use crypto::{decrypt, encrypt};
use storage::{copy_new_synced, read_envelope, write_envelope_recoverable};

const STATE_SCHEMA_VERSION: u16 = 1;
pub const DEFAULT_MAX_BLOB_BYTES: usize = 25 * 1024 * 1024;

#[derive(Debug)]
pub enum VaultError {
    EmptyPassphrase,
    AlreadyExists,
    InvalidEnvelope,
    UnsupportedVersion(u16),
    UnsafeKdfParameters,
    AuthenticationFailed,
    InvalidRecoveryCode,
    InvalidRecoveryKit,
    RecoveryKitMismatch,
    InvalidSource(String),
    InvalidClaim(String),
    InvalidBundle(String),
    BlobTooLarge { actual: usize, limit: usize },
    FingerprintMismatch,
    DuplicateSourceId,
    StaleClaimRevision,
    DuplicateBundleId,
    MissingClaimReference(String),
    MissingClaim(String),
    InvalidSyncProfile(String),
    Serialize(String),
    Io(std::io::Error),
    Randomness,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyPassphrase => write!(f, "vault passphrase must not be empty"),
            Self::AlreadyExists => write!(f, "refusing to overwrite an existing vault"),
            Self::InvalidEnvelope => write!(f, "vault envelope is malformed"),
            Self::UnsupportedVersion(version) => write!(f, "unsupported vault version {version}"),
            Self::UnsafeKdfParameters => write!(f, "vault KDF parameters exceed supported policy"),
            Self::AuthenticationFailed => write!(f, "vault authentication failed"),
            Self::InvalidRecoveryCode => write!(f, "recovery code is malformed"),
            Self::InvalidRecoveryKit => write!(f, "recovery kit is malformed"),
            Self::RecoveryKitMismatch => write!(f, "recovery kit belongs to another vault"),
            Self::InvalidSource(error) => write!(f, "source is invalid: {error}"),
            Self::InvalidClaim(error) => write!(f, "claim is invalid: {error}"),
            Self::InvalidBundle(error) => write!(f, "bundle is invalid: {error}"),
            Self::BlobTooLarge { actual, limit } => {
                write!(f, "blob has {actual} bytes; limit is {limit}")
            }
            Self::FingerprintMismatch => write!(f, "blob does not match source fingerprint"),
            Self::DuplicateSourceId => {
                write!(f, "source identifier already belongs to different content")
            }
            Self::StaleClaimRevision => write!(f, "claim revision is stale or conflicting"),
            Self::DuplicateBundleId => {
                write!(f, "bundle identifier already exists with different data")
            }
            Self::MissingClaimReference(id) => write!(f, "bundle references missing claim {id}"),
            Self::MissingClaim(id) => write!(f, "claim {id} was not found"),
            Self::InvalidSyncProfile(error) => write!(f, "sync profile is invalid: {error}"),
            Self::Serialize(error) => write!(f, "vault serialization failed: {error}"),
            Self::Io(error) => error.fmt(f),
            Self::Randomness => write!(f, "operating-system randomness unavailable"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSource {
    pub source: Source,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VaultState {
    schema_version: u16,
    #[serde(default)]
    recovery_configured: bool,
    #[serde(default)]
    sources: BTreeMap<String, StoredSource>,
    #[serde(default)]
    claims: BTreeMap<String, Claim>,
    #[serde(default)]
    bundles: BTreeMap<String, BundleDraft>,
    #[serde(default)]
    sync_profile: Option<SyncProfile>,
    #[serde(default)]
    pending_sync_pairing: Option<PendingPairing>,
}

impl Default for VaultState {
    fn default() -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            recovery_configured: false,
            sources: BTreeMap::new(),
            claims: BTreeMap::new(),
            bundles: BTreeMap::new(),
            sync_profile: None,
            pending_sync_pairing: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    Inserted,
    AlreadyPresent,
}

pub struct Vault {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    salt: [u8; 16],
    policy: KdfPolicy,
    state: VaultState,
    max_blob_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryKitReceipt {
    pub path: PathBuf,
    pub bytes: u64,
    pub recovery_code: Zeroizing<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRotationReceipt {
    pub kit: RecoveryKitReceipt,
    pub local_revocation_complete: bool,
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.salt.zeroize();
        for stored in self.state.sources.values_mut() {
            stored.content.zeroize();
        }
    }
}

impl Vault {
    pub fn create(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, VaultError> {
        Self::create_with_policy(path, passphrase, KdfPolicy::default())
    }

    pub fn create_with_policy(
        path: impl AsRef<Path>,
        passphrase: &str,
        policy: KdfPolicy,
    ) -> Result<Self, VaultError> {
        if path.as_ref().exists() {
            return Err(VaultError::AlreadyExists);
        }
        policy.validate()?;
        let mut salt = [0_u8; 16];
        getrandom::getrandom(&mut salt).map_err(|_| VaultError::Randomness)?;
        let key = crypto::derive_key(passphrase, &salt, policy)?;
        let mut vault = Self {
            path: path.as_ref().to_owned(),
            key: Zeroizing::new(key),
            salt,
            policy,
            state: VaultState::default(),
            max_blob_bytes: DEFAULT_MAX_BLOB_BYTES,
        };
        vault.save()?;
        Ok(vault)
    }

    pub fn open(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, VaultError> {
        let envelope = read_envelope(path.as_ref())?;
        envelope.policy.validate()?;
        let key = crypto::derive_key(passphrase, &envelope.salt, envelope.policy)?;
        let plaintext = Zeroizing::new(decrypt(&envelope, &key)?);
        let state: VaultState = serde_json::from_slice(&plaintext)
            .map_err(|error| VaultError::Serialize(error.to_string()))?;
        if state.schema_version != STATE_SCHEMA_VERSION {
            return Err(VaultError::UnsupportedVersion(state.schema_version));
        }
        validate_state(&state, DEFAULT_MAX_BLOB_BYTES)?;
        Ok(Self {
            path: path.as_ref().to_owned(),
            key: Zeroizing::new(key),
            salt: envelope.salt,
            policy: envelope.policy,
            state,
            max_blob_bytes: DEFAULT_MAX_BLOB_BYTES,
        })
    }

    pub fn set_max_blob_bytes(&mut self, max_blob_bytes: usize) {
        self.max_blob_bytes = max_blob_bytes;
    }

    pub fn insert_source(
        &mut self,
        source: Source,
        content: Vec<u8>,
    ) -> Result<InsertOutcome, VaultError> {
        source
            .validate()
            .map_err(|error| VaultError::InvalidSource(error.to_string()))?;
        if content.len() > self.max_blob_bytes {
            return Err(VaultError::BlobTooLarge {
                actual: content.len(),
                limit: self.max_blob_bytes,
            });
        }
        let actual = format!("sha256:{}", hex_digest(&content));
        if source.fingerprint != actual {
            return Err(VaultError::FingerprintMismatch);
        }
        if let Some(existing) = self.state.sources.get(&source.id) {
            if existing.source.fingerprint == source.fingerprint && existing.content == content {
                return Ok(InsertOutcome::AlreadyPresent);
            }
            return Err(VaultError::DuplicateSourceId);
        }
        self.state
            .sources
            .insert(source.id.clone(), StoredSource { source, content });
        Ok(InsertOutcome::Inserted)
    }

    pub fn source(&self, id: &str) -> Option<&StoredSource> {
        self.state.sources.get(id)
    }

    pub fn sources(&self) -> impl Iterator<Item = &StoredSource> {
        self.state.sources.values()
    }
    pub fn source_count(&self) -> usize {
        self.state.sources.len()
    }

    pub fn claim_count(&self) -> usize {
        self.state.claims.len()
    }

    pub fn bundle_count(&self) -> usize {
        self.state.bundles.len()
    }

    pub fn recovery_configured(&self) -> bool {
        self.state.recovery_configured
    }

    pub fn sync_profile(&self) -> Option<&SyncProfile> {
        self.state.sync_profile.as_ref()
    }

    pub fn pending_sync_pairing(&self) -> Option<&PendingPairing> {
        self.state.pending_sync_pairing.as_ref()
    }

    pub fn set_sync_profile_persisted(&mut self, profile: SyncProfile) -> Result<(), VaultError> {
        profile
            .validate()
            .map_err(|error| VaultError::InvalidSyncProfile(error.to_string()))?;
        let previous = self.state.clone();
        self.state.sync_profile = Some(profile);
        self.commit_or_rollback(previous)
    }

    pub fn clear_sync_profile_persisted(&mut self) -> Result<(), VaultError> {
        let previous = self.state.clone();
        self.state.sync_profile = None;
        self.commit_or_rollback(previous)
    }

    pub fn set_pending_sync_pairing_persisted(
        &mut self,
        pending: PendingPairing,
    ) -> Result<(), VaultError> {
        pending
            .validate()
            .map_err(|error| VaultError::InvalidSyncProfile(error.to_string()))?;
        let previous = self.state.clone();
        self.state.pending_sync_pairing = Some(pending);
        self.commit_or_rollback(previous)
    }

    pub fn clear_pending_sync_pairing_persisted(&mut self) -> Result<(), VaultError> {
        let previous = self.state.clone();
        self.state.pending_sync_pairing = None;
        self.commit_or_rollback(previous)
    }

    pub fn finish_pending_sync_pairing(&mut self, profile: SyncProfile) -> Result<(), VaultError> {
        profile
            .validate()
            .map_err(|error| VaultError::InvalidSyncProfile(error.to_string()))?;
        if self.state.pending_sync_pairing.is_none() {
            return Err(VaultError::InvalidSyncProfile(
                "no pending pairing request".into(),
            ));
        }
        let previous = self.state.clone();
        self.state.sync_profile = Some(profile);
        self.state.pending_sync_pairing = None;
        self.commit_or_rollback(previous)
    }

    /// Serializes vault content without the sync credentials themselves. The
    /// caller must encrypt these bytes before handing them to a sync client.
    pub fn sync_snapshot(&self) -> Result<Vec<u8>, VaultError> {
        let mut state = self.state.clone();
        state.sync_profile = None;
        state.pending_sync_pairing = None;
        let bytes =
            serde_json::to_vec(&state).map_err(|error| VaultError::Serialize(error.to_string()))?;
        if bytes.len() > foliora_sync::MAX_OBJECT_BYTES {
            return Err(VaultError::BlobTooLarge {
                actual: bytes.len(),
                limit: foliora_sync::MAX_OBJECT_BYTES,
            });
        }
        Ok(bytes)
    }

    /// Atomically applies a decrypted sync snapshot while retaining the local
    /// device profile. A malformed or incompatible snapshot never mutates the
    /// unlocked vault.
    pub fn replace_from_sync_snapshot(&mut self, bytes: &[u8]) -> Result<(), VaultError> {
        let profile = self.state.sync_profile.clone();
        self.replace_from_sync_snapshot_with_profile(bytes, profile)
    }

    pub fn replace_from_sync_snapshot_with_profile(
        &mut self,
        bytes: &[u8],
        profile: Option<SyncProfile>,
    ) -> Result<(), VaultError> {
        if bytes.len() > foliora_sync::MAX_OBJECT_BYTES {
            return Err(VaultError::BlobTooLarge {
                actual: bytes.len(),
                limit: foliora_sync::MAX_OBJECT_BYTES,
            });
        }
        let mut incoming: VaultState = serde_json::from_slice(bytes)
            .map_err(|error| VaultError::Serialize(error.to_string()))?;
        let previous = self.state.clone();
        if let Some(profile) = &profile {
            profile
                .validate()
                .map_err(|error| VaultError::InvalidSyncProfile(error.to_string()))?;
        }
        incoming.sync_profile = profile;
        incoming.pending_sync_pairing = None;
        validate_state(&incoming, self.max_blob_bytes)?;
        self.state = incoming;
        self.commit_or_rollback(previous)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn upsert_claim(&mut self, claim: Claim) -> Result<InsertOutcome, VaultError> {
        claim
            .validate()
            .map_err(|error| VaultError::InvalidClaim(error.to_string()))?;
        validate_claim_against_sources(&claim, &self.state.sources)?;
        if let Some(existing) = self.state.claims.get(&claim.id) {
            if existing == &claim {
                return Ok(InsertOutcome::AlreadyPresent);
            }
            if claim.revision <= existing.revision {
                return Err(VaultError::StaleClaimRevision);
            }
        }
        self.state.claims.insert(claim.id.clone(), claim);
        Ok(InsertOutcome::Inserted)
    }

    pub fn claim(&self, id: &str) -> Option<&Claim> {
        self.state.claims.get(id)
    }

    pub fn claims(&self) -> impl Iterator<Item = &Claim> {
        self.state.claims.values()
    }

    pub fn insert_source_persisted(
        &mut self,
        source: Source,
        content: Vec<u8>,
    ) -> Result<InsertOutcome, VaultError> {
        let previous = self.state.clone();
        match self.insert_source(source, content) {
            Ok(InsertOutcome::AlreadyPresent) => Ok(InsertOutcome::AlreadyPresent),
            Ok(InsertOutcome::Inserted) => {
                self.commit_or_rollback(previous)?;
                Ok(InsertOutcome::Inserted)
            }
            Err(error) => {
                self.state = previous;
                Err(error)
            }
        }
    }

    /// Atomically inserts all derived sources from one container import.
    /// No encrypted save is committed if any identifier or fingerprint fails.
    pub fn insert_sources_persisted(
        &mut self,
        sources: Vec<(Source, Vec<u8>)>,
    ) -> Result<Vec<InsertOutcome>, VaultError> {
        let previous = self.state.clone();
        let mut outcomes = Vec::with_capacity(sources.len());
        for (source, content) in sources {
            match self.insert_source(source, content) {
                Ok(outcome) => outcomes.push(outcome),
                Err(error) => {
                    self.state = previous;
                    return Err(error);
                }
            }
        }
        if outcomes.contains(&InsertOutcome::Inserted) {
            self.commit_or_rollback(previous)?;
        }
        Ok(outcomes)
    }

    pub fn upsert_claim_persisted(&mut self, claim: Claim) -> Result<InsertOutcome, VaultError> {
        let previous = self.state.clone();
        match self.upsert_claim(claim) {
            Ok(InsertOutcome::AlreadyPresent) => Ok(InsertOutcome::AlreadyPresent),
            Ok(InsertOutcome::Inserted) => {
                self.commit_or_rollback(previous)?;
                Ok(InsertOutcome::Inserted)
            }
            Err(error) => {
                self.state = previous;
                Err(error)
            }
        }
    }

    pub fn transition_claim_persisted(
        &mut self,
        id: &str,
        status: ClaimStatus,
    ) -> Result<Claim, VaultError> {
        let id = id.to_owned();
        self.persist_change(|vault| {
            let mut claim = vault
                .state
                .claims
                .get(&id)
                .cloned()
                .ok_or_else(|| VaultError::MissingClaim(id.clone()))?;
            claim
                .transition(status)
                .map_err(|error| VaultError::InvalidClaim(error.to_string()))?;
            vault.upsert_claim(claim.clone())?;
            Ok(claim)
        })
    }

    pub fn insert_bundle(&mut self, bundle: BundleDraft) -> Result<InsertOutcome, VaultError> {
        bundle
            .validate()
            .map_err(|error| VaultError::InvalidBundle(error.to_string()))?;
        if let Some(missing) = bundle
            .claim_ids
            .iter()
            .find(|claim_id| !self.state.claims.contains_key(*claim_id))
        {
            return Err(VaultError::MissingClaimReference(missing.clone()));
        }
        if let Some(existing) = self.state.bundles.get(&bundle.id) {
            return if existing == &bundle {
                Ok(InsertOutcome::AlreadyPresent)
            } else {
                Err(VaultError::DuplicateBundleId)
            };
        }
        self.state.bundles.insert(bundle.id.clone(), bundle);
        Ok(InsertOutcome::Inserted)
    }

    pub fn insert_bundle_persisted(
        &mut self,
        bundle: BundleDraft,
    ) -> Result<InsertOutcome, VaultError> {
        let previous = self.state.clone();
        match self.insert_bundle(bundle) {
            Ok(InsertOutcome::AlreadyPresent) => Ok(InsertOutcome::AlreadyPresent),
            Ok(InsertOutcome::Inserted) => {
                self.commit_or_rollback(previous)?;
                Ok(InsertOutcome::Inserted)
            }
            Err(error) => {
                self.state = previous;
                Err(error)
            }
        }
    }

    pub fn bundle(&self, id: &str) -> Option<&BundleDraft> {
        self.state.bundles.get(id)
    }

    pub fn save(&mut self) -> Result<(), VaultError> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&self.state)
                .map_err(|error| VaultError::Serialize(error.to_string()))?,
        );
        let envelope = encrypt(&plaintext, &self.key, self.salt, self.policy)?;
        write_envelope_recoverable(&self.path, &envelope)
    }

    pub fn backup_path(&self) -> PathBuf {
        storage::backup_path(&self.path)
    }

    /// Writes an authenticated encrypted snapshot to a new destination.
    /// The destination is removed if post-copy verification fails.
    pub fn create_verified_backup(
        &mut self,
        destination: impl AsRef<Path>,
    ) -> Result<u64, VaultError> {
        self.save()?;
        let destination = destination.as_ref();
        let bytes = copy_new_synced(&self.path, destination)?;
        if let Err(error) = self.verify_copy(destination) {
            let _ = std::fs::remove_file(destination);
            return Err(error);
        }
        Ok(bytes)
    }

    /// Authenticates a backup and restores it to a new path without overwriting.
    pub fn restore_to_new_path(
        backup: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        passphrase: &str,
    ) -> Result<Self, VaultError> {
        let backup = backup.as_ref();
        let destination = destination.as_ref();
        let verified = Self::open(backup, passphrase)?;
        copy_new_synced(backup, destination)?;
        drop(verified);
        match Self::open(destination, passphrase) {
            Ok(vault) => Ok(vault),
            Err(error) => {
                let _ = std::fs::remove_file(destination);
                Err(error)
            }
        }
    }

    /// Creates a separate key-wrapping kit. Its recovery code is returned once
    /// and is never written into either the vault or kit.
    pub fn create_recovery_kit(
        &mut self,
        destination: impl AsRef<Path>,
    ) -> Result<RecoveryKitReceipt, VaultError> {
        self.save()?;
        let destination = destination.as_ref();
        let (bytes, recovery_code) = recovery::create(destination, &self.salt, &self.key)?;
        let recovered = match recovery::recover_key(destination, &self.salt, &recovery_code) {
            Ok(recovered) => recovered,
            Err(error) => {
                let _ = std::fs::remove_file(destination);
                return Err(error);
            }
        };
        if recovered.as_ref() != self.key.as_ref() {
            let _ = std::fs::remove_file(destination);
            return Err(VaultError::InvalidRecoveryKit);
        }
        Ok(RecoveryKitReceipt {
            path: destination.to_owned(),
            bytes,
            recovery_code,
        })
    }

    /// Re-encrypts the vault under the same passphrase and creates a fresh
    /// recovery kit. Changing the vault salt and key invalidates kits from the
    /// previous local recovery epoch.
    pub fn rotate_recovery_key(
        &mut self,
        destination: impl AsRef<Path>,
        passphrase: &str,
    ) -> Result<RecoveryRotationReceipt, VaultError> {
        let destination = destination.as_ref();
        let backup = storage::backup_path(&self.path);
        let temp = self.path.with_extension("vault.tmp");
        if destination.exists()
            || destination == self.path
            || destination == backup
            || destination == temp
        {
            return Err(VaultError::AlreadyExists);
        }

        let verified_key = Zeroizing::new(crypto::derive_key(passphrase, &self.salt, self.policy)?);
        if verified_key.as_ref() != self.key.as_ref() {
            return Err(VaultError::AuthenticationFailed);
        }
        let mut salt = [0_u8; 16];
        getrandom::getrandom(&mut salt).map_err(|_| VaultError::Randomness)?;
        let key = Zeroizing::new(crypto::derive_key(passphrase, &salt, self.policy)?);
        let (bytes, recovery_code) = recovery::create(destination, &salt, &key)?;
        let recovered = match recovery::recover_key(destination, &salt, &recovery_code) {
            Ok(recovered) => recovered,
            Err(error) => {
                let _ = std::fs::remove_file(destination);
                return Err(error);
            }
        };
        if recovered.as_ref() != key.as_ref() {
            let _ = std::fs::remove_file(destination);
            return Err(VaultError::InvalidRecoveryKit);
        }

        let old_key = std::mem::replace(&mut self.key, key);
        let old_salt = std::mem::replace(&mut self.salt, salt);
        let old_recovery_configured = self.state.recovery_configured;
        self.state.recovery_configured = false;

        if let Err(error) = self.save() {
            self.key = old_key;
            self.salt = old_salt;
            self.state.recovery_configured = old_recovery_configured;
            let _ = std::fs::remove_file(destination);
            return Err(error);
        }

        let local_revocation_complete = !backup.exists() || std::fs::remove_file(&backup).is_ok();
        Ok(RecoveryRotationReceipt {
            kit: RecoveryKitReceipt {
                path: destination.to_owned(),
                bytes,
                recovery_code,
            },
            local_revocation_complete,
        })
    }

    pub fn confirm_recovery_configured(&mut self) -> Result<(), VaultError> {
        if self.state.recovery_configured {
            return Ok(());
        }
        self.state.recovery_configured = true;
        if let Err(error) = self.save() {
            self.state.recovery_configured = false;
            return Err(error);
        }
        Ok(())
    }

    /// Recovers an encrypted snapshot without its old passphrase and immediately
    /// re-encrypts it at a new destination using a new passphrase.
    pub fn restore_with_recovery(
        backup: impl AsRef<Path>,
        recovery_kit: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        recovery_code: &str,
        new_passphrase: &str,
    ) -> Result<Self, VaultError> {
        let backup = backup.as_ref();
        let destination = destination.as_ref();
        if destination.exists() || backup == destination {
            return Err(VaultError::AlreadyExists);
        }
        let envelope = read_envelope(backup)?;
        let old_key = recovery::recover_key(recovery_kit.as_ref(), &envelope.salt, recovery_code)?;
        let plaintext = Zeroizing::new(decrypt(&envelope, &old_key)?);
        let state: VaultState = serde_json::from_slice(&plaintext)
            .map_err(|error| VaultError::Serialize(error.to_string()))?;
        if state.schema_version != STATE_SCHEMA_VERSION {
            return Err(VaultError::UnsupportedVersion(state.schema_version));
        }
        validate_state(&state, DEFAULT_MAX_BLOB_BYTES)?;
        let policy = KdfPolicy::default();
        let mut salt = [0_u8; 16];
        getrandom::getrandom(&mut salt).map_err(|_| VaultError::Randomness)?;
        let key = crypto::derive_key(new_passphrase, &salt, policy)?;
        let mut vault = Self {
            path: destination.to_owned(),
            key: Zeroizing::new(key),
            salt,
            policy,
            state,
            max_blob_bytes: DEFAULT_MAX_BLOB_BYTES,
        };
        if let Err(error) = vault.save() {
            let _ = std::fs::remove_file(destination);
            return Err(error);
        }
        Ok(vault)
    }

    fn verify_copy(&self, path: &Path) -> Result<(), VaultError> {
        let envelope = read_envelope(path)?;
        if envelope.salt != self.salt || envelope.policy != self.policy {
            return Err(VaultError::InvalidEnvelope);
        }
        let plaintext = Zeroizing::new(decrypt(&envelope, &self.key)?);
        let state: VaultState = serde_json::from_slice(&plaintext)
            .map_err(|error| VaultError::Serialize(error.to_string()))?;
        if state != self.state {
            return Err(VaultError::InvalidEnvelope);
        }
        validate_state(&state, self.max_blob_bytes)
    }

    fn persist_change<T>(
        &mut self,
        change: impl FnOnce(&mut Self) -> Result<T, VaultError>,
    ) -> Result<T, VaultError> {
        let previous = self.state.clone();
        match change(self).and_then(|result| self.save().map(|()| result)) {
            Ok(result) => Ok(result),
            Err(error) => {
                self.state = previous;
                Err(error)
            }
        }
    }

    fn commit_or_rollback(&mut self, previous: VaultState) -> Result<(), VaultError> {
        if let Err(error) = self.save() {
            self.state = previous;
            return Err(error);
        }
        Ok(())
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_state(state: &VaultState, max_blob_bytes: usize) -> Result<(), VaultError> {
    for (id, stored) in &state.sources {
        stored
            .source
            .validate()
            .map_err(|error| VaultError::InvalidSource(error.to_string()))?;
        if id != &stored.source.id {
            return Err(VaultError::InvalidEnvelope);
        }
        if stored.content.len() > max_blob_bytes {
            return Err(VaultError::BlobTooLarge {
                actual: stored.content.len(),
                limit: max_blob_bytes,
            });
        }
        let actual = format!("sha256:{}", hex_digest(&stored.content));
        if stored.source.fingerprint != actual {
            return Err(VaultError::FingerprintMismatch);
        }
    }
    for (id, claim) in &state.claims {
        if id != &claim.id {
            return Err(VaultError::InvalidEnvelope);
        }
        claim
            .validate()
            .map_err(|error| VaultError::InvalidClaim(error.to_string()))?;
        validate_claim_against_sources(claim, &state.sources)?;
    }
    for (id, bundle) in &state.bundles {
        if id != &bundle.id {
            return Err(VaultError::InvalidEnvelope);
        }
        bundle
            .validate()
            .map_err(|error| VaultError::InvalidBundle(error.to_string()))?;
        if bundle
            .claim_ids
            .iter()
            .any(|claim_id| !state.claims.contains_key(claim_id))
        {
            return Err(VaultError::InvalidEnvelope);
        }
    }
    if let Some(profile) = &state.sync_profile {
        profile
            .validate()
            .map_err(|error| VaultError::InvalidSyncProfile(error.to_string()))?;
    }
    if let Some(pending) = &state.pending_sync_pairing {
        pending
            .validate()
            .map_err(|error| VaultError::InvalidSyncProfile(error.to_string()))?;
        if state.sync_profile.is_some() {
            return Err(VaultError::InvalidEnvelope);
        }
    }
    Ok(())
}

fn validate_claim_against_sources(
    claim: &Claim,
    sources: &BTreeMap<String, StoredSource>,
) -> Result<(), VaultError> {
    let Provenance::Source(provenance) = &claim.provenance else {
        return Ok(());
    };
    let stored = sources
        .get(&provenance.source_id)
        .ok_or(VaultError::InvalidEnvelope)?;
    if let SourceLocator::Span { start, end } = provenance.locator {
        let start = usize::try_from(start).map_err(|_| VaultError::InvalidEnvelope)?;
        let end = usize::try_from(end).map_err(|_| VaultError::InvalidEnvelope)?;
        let text = std::str::from_utf8(&stored.content).map_err(|_| VaultError::InvalidEnvelope)?;
        let cited = text.get(start..end).ok_or(VaultError::InvalidEnvelope)?;
        if let serde_json::Value::String(value) = &claim.value {
            if cited != value {
                return Err(VaultError::InvalidEnvelope);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use foliora_domain::{
        ClaimStatus, Provenance, Sensitivity, SourceLocator, SourceProvenance, ValidityWindow,
    };
    use foliora_sync::{DeviceIdentity, EpochKey, SyncProfile};
    use serde_json::Value;
    use std::fs;

    fn fast_policy() -> KdfPolicy {
        KdfPolicy {
            memory_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
        }
    }
    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("foliora-{name}-{}.vault", std::process::id()))
    }
    fn source_for(content: &[u8]) -> Source {
        Source {
            schema_version: 1,
            id: format!("source:{}", hex_digest(content)),
            fingerprint: format!("sha256:{}", hex_digest(content)),
            media_type: "text/plain".into(),
            title: None,
            captured_at: "2026-09-11T00:00:00Z".into(),
            sensitivity: Sensitivity::Private,
            expires_at: None,
        }
    }

    fn confirmed_claim(source_id: &str, revision: u64) -> Claim {
        Claim {
            schema_version: 1,
            id: "claim:1".into(),
            claim_type: "project.goal".into(),
            subject: "project:1".into(),
            value: Value::String("Ship safely".into()),
            status: ClaimStatus::Confirmed,
            provenance: Provenance::Source(SourceProvenance {
                source_id: source_id.into(),
                locator: SourceLocator::Span { start: 0, end: 11 },
                extractor: None,
            }),
            captured_at: "2026-09-11T00:00:00Z".into(),
            validity: ValidityWindow::default(),
            sensitivity: Sensitivity::Private,
            revision,
        }
    }

    #[test]
    fn round_trip_requires_correct_passphrase() {
        let path = temp_path("roundtrip");
        let _ = fs::remove_file(&path);
        let mut vault = Vault::create_with_policy(&path, "correct horse", fast_policy()).unwrap();
        let content = b"private context".to_vec();
        let source = source_for(&content);
        vault
            .insert_source(source.clone(), content.clone())
            .unwrap();
        vault.save().unwrap();
        drop(vault);
        assert!(matches!(
            Vault::open(&path, "wrong"),
            Err(VaultError::AuthenticationFailed)
        ));
        let opened = Vault::open(&path, "correct horse").unwrap();
        assert_eq!(opened.source(&source.id).unwrap().content, content);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn plaintext_is_not_present_in_encrypted_file() {
        let path = temp_path("ciphertext");
        let _ = fs::remove_file(&path);
        let mut vault = Vault::create_with_policy(&path, "passphrase", fast_policy()).unwrap();
        let content = b"secret-marker-9137".to_vec();
        vault
            .insert_source(source_for(&content), content.clone())
            .unwrap();
        vault.save().unwrap();
        let bytes = fs::read(&path).unwrap();
        assert!(!bytes.windows(content.len()).any(|window| window == content));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_mismatched_and_oversized_blobs() {
        let path = temp_path("limits");
        let _ = fs::remove_file(&path);
        let mut vault = Vault::create_with_policy(&path, "passphrase", fast_policy()).unwrap();
        assert!(matches!(
            vault.insert_source(source_for(b"one"), b"two".to_vec()),
            Err(VaultError::FingerprintMismatch)
        ));
        vault.set_max_blob_bytes(2);
        assert!(matches!(
            vault.insert_source(source_for(b"abc"), b"abc".to_vec()),
            Err(VaultError::BlobTooLarge { .. })
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn duplicate_identifier_cannot_hide_different_content() {
        let path = temp_path("duplicate-id");
        let _ = fs::remove_file(&path);
        let mut vault = Vault::create_with_policy(&path, "passphrase", fast_policy()).unwrap();
        let first = source_for(b"first");
        vault
            .insert_source(first.clone(), b"first".to_vec())
            .unwrap();
        let mut second = source_for(b"second");
        second.id = first.id;
        assert!(matches!(
            vault.insert_source(second, b"second".to_vec()),
            Err(VaultError::DuplicateSourceId)
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn idempotent_persisted_insert_does_not_rotate_recovery_backup() {
        let path = temp_path("persisted-idempotency");
        let _ = fs::remove_file(&path);
        let backup = storage::backup_path(&path);
        let _ = fs::remove_file(&backup);
        let mut vault = Vault::create_with_policy(&path, "passphrase", fast_policy()).unwrap();
        let content = b"same source".to_vec();
        let source = source_for(&content);
        assert_eq!(
            vault
                .insert_source_persisted(source.clone(), content.clone())
                .unwrap(),
            InsertOutcome::Inserted
        );
        let vault_before = fs::read(&path).unwrap();
        let backup_before = fs::read(&backup).unwrap();
        assert_eq!(
            vault.insert_source_persisted(source, content).unwrap(),
            InsertOutcome::AlreadyPresent
        );
        assert_eq!(fs::read(&path).unwrap(), vault_before);
        assert_eq!(fs::read(&backup).unwrap(), backup_before);
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(backup);
    }

    #[test]
    fn multi_source_import_rolls_back_every_item_on_collision() {
        let path = temp_path("atomic-sources");
        let _ = fs::remove_file(&path);
        let mut vault = Vault::create_with_policy(&path, "passphrase", fast_policy()).unwrap();
        let existing = source_for(b"existing");
        vault
            .insert_source_persisted(existing.clone(), b"existing".to_vec())
            .unwrap();
        let new_source = source_for(b"new derived body");
        let mut colliding = source_for(b"different");
        colliding.id = existing.id;
        assert!(matches!(
            vault.insert_sources_persisted(vec![
                (new_source.clone(), b"new derived body".to_vec()),
                (colliding, b"different".to_vec()),
            ]),
            Err(VaultError::DuplicateSourceId)
        ));
        assert!(vault.source(&new_source.id).is_none());
        assert_eq!(vault.source_count(), 1);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn create_refuses_to_overwrite_existing_vault() {
        let path = temp_path("no-overwrite");
        let _ = fs::remove_file(&path);
        let vault = Vault::create_with_policy(&path, "first", fast_policy()).unwrap();
        drop(vault);
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            Vault::create_with_policy(&path, "second", fast_policy()),
            Err(VaultError::AlreadyExists)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn ciphertext_tampering_fails_authentication() {
        let path = temp_path("tamper");
        let _ = fs::remove_file(&path);
        let vault = Vault::create_with_policy(&path, "passphrase", fast_policy()).unwrap();
        drop(vault);
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.last_mut().unwrap();
        *last ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            Vault::open(&path, "passphrase"),
            Err(VaultError::AuthenticationFailed)
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn second_save_keeps_encrypted_recovery_backup() {
        let path = temp_path("backup");
        let _ = fs::remove_file(&path);
        let backup = storage::backup_path(&path);
        let _ = fs::remove_file(&backup);
        let mut vault = Vault::create_with_policy(&path, "passphrase", fast_policy()).unwrap();
        let content = b"backup content".to_vec();
        vault.insert_source(source_for(&content), content).unwrap();
        vault.save().unwrap();
        assert!(backup.exists());
        assert!(Vault::open(&backup, "passphrase").is_ok());
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(backup);
    }

    #[test]
    fn verified_backup_restores_to_a_new_machine_path() {
        let path = temp_path("verified-backup-source");
        let backup = temp_path("verified-backup-copy").with_extension("foliora-backup");
        let restored = temp_path("verified-backup-restored");
        for candidate in [&path, &backup, &restored] {
            let _ = fs::remove_file(candidate);
        }
        let mut vault = Vault::create_with_policy(&path, "passphrase", fast_policy()).unwrap();
        let content = b"portable encrypted recovery".to_vec();
        let source = source_for(&content);
        vault
            .insert_source_persisted(source.clone(), content)
            .unwrap();
        let copied = vault.create_verified_backup(&backup).unwrap();
        assert_eq!(copied, fs::metadata(&backup).unwrap().len());
        assert_ne!(fs::read(&backup).unwrap(), b"portable encrypted recovery");

        let recovered = Vault::restore_to_new_path(&backup, &restored, "passphrase").unwrap();
        assert_eq!(recovered.source(&source.id).unwrap().source, source);
        assert_eq!(recovered.path(), restored);
        for candidate in [path, backup, restored] {
            let _ = fs::remove_file(candidate);
        }
    }

    #[test]
    fn restore_fails_closed_for_wrong_key_tamper_and_existing_destination() {
        let path = temp_path("restore-fail-source");
        let backup = temp_path("restore-fail-copy").with_extension("foliora-backup");
        let destination = temp_path("restore-fail-destination");
        for candidate in [&path, &backup, &destination] {
            let _ = fs::remove_file(candidate);
        }
        let mut vault = Vault::create_with_policy(&path, "right", fast_policy()).unwrap();
        vault.create_verified_backup(&backup).unwrap();
        assert!(matches!(
            Vault::restore_to_new_path(&backup, &destination, "wrong"),
            Err(VaultError::AuthenticationFailed)
        ));
        assert!(!destination.exists());

        fs::write(&destination, b"do not overwrite").unwrap();
        assert!(matches!(
            Vault::restore_to_new_path(&backup, &destination, "right"),
            Err(VaultError::AlreadyExists)
        ));
        assert_eq!(fs::read(&destination).unwrap(), b"do not overwrite");
        fs::remove_file(&destination).unwrap();

        let mut bytes = fs::read(&backup).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&backup, bytes).unwrap();
        assert!(matches!(
            Vault::restore_to_new_path(&backup, &destination, "right"),
            Err(VaultError::AuthenticationFailed)
        ));
        assert!(!destination.exists());
        for candidate in [path, backup, destination] {
            let _ = fs::remove_file(candidate);
        }
    }

    #[test]
    fn recovery_kit_restores_with_a_new_passphrase_without_storing_the_code() {
        let path = temp_path("recovery-source");
        let backup = temp_path("recovery-backup").with_extension("foliora-backup");
        let kit = temp_path("recovery-kit").with_extension("foliora-recovery");
        let restored = temp_path("recovery-restored");
        for candidate in [&path, &backup, &kit, &restored] {
            let _ = fs::remove_file(candidate);
        }
        let mut vault = Vault::create_with_policy(&path, "old passphrase", fast_policy()).unwrap();
        let content = b"recover this exact encrypted state".to_vec();
        let source = source_for(&content);
        vault
            .insert_source_persisted(source.clone(), content)
            .unwrap();
        vault.create_verified_backup(&backup).unwrap();
        let receipt = vault.create_recovery_kit(&kit).unwrap();
        let recovery_code = receipt.recovery_code.clone();
        assert!(!vault.recovery_configured());
        vault.confirm_recovery_configured().unwrap();
        assert!(vault.recovery_configured());
        assert_eq!(recovery_code.split('-').count(), 16);
        assert!(!fs::read(&kit)
            .unwrap()
            .windows(recovery_code.len())
            .any(|window| window == recovery_code.as_bytes()));
        drop(vault);

        assert!(Vault::open(&path, "old passphrase")
            .unwrap()
            .recovery_configured());

        let recovered = Vault::restore_with_recovery(
            &backup,
            &kit,
            &restored,
            &recovery_code,
            "brand new passphrase",
        )
        .unwrap();
        assert_eq!(recovered.source(&source.id).unwrap().source, source);
        assert!(!recovered.recovery_configured());
        drop(recovered);
        assert!(Vault::open(&restored, "old passphrase").is_err());
        assert!(Vault::open(&restored, "brand new passphrase").is_ok());
        for candidate in [path, backup, kit, restored] {
            let _ = fs::remove_file(candidate);
        }
    }

    #[test]
    fn recovery_rejects_wrong_code_tamper_mismatched_vault_and_existing_path() {
        let first = temp_path("recovery-first");
        let first_backup = temp_path("recovery-first-backup").with_extension("foliora-backup");
        let first_kit = temp_path("recovery-first-kit").with_extension("foliora-recovery");
        let second = temp_path("recovery-second");
        let second_backup = temp_path("recovery-second-backup").with_extension("foliora-backup");
        let destination = temp_path("recovery-failure-destination");
        for candidate in [
            &first,
            &first_backup,
            &first_kit,
            &second,
            &second_backup,
            &destination,
        ] {
            let _ = fs::remove_file(candidate);
        }
        let mut first_vault = Vault::create_with_policy(&first, "one", fast_policy()).unwrap();
        first_vault.create_verified_backup(&first_backup).unwrap();
        let receipt = first_vault.create_recovery_kit(&first_kit).unwrap();
        let mut second_vault = Vault::create_with_policy(&second, "two", fast_policy()).unwrap();
        second_vault.create_verified_backup(&second_backup).unwrap();

        assert!(matches!(
            Vault::restore_with_recovery(
                &first_backup,
                &first_kit,
                &destination,
                "0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000",
                "new"
            ),
            Err(VaultError::AuthenticationFailed)
        ));
        assert!(!destination.exists());
        assert!(matches!(
            Vault::restore_with_recovery(
                &second_backup,
                &first_kit,
                &destination,
                &receipt.recovery_code,
                "new"
            ),
            Err(VaultError::RecoveryKitMismatch)
        ));
        fs::write(&destination, b"keep me").unwrap();
        assert!(matches!(
            Vault::restore_with_recovery(
                &first_backup,
                &first_kit,
                &destination,
                &receipt.recovery_code,
                "new"
            ),
            Err(VaultError::AlreadyExists)
        ));
        assert_eq!(fs::read(&destination).unwrap(), b"keep me");
        fs::remove_file(&destination).unwrap();
        let mut kit_bytes = fs::read(&first_kit).unwrap();
        *kit_bytes.last_mut().unwrap() ^= 1;
        fs::write(&first_kit, kit_bytes).unwrap();
        assert!(matches!(
            Vault::restore_with_recovery(
                &first_backup,
                &first_kit,
                &destination,
                &receipt.recovery_code,
                "new"
            ),
            Err(VaultError::AuthenticationFailed)
        ));
        assert!(!destination.exists());
        for candidate in [
            first,
            first_backup,
            first_kit,
            second,
            second_backup,
            destination,
        ] {
            let _ = fs::remove_file(candidate);
        }
    }

    #[test]
    fn recovery_rotation_invalidates_old_kit_and_requires_new_confirmation() {
        let path = temp_path("recovery-rotation");
        let old_kit = temp_path("recovery-rotation-old").with_extension("foliora-recovery");
        let new_kit = temp_path("recovery-rotation-new").with_extension("foliora-recovery");
        for candidate in [&path, &old_kit, &new_kit, &storage::backup_path(&path)] {
            let _ = fs::remove_file(candidate);
        }
        let mut vault = Vault::create_with_policy(&path, "passphrase", fast_policy()).unwrap();
        let old = vault.create_recovery_kit(&old_kit).unwrap();
        vault.confirm_recovery_configured().unwrap();
        let old_salt = vault.salt;
        let rotated = vault.rotate_recovery_key(&new_kit, "passphrase").unwrap();

        assert_ne!(vault.salt, old_salt);
        assert!(!vault.recovery_configured());
        assert!(matches!(
            recovery::recover_key(&old_kit, &vault.salt, &old.recovery_code),
            Err(VaultError::RecoveryKitMismatch)
        ));
        assert!(recovery::recover_key(&new_kit, &vault.salt, &rotated.kit.recovery_code).is_ok());
        assert!(rotated.local_revocation_complete);
        assert!(!storage::backup_path(&path).exists());

        for candidate in [path, old_kit, new_kit] {
            let _ = fs::remove_file(candidate);
        }
    }

    #[test]
    fn recovery_rotation_preflight_failures_do_not_mutate_vault() {
        let path = temp_path("recovery-rotation-preflight");
        let occupied = temp_path("recovery-rotation-occupied").with_extension("foliora-recovery");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&occupied);
        fs::write(&occupied, b"keep").unwrap();
        let mut vault = Vault::create_with_policy(&path, "passphrase", fast_policy()).unwrap();
        vault.confirm_recovery_configured().unwrap();
        let original_salt = vault.salt;

        assert!(matches!(
            vault.rotate_recovery_key(&occupied, "passphrase"),
            Err(VaultError::AlreadyExists)
        ));
        assert!(matches!(
            vault.rotate_recovery_key(occupied.with_extension("new"), "wrong"),
            Err(VaultError::AuthenticationFailed)
        ));
        assert_eq!(vault.salt, original_salt);
        assert!(vault.recovery_configured());
        assert_eq!(fs::read(&occupied).unwrap(), b"keep");

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(occupied);
    }

    #[test]
    fn claims_and_bundles_round_trip_inside_encrypted_state() {
        let path = temp_path("domain-state");
        let _ = fs::remove_file(&path);
        let mut vault = Vault::create_with_policy(&path, "passphrase", fast_policy()).unwrap();
        let content = b"Ship safely".to_vec();
        let source = source_for(&content);
        vault.insert_source(source.clone(), content).unwrap();
        let claim = confirmed_claim(&source.id, 1);
        vault.upsert_claim(claim.clone()).unwrap();
        let bundle = BundleDraft {
            schema_version: 1,
            id: "bundle:1".into(),
            purpose: "Project handoff".into(),
            claim_ids: vec![claim.id.clone()],
            expires_at: None,
        };
        vault.insert_bundle(bundle.clone()).unwrap();
        vault.save().unwrap();
        drop(vault);

        let opened = Vault::open(&path, "passphrase").unwrap();
        assert_eq!(opened.claim(&claim.id), Some(&claim));
        assert_eq!(opened.bundle(&bundle.id), Some(&bundle));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn persisted_bundle_is_immediately_recoverable() {
        let path = temp_path("persisted-bundle");
        let _ = fs::remove_file(&path);
        let mut vault = Vault::create_with_policy(&path, "passphrase", fast_policy()).unwrap();
        let content = b"Ship safely".to_vec();
        let source = source_for(&content);
        vault.insert_source(source.clone(), content).unwrap();
        let claim = confirmed_claim(&source.id, 1);
        vault.upsert_claim(claim.clone()).unwrap();
        vault.save().unwrap();
        let bundle = BundleDraft {
            schema_version: 1,
            id: "bundle:persisted".into(),
            purpose: "Project handoff".into(),
            claim_ids: vec![claim.id],
            expires_at: None,
        };
        assert_eq!(
            vault.insert_bundle_persisted(bundle.clone()).unwrap(),
            InsertOutcome::Inserted
        );
        drop(vault);
        let reopened = Vault::open(&path, "passphrase").unwrap();
        assert_eq!(reopened.bundle(&bundle.id), Some(&bundle));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn stale_claim_revision_is_rejected() {
        let path = temp_path("stale-claim");
        let _ = fs::remove_file(&path);
        let mut vault = Vault::create_with_policy(&path, "passphrase", fast_policy()).unwrap();
        let content = b"Ship safely".to_vec();
        let source = source_for(&content);
        vault.insert_source(source.clone(), content).unwrap();
        vault.upsert_claim(confirmed_claim(&source.id, 2)).unwrap();
        assert!(matches!(
            vault.upsert_claim(confirmed_claim(&source.id, 1)),
            Err(VaultError::StaleClaimRevision)
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn span_claim_must_match_encrypted_source_blob() {
        let path = temp_path("span-integrity");
        let _ = fs::remove_file(&path);
        let mut vault = Vault::create_with_policy(&path, "passphrase", fast_policy()).unwrap();
        let content = b"Ship safely".to_vec();
        let source = source_for(&content);
        vault.insert_source(source.clone(), content).unwrap();
        let mut claim = confirmed_claim(&source.id, 1);
        claim.value = Value::String("Not in source".into());
        assert!(matches!(
            vault.upsert_claim(claim),
            Err(VaultError::InvalidEnvelope)
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn bundle_cannot_reference_missing_claim() {
        let path = temp_path("missing-claim");
        let _ = fs::remove_file(&path);
        let mut vault = Vault::create_with_policy(&path, "passphrase", fast_policy()).unwrap();
        let bundle = BundleDraft {
            schema_version: 1,
            id: "bundle:missing".into(),
            purpose: "Project handoff".into(),
            claim_ids: vec!["claim:missing".into()],
            expires_at: None,
        };
        assert!(matches!(
            vault.insert_bundle(bundle),
            Err(VaultError::MissingClaimReference(id)) if id == "claim:missing"
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn sync_profile_is_persisted_inside_encryption_and_snapshot_excludes_credentials() {
        let path = temp_path("sync-profile");
        let _ = fs::remove_file(&path);
        let mut vault = Vault::create_with_policy(&path, "passphrase", fast_policy()).unwrap();
        let content = b"private sync content".to_vec();
        let source = source_for(&content);
        vault.insert_source(source, content).unwrap();
        let identity = DeviceIdentity::generate().unwrap();
        let profile = SyncProfile::new(
            "https://sync.example".into(),
            "vault:0123456789abcdef".into(),
            identity.record("This device").unwrap(),
            &identity,
            "device-token-that-must-stay-encrypted-123".into(),
            &EpochKey::from_bytes([11; 32]),
            false,
        )
        .unwrap();
        vault.set_sync_profile_persisted(profile).unwrap();
        let raw = fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("device-token-that-must-stay-encrypted"));
        let snapshot = vault.sync_snapshot().unwrap();
        assert!(
            !String::from_utf8_lossy(&snapshot).contains("device-token-that-must-stay-encrypted")
        );
        vault.replace_from_sync_snapshot(&snapshot).unwrap();
        assert!(vault.sync_profile().is_some());
        drop(vault);
        let reopened = Vault::open(&path, "passphrase").unwrap();
        assert_eq!(
            reopened.sync_profile().unwrap().vault_id,
            "vault:0123456789abcdef"
        );
        let _ = fs::remove_file(path);
    }
}
