//! Client-side primitives for Foliora's opaque E2EE synchronization protocol.

pub mod client;
mod crypto;
pub mod profile;
mod protocol;
mod retry;

pub use crypto::{DeviceIdentity, EpochKey};
pub use profile::{PairingGrantPackage, PairingRequest, PendingPairing, SyncProfile};
pub use protocol::{
    validate_vault_id, DeviceRecord, EncryptedObject, Manifest, ManifestDraft, PairingGrant,
    SignedManifest, SignedPairingGrant, SyncError, SyncResult, MAX_MANIFEST_OBJECTS,
    MAX_OBJECT_BYTES, MAX_OBJECT_JSON_BYTES, MAX_TRUSTED_DEVICES, PROTOCOL_VERSION,
};

#[cfg(test)]
mod tests;
