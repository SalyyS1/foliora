use crate::VaultError;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};

pub(crate) const ENVELOPE_VERSION: u16 = 1;
pub(crate) const MAGIC: &[u8; 8] = b"FOLIVLT1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfPolicy {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfPolicy {
    fn default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }
}

impl KdfPolicy {
    pub fn validate(self) -> Result<(), VaultError> {
        if !(8 * 1024..=256 * 1024).contains(&self.memory_kib)
            || !(1..=10).contains(&self.iterations)
            || !(1..=8).contains(&self.parallelism)
        {
            return Err(VaultError::UnsafeKdfParameters);
        }
        Ok(())
    }
}

pub(crate) struct Envelope {
    pub policy: KdfPolicy,
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

pub(crate) fn derive_key(
    passphrase: &str,
    salt: &[u8; 16],
    policy: KdfPolicy,
) -> Result<[u8; 32], VaultError> {
    if passphrase.is_empty() {
        return Err(VaultError::EmptyPassphrase);
    }
    policy.validate()?;
    let params = Params::new(
        policy.memory_kib,
        policy.iterations,
        policy.parallelism,
        Some(32),
    )
    .map_err(|_| VaultError::UnsafeKdfParameters)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|_| VaultError::AuthenticationFailed)?;
    Ok(key)
}

pub(crate) fn encrypt(
    plaintext: &[u8],
    key: &[u8; 32],
    salt: [u8; 16],
    policy: KdfPolicy,
) -> Result<Envelope, VaultError> {
    let mut nonce = [0_u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|_| VaultError::Randomness)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let aad = header_aad(policy, &salt);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;
    Ok(Envelope {
        policy,
        salt,
        nonce,
        ciphertext,
    })
}

pub(crate) fn decrypt(envelope: &Envelope, key: &[u8; 32]) -> Result<Vec<u8>, VaultError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let aad = header_aad(envelope.policy, &envelope.salt);
    cipher
        .decrypt(
            XNonce::from_slice(&envelope.nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)
}

pub(crate) fn header_aad(policy: KdfPolicy, salt: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(38);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&ENVELOPE_VERSION.to_le_bytes());
    out.extend_from_slice(&policy.memory_kib.to_le_bytes());
    out.extend_from_slice(&policy.iterations.to_le_bytes());
    out.extend_from_slice(&policy.parallelism.to_le_bytes());
    out.extend_from_slice(salt);
    out
}
