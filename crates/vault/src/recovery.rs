use crate::{storage::write_new_synced, VaultError};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"FOLIRCV1";
const KIT_SALT_LEN: usize = 16;
const VAULT_SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const WRAPPED_KEY_LEN: usize = 32 + 16;
const KIT_LEN: usize = MAGIC.len() + VAULT_SALT_LEN + KIT_SALT_LEN + NONCE_LEN + WRAPPED_KEY_LEN;
const DOMAIN: &[u8] = b"foliora-recovery-wrap-v1";

pub(crate) fn create(
    destination: &Path,
    vault_salt: &[u8; 16],
    vault_key: &[u8; 32],
) -> Result<(u64, Zeroizing<String>), VaultError> {
    let mut recovery_secret = Zeroizing::new([0_u8; 32]);
    let mut kit_salt = [0_u8; KIT_SALT_LEN];
    let mut nonce = [0_u8; NONCE_LEN];
    getrandom::getrandom(recovery_secret.as_mut()).map_err(|_| VaultError::Randomness)?;
    getrandom::getrandom(&mut kit_salt).map_err(|_| VaultError::Randomness)?;
    getrandom::getrandom(&mut nonce).map_err(|_| VaultError::Randomness)?;
    let wrapping_key = derive_wrapping_key(&recovery_secret, &kit_salt);
    let aad = aad(vault_salt, &kit_salt);
    let wrapped = XChaCha20Poly1305::new(wrapping_key.as_ref().into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: vault_key,
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let mut bytes = Vec::with_capacity(KIT_LEN);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(vault_salt);
    bytes.extend_from_slice(&kit_salt);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&wrapped);
    let written = write_new_synced(destination, &bytes)?;
    let code = Zeroizing::new(format_code(&recovery_secret));
    Ok((written, code))
}

pub(crate) fn recover_key(
    kit_path: &Path,
    expected_vault_salt: &[u8; 16],
    code: &str,
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let bytes = std::fs::read(kit_path)?;
    if bytes.len() != KIT_LEN || &bytes[..MAGIC.len()] != MAGIC {
        return Err(VaultError::InvalidRecoveryKit);
    }
    let vault_salt: [u8; 16] = bytes[8..24].try_into().unwrap();
    if &vault_salt != expected_vault_salt {
        return Err(VaultError::RecoveryKitMismatch);
    }
    let kit_salt: [u8; 16] = bytes[24..40].try_into().unwrap();
    let nonce: [u8; 24] = bytes[40..64].try_into().unwrap();
    let recovery_secret = parse_code(code)?;
    let wrapping_key = derive_wrapping_key(&recovery_secret, &kit_salt);
    let aad = aad(&vault_salt, &kit_salt);
    let mut plaintext = XChaCha20Poly1305::new(wrapping_key.as_ref().into())
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &bytes[64..],
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;
    if plaintext.len() != 32 {
        plaintext.zeroize();
        return Err(VaultError::InvalidRecoveryKit);
    }
    let key: [u8; 32] = plaintext.as_slice().try_into().unwrap();
    plaintext.zeroize();
    Ok(Zeroizing::new(key))
}

fn derive_wrapping_key(secret: &[u8; 32], salt: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(salt);
    hasher.update(secret);
    Zeroizing::new(hasher.finalize().into())
}

fn aad(vault_salt: &[u8; 16], kit_salt: &[u8; 16]) -> Vec<u8> {
    [MAGIC.as_slice(), vault_salt, kit_salt].concat()
}

fn format_code(secret: &[u8; 32]) -> String {
    let hex: String = secret.iter().map(|byte| format!("{byte:02X}")).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

fn parse_code(code: &str) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let compact: Zeroizing<String> = Zeroizing::new(
        code.chars()
            .filter(|character| !character.is_ascii_whitespace() && *character != '-')
            .collect(),
    );
    if compact.len() != 64 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(VaultError::InvalidRecoveryCode);
    }
    let mut secret = Zeroizing::new([0_u8; 32]);
    for (index, byte) in secret.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16)
            .map_err(|_| VaultError::InvalidRecoveryCode)?;
    }
    Ok(secret)
}
