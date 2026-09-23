//! Optional OS-backed storage for a vault passphrase.
//!
//! The keychain is convenience only. The encrypted vault remains the source
//! of truth, and callers must make the opt-in explicit. No keychain value is
//! ever serialized into a Tauri response.

use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroizing;

const SERVICE: &str = "app.foliora.desktop.vault";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeychainError {
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    Unsupported,
    Unavailable,
    EmptyPassphrase,
}

impl std::fmt::Display for KeychainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
            Self::Unsupported => write!(f, "OS keychain is not supported on this platform"),
            Self::Unavailable => write!(f, "could not access the OS keychain"),
            Self::EmptyPassphrase => write!(f, "vault passphrase must not be empty"),
        }
    }
}

impl std::error::Error for KeychainError {}

/// Returns a non-secret, versioned keychain account derived from the vault path.
/// The path itself is never used as a credential-store user name.
pub(crate) fn account_for_path(path: &Path) -> String {
    let mut normalized = path.to_string_lossy().replace('\\', "/");
    #[cfg(windows)]
    {
        normalized = normalized.to_ascii_lowercase();
    }
    let digest = Sha256::digest(normalized.as_bytes());
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("vault-v1:{hex}")
}

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
mod native {
    use super::{account_for_path, KeychainError, SERVICE};
    use std::path::Path;
    use zeroize::Zeroizing;

    fn entry(path: &Path) -> Result<keyring::Entry, KeychainError> {
        keyring::Entry::new(SERVICE, &account_for_path(path))
            .map_err(|_| KeychainError::Unavailable)
    }

    pub(super) fn has(path: &Path) -> Result<bool, KeychainError> {
        match entry(path)?.get_password() {
            Ok(_) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(_) => Err(KeychainError::Unavailable),
        }
    }

    pub(super) fn load(path: &Path) -> Result<Zeroizing<String>, KeychainError> {
        entry(path)?
            .get_password()
            .map(Zeroizing::new)
            .map_err(|error| match error {
                keyring::Error::NoEntry => KeychainError::Unavailable,
                _ => KeychainError::Unavailable,
            })
    }

    pub(super) fn save(path: &Path, passphrase: &str) -> Result<(), KeychainError> {
        if passphrase.is_empty() {
            return Err(KeychainError::EmptyPassphrase);
        }
        entry(path)?
            .set_password(passphrase)
            .map_err(|_| KeychainError::Unavailable)
    }

    pub(super) fn forget(path: &Path) -> Result<(), KeychainError> {
        match entry(path)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(KeychainError::Unavailable),
        }
    }
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
mod native {
    use super::KeychainError;
    use std::path::Path;
    use zeroize::Zeroizing;

    pub(super) fn has(_: &Path) -> Result<bool, KeychainError> {
        Err(KeychainError::Unsupported)
    }

    pub(super) fn load(_: &Path) -> Result<Zeroizing<String>, KeychainError> {
        Err(KeychainError::Unsupported)
    }

    pub(super) fn save(_: &Path, _: &str) -> Result<(), KeychainError> {
        Err(KeychainError::Unsupported)
    }

    pub(super) fn forget(_: &Path) -> Result<(), KeychainError> {
        Err(KeychainError::Unsupported)
    }
}

pub(crate) fn has(path: &Path) -> Result<bool, KeychainError> {
    native::has(path)
}

pub(crate) fn load(path: &Path) -> Result<Zeroizing<String>, KeychainError> {
    native::load(path)
}

pub(crate) fn save(path: &Path, passphrase: &str) -> Result<(), KeychainError> {
    native::save(path, passphrase)
}

pub(crate) fn forget(path: &Path) -> Result<(), KeychainError> {
    native::forget(path)
}

#[cfg(test)]
mod tests {
    use super::account_for_path;
    use std::path::Path;

    #[test]
    fn account_is_stable_and_does_not_include_path() {
        let path = Path::new(r"C:\Users\Alice\foliora.vault");
        let account = account_for_path(path);
        assert_eq!(account.len(), "vault-v1:".len() + 64);
        assert!(!account.contains("Alice"));
        assert_eq!(account, account_for_path(path));
    }

    #[test]
    fn different_paths_have_different_accounts() {
        assert_ne!(
            account_for_path(Path::new(r"C:\vaults\one.vault")),
            account_for_path(Path::new(r"C:\vaults\two.vault")),
        );
    }
}
