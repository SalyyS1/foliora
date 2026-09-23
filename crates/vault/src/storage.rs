use crate::{
    crypto::{Envelope, KdfPolicy, ENVELOPE_VERSION, MAGIC},
    VaultError,
};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const HEADER_LEN: usize = 8 + 2 + 4 + 4 + 4 + 16 + 24;

pub(crate) fn read_envelope(path: &Path) -> Result<Envelope, VaultError> {
    let bytes = fs::read(path)?;
    if bytes.len() < HEADER_LEN + 16 || &bytes[..8] != MAGIC {
        return Err(VaultError::InvalidEnvelope);
    }
    let version = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    if version != ENVELOPE_VERSION {
        return Err(VaultError::UnsupportedVersion(version));
    }
    let policy = KdfPolicy {
        memory_kib: u32::from_le_bytes(bytes[10..14].try_into().unwrap()),
        iterations: u32::from_le_bytes(bytes[14..18].try_into().unwrap()),
        parallelism: u32::from_le_bytes(bytes[18..22].try_into().unwrap()),
    };
    policy.validate()?;
    let salt = bytes[22..38].try_into().unwrap();
    let nonce = bytes[38..62].try_into().unwrap();
    Ok(Envelope {
        policy,
        salt,
        nonce,
        ciphertext: bytes[HEADER_LEN..].to_vec(),
    })
}

pub(crate) fn write_envelope_recoverable(
    path: &Path,
    envelope: &Envelope,
) -> Result<(), VaultError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension("vault.tmp");
    let backup = backup_path(path);
    if temp.exists() {
        fs::remove_file(&temp)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    file.write_all(MAGIC)?;
    file.write_all(&ENVELOPE_VERSION.to_le_bytes())?;
    file.write_all(&envelope.policy.memory_kib.to_le_bytes())?;
    file.write_all(&envelope.policy.iterations.to_le_bytes())?;
    file.write_all(&envelope.policy.parallelism.to_le_bytes())?;
    file.write_all(&envelope.salt)?;
    file.write_all(&envelope.nonce)?;
    file.write_all(&envelope.ciphertext)?;
    file.sync_all()?;
    drop(file);

    if path.exists() {
        if backup.exists() {
            fs::remove_file(&backup)?;
        }
        fs::rename(path, &backup)?;
    }
    if let Err(error) = fs::rename(&temp, path) {
        if backup.exists() && !path.exists() {
            let _ = fs::rename(&backup, path);
        }
        return Err(VaultError::Io(error));
    }
    Ok(())
}

pub(crate) fn backup_path(path: &Path) -> PathBuf {
    path.with_extension("vault.bak")
}

pub(crate) fn copy_new_synced(source: &Path, destination: &Path) -> Result<u64, VaultError> {
    if destination.exists() {
        return Err(VaultError::AlreadyExists);
    }
    if source == destination {
        return Err(VaultError::AlreadyExists);
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = fs::read(source)?;
    write_new_synced(destination, &bytes)
}

pub(crate) fn write_new_synced(destination: &Path, bytes: &[u8]) -> Result<u64, VaultError> {
    if destination.exists() {
        return Err(VaultError::AlreadyExists);
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    if let Err(error) = output.write_all(bytes).and_then(|()| output.sync_all()) {
        drop(output);
        let _ = fs::remove_file(destination);
        return Err(VaultError::Io(error));
    }
    Ok(bytes.len() as u64)
}
