use crate::protocol::{
    canonical_manifest_bytes, canonical_pairing_bytes, device_digest, object_aad, object_digest,
    pairing_aad, DeviceRecord, EncryptedObject, Manifest, PairingGrant, SignedPairingGrant,
    SyncError, SyncResult, MAX_OBJECT_BYTES, PROTOCOL_VERSION,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as ExchangePublicKey, StaticSecret};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct EpochKey(Zeroizing<[u8; 32]>);

impl EpochKey {
    pub fn generate() -> SyncResult<Self> {
        let mut key = [0_u8; 32];
        getrandom::getrandom(&mut key).map_err(|_| SyncError::Randomness)?;
        Ok(Self(Zeroizing::new(key)))
    }

    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self(Zeroizing::new(key))
    }

    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.0)
    }

    pub fn encrypt(
        &self,
        vault_id: &str,
        epoch: u64,
        plaintext: &[u8],
    ) -> SyncResult<EncryptedObject> {
        crate::protocol::validate_vault_id(vault_id)?;
        if epoch == 0 || plaintext.is_empty() || plaintext.len() > MAX_OBJECT_BYTES {
            return Err(SyncError::InvalidObject);
        }
        let mut nonce = [0_u8; 24];
        getrandom::getrandom(&mut nonce).map_err(|_| SyncError::Randomness)?;
        let ciphertext = XChaCha20Poly1305::new(self.0.as_ref().into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &object_aad(vault_id, epoch),
                },
            )
            .map_err(|_| SyncError::AuthenticationFailed)?;
        let object_id = object_digest(vault_id, epoch, &nonce, &ciphertext);
        Ok(EncryptedObject {
            protocol_version: PROTOCOL_VERSION,
            vault_id: vault_id.into(),
            epoch,
            object_id,
            nonce,
            ciphertext,
        })
    }

    pub fn decrypt(&self, object: &EncryptedObject) -> SyncResult<Zeroizing<Vec<u8>>> {
        object.validate()?;
        let plaintext = XChaCha20Poly1305::new(self.0.as_ref().into())
            .decrypt(
                XNonce::from_slice(&object.nonce),
                Payload {
                    msg: &object.ciphertext,
                    aad: &object_aad(&object.vault_id, object.epoch),
                },
            )
            .map_err(|_| SyncError::AuthenticationFailed)?;
        Ok(Zeroizing::new(plaintext))
    }
}

pub struct DeviceIdentity {
    signing: SigningKey,
    exchange: StaticSecret,
}

impl DeviceIdentity {
    pub fn generate() -> SyncResult<Self> {
        let mut signing_secret = Zeroizing::new([0_u8; 32]);
        let mut exchange_secret = Zeroizing::new([0_u8; 32]);
        getrandom::getrandom(signing_secret.as_mut()).map_err(|_| SyncError::Randomness)?;
        getrandom::getrandom(exchange_secret.as_mut()).map_err(|_| SyncError::Randomness)?;
        Ok(Self {
            signing: SigningKey::from_bytes(&signing_secret),
            exchange: StaticSecret::from(*exchange_secret),
        })
    }

    /// Exports private signing and exchange keys for encrypted local
    /// persistence. Callers must keep the returned bytes protected.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 64]> {
        let mut bytes = Zeroizing::new([0_u8; 64]);
        bytes[..32].copy_from_slice(self.signing.as_bytes());
        bytes[32..].copy_from_slice(self.exchange.as_bytes());
        bytes
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> SyncResult<Self> {
        let bytes: &[u8; 64] = bytes.try_into().map_err(|_| SyncError::InvalidDevice)?;
        let signing_bytes: &[u8; 32] = bytes[..32].try_into().unwrap();
        let exchange_bytes: &[u8; 32] = bytes[32..].try_into().unwrap();
        Ok(Self {
            signing: SigningKey::from_bytes(signing_bytes),
            exchange: StaticSecret::from(*exchange_bytes),
        })
    }

    pub fn record(&self, label: impl Into<String>) -> SyncResult<DeviceRecord> {
        let public_key = self.signing.verifying_key().to_bytes();
        let exchange_public_key = ExchangePublicKey::from(&self.exchange).to_bytes();
        let device_id = device_digest(&public_key, &exchange_public_key);
        let record = DeviceRecord {
            device_id,
            label: label.into(),
            public_key,
            exchange_public_key,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn sign(&self, manifest: Manifest) -> SyncResult<crate::SignedManifest> {
        manifest.validate()?;
        let expected = self.record("signer")?.device_id;
        if manifest.device_id != expected {
            return Err(SyncError::DeviceMismatch);
        }
        let signature = self
            .signing
            .sign(&canonical_manifest_bytes(&manifest)?)
            .to_bytes()
            .to_vec();
        Ok(crate::SignedManifest {
            manifest,
            signature,
        })
    }

    pub fn grant_epoch_key(
        &self,
        vault_id: &str,
        epoch: u64,
        epoch_key: &EpochKey,
        recipient: DeviceRecord,
    ) -> SyncResult<SignedPairingGrant> {
        let authorizer = self.record("authorizer")?;
        self.grant_epoch_key_with_trust(vault_id, epoch, epoch_key, recipient, vec![authorizer])
    }

    pub fn grant_epoch_key_with_trust(
        &self,
        vault_id: &str,
        epoch: u64,
        epoch_key: &EpochKey,
        recipient: DeviceRecord,
        trusted_devices: Vec<DeviceRecord>,
    ) -> SyncResult<SignedPairingGrant> {
        self.grant_epoch_key_with_context(
            vault_id,
            epoch,
            epoch_key,
            recipient,
            trusted_devices,
            Vec::new(),
        )
    }

    pub fn grant_epoch_key_with_context(
        &self,
        vault_id: &str,
        epoch: u64,
        epoch_key: &EpochKey,
        recipient: DeviceRecord,
        mut trusted_devices: Vec<DeviceRecord>,
        mut heads: Vec<String>,
    ) -> SyncResult<SignedPairingGrant> {
        crate::protocol::validate_vault_id(vault_id)?;
        recipient.validate()?;
        if epoch == 0 {
            return Err(SyncError::InvalidPairingGrant);
        }
        let authorizer = self.record("authorizer")?;
        if authorizer.device_id == recipient.device_id {
            return Err(SyncError::InvalidPairingGrant);
        }
        if !trusted_devices
            .iter()
            .any(|device| device.device_id == authorizer.device_id)
        {
            trusted_devices.push(authorizer.clone());
        }
        trusted_devices.sort_by(|left, right| left.device_id.cmp(&right.device_id));
        trusted_devices.dedup_by(|left, right| left.device_id == right.device_id);
        heads.sort();
        heads.dedup();
        let shared = self
            .exchange
            .diffie_hellman(&ExchangePublicKey::from(recipient.exchange_public_key));
        let mut nonce = [0_u8; 24];
        getrandom::getrandom(&mut nonce).map_err(|_| SyncError::Randomness)?;
        let transport_key = pairing_transport_key(
            shared.as_bytes(),
            &nonce,
            vault_id,
            epoch,
            &authorizer.device_id,
            &recipient.device_id,
        )?;
        let aad = pairing_aad(vault_id, epoch, &authorizer.device_id, &recipient.device_id);
        let encrypted_epoch_key = XChaCha20Poly1305::new(transport_key.as_ref().into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: epoch_key.0.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| SyncError::AuthenticationFailed)?;
        let grant = PairingGrant {
            protocol_version: PROTOCOL_VERSION,
            vault_id: vault_id.into(),
            epoch,
            authorizing_device_id: authorizer.device_id,
            recipient,
            trusted_devices,
            heads,
            nonce,
            encrypted_epoch_key,
        };
        grant.validate()?;
        let signature = self
            .signing
            .sign(&canonical_pairing_bytes(&grant)?)
            .to_bytes()
            .to_vec();
        Ok(SignedPairingGrant { grant, signature })
    }

    pub fn accept_epoch_key(
        &self,
        signed: &SignedPairingGrant,
        authorizer: &DeviceRecord,
        confirmed_code: &str,
    ) -> SyncResult<EpochKey> {
        signed.verify(authorizer)?;
        let own = self.record("recipient")?;
        if signed.grant.recipient.device_id != own.device_id {
            return Err(SyncError::DeviceMismatch);
        }
        if signed.confirmation_code()?.as_bytes() != confirmed_code.trim().to_uppercase().as_bytes()
        {
            return Err(SyncError::PairingConfirmationMismatch);
        }
        let shared = self
            .exchange
            .diffie_hellman(&ExchangePublicKey::from(authorizer.exchange_public_key));
        let transport_key = pairing_transport_key(
            shared.as_bytes(),
            &signed.grant.nonce,
            &signed.grant.vault_id,
            signed.grant.epoch,
            &signed.grant.authorizing_device_id,
            &signed.grant.recipient.device_id,
        )?;
        let plaintext = Zeroizing::new(
            XChaCha20Poly1305::new(transport_key.as_ref().into())
                .decrypt(
                    XNonce::from_slice(&signed.grant.nonce),
                    Payload {
                        msg: &signed.grant.encrypted_epoch_key,
                        aad: &pairing_aad(
                            &signed.grant.vault_id,
                            signed.grant.epoch,
                            &signed.grant.authorizing_device_id,
                            &signed.grant.recipient.device_id,
                        ),
                    },
                )
                .map_err(|_| SyncError::AuthenticationFailed)?,
        );
        let key: [u8; 32] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| SyncError::InvalidPairingGrant)?;
        Ok(EpochKey::from_bytes(key))
    }
}

fn pairing_transport_key(
    shared: &[u8; 32],
    nonce: &[u8; 24],
    vault_id: &str,
    epoch: u64,
    authorizer: &str,
    recipient: &str,
) -> SyncResult<Zeroizing<[u8; 32]>> {
    if shared.iter().all(|byte| *byte == 0) {
        return Err(SyncError::InvalidPairingGrant);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(nonce), shared);
    let mut key = Zeroizing::new([0_u8; 32]);
    let mut info = b"foliora-pairing-transport-v1\0".to_vec();
    info.extend_from_slice(&pairing_aad(vault_id, epoch, authorizer, recipient));
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| SyncError::InvalidPairingGrant)?;
    Ok(key)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
