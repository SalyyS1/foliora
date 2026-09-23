use super::*;

fn vault_id() -> &'static str {
    "vault:0123456789abcdef"
}

#[test]
fn encrypted_objects_round_trip_and_bind_vault_epoch_and_ciphertext() {
    let key = EpochKey::from_bytes([7; 32]);
    let plaintext = br#"{"claim":"private value"}"#;
    let object = key.encrypt(vault_id(), 1, plaintext).unwrap();
    assert_ne!(object.ciphertext, plaintext);
    assert_eq!(key.decrypt(&object).unwrap().as_slice(), plaintext);

    let mut tampered = object.clone();
    *tampered.ciphertext.last_mut().unwrap() ^= 1;
    assert!(matches!(tampered.validate(), Err(SyncError::InvalidObject)));
    let mut wrong_epoch = object.clone();
    wrong_epoch.epoch = 2;
    assert!(matches!(
        wrong_epoch.validate(),
        Err(SyncError::InvalidObject)
    ));
    let other_key = EpochKey::from_bytes([8; 32]);
    assert!(matches!(
        other_key.decrypt(&object),
        Err(SyncError::AuthenticationFailed)
    ));

    let wire = serde_json::to_value(&object).unwrap();
    assert!(wire["ciphertext"].is_string());
    let restored: EncryptedObject = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(restored, object);

    let mut legacy_wire = wire;
    legacy_wire["ciphertext"] = serde_json::to_value(&object.ciphertext).unwrap();
    let legacy: EncryptedObject = serde_json::from_value(legacy_wire).unwrap();
    assert_eq!(legacy, object);

    let mut malformed = serde_json::to_value(&object).unwrap();
    malformed["ciphertext"] = serde_json::Value::String("not base64".into());
    assert!(serde_json::from_value::<EncryptedObject>(malformed).is_err());

    let maximum_base64_bytes = (MAX_OBJECT_BYTES + 16).div_ceil(3) * 4;
    assert!(maximum_base64_bytes + 1024 < MAX_OBJECT_JSON_BYTES);
}

#[test]
fn signed_manifest_is_canonical_and_detects_forgery() {
    let identity = DeviceIdentity::generate().unwrap();
    let device = identity.record("Laptop").unwrap();
    let key = EpochKey::from_bytes([9; 32]);
    let first = key.encrypt(vault_id(), 1, b"first").unwrap();
    let second = key.encrypt(vault_id(), 1, b"second").unwrap();
    let manifest = ManifestDraft {
        vault_id: vault_id().into(),
        epoch: 1,
        parents: vec![],
        object_ids: vec![second.object_id, first.object_id],
        tombstones: vec!["claim:removed".into(), "claim:removed".into()],
        device_id: device.device_id.clone(),
        sequence: 1,
    }
    .finalize()
    .unwrap();
    assert_eq!(manifest.object_ids.len(), 2);
    assert!(manifest.object_ids[0] < manifest.object_ids[1]);
    assert_eq!(manifest.tombstones, ["claim:removed"]);
    let signed = identity.sign(manifest).unwrap();
    signed.verify(&device).unwrap();

    let mut forged = signed.clone();
    forged.signature[0] ^= 1;
    assert!(matches!(
        forged.verify(&device),
        Err(SyncError::InvalidSignature)
    ));
    let attacker = DeviceIdentity::generate().unwrap();
    assert!(signed
        .verify(&attacker.record("Attacker").unwrap())
        .is_err());
}

#[test]
fn malformed_and_oversized_protocol_inputs_fail_closed() {
    let key = EpochKey::from_bytes([3; 32]);
    assert!(key.encrypt("not-a-vault", 1, b"x").is_err());
    assert!(key.encrypt(vault_id(), 0, b"x").is_err());
    assert!(key.encrypt(vault_id(), 1, &[]).is_err());
    assert!(key
        .encrypt(vault_id(), 1, &vec![0; MAX_OBJECT_BYTES + 1])
        .is_err());
    let identity = DeviceIdentity::generate().unwrap();
    let device = identity.record("Laptop").unwrap();
    assert!(ManifestDraft {
        vault_id: vault_id().into(),
        epoch: 1,
        parents: vec![],
        object_ids: vec![],
        tombstones: vec![],
        device_id: device.device_id,
        sequence: 0,
    }
    .finalize()
    .is_err());
}

#[test]
fn maximum_ciphertext_uses_bounded_base64_wire_shape() {
    let object = EpochKey::from_bytes([31; 32])
        .encrypt(vault_id(), 1, &vec![42; MAX_OBJECT_BYTES])
        .unwrap();
    let wire = serde_json::to_vec(&object).unwrap();

    assert!(wire.len() < MAX_OBJECT_JSON_BYTES);
    assert_eq!(
        serde_json::from_slice::<EncryptedObject>(&wire).unwrap(),
        object
    );
}

#[test]
fn trusted_pairing_transfers_only_the_confirmed_epoch_key() {
    let owner = DeviceIdentity::generate().unwrap();
    let recipient = DeviceIdentity::generate().unwrap();
    let owner_record = owner.record("Owner laptop").unwrap();
    let recipient_record = recipient.record("New phone").unwrap();
    let epoch_key = EpochKey::from_bytes([42; 32]);
    let grant = owner
        .grant_epoch_key(vault_id(), 7, &epoch_key, recipient_record)
        .unwrap();
    grant.verify(&owner_record).unwrap();
    let code = grant.confirmation_code().unwrap();
    assert_eq!(code.len(), 9);
    assert!(matches!(
        recipient.accept_epoch_key(&grant, &owner_record, "0000-0000"),
        Err(SyncError::PairingConfirmationMismatch)
    ));
    let accepted = recipient
        .accept_epoch_key(&grant, &owner_record, &code)
        .unwrap();
    let object = epoch_key.encrypt(vault_id(), 7, b"paired secret").unwrap();
    assert_eq!(
        accepted.decrypt(&object).unwrap().as_slice(),
        b"paired secret"
    );
}

#[test]
fn pairing_rejects_server_substitution_signature_tamper_and_wrong_recipient() {
    let owner = DeviceIdentity::generate().unwrap();
    let recipient = DeviceIdentity::generate().unwrap();
    let stranger = DeviceIdentity::generate().unwrap();
    let owner_record = owner.record("Owner").unwrap();
    let grant = owner
        .grant_epoch_key(
            vault_id(),
            1,
            &EpochKey::from_bytes([5; 32]),
            recipient.record("Phone").unwrap(),
        )
        .unwrap();
    let code = grant.confirmation_code().unwrap();
    assert!(matches!(
        stranger.accept_epoch_key(&grant, &owner_record, &code),
        Err(SyncError::DeviceMismatch)
    ));
    let mut tampered = grant.clone();
    tampered.grant.encrypted_epoch_key[0] ^= 1;
    assert!(matches!(
        recipient.accept_epoch_key(&tampered, &owner_record, &code),
        Err(SyncError::InvalidSignature)
    ));
    let fake_owner = DeviceIdentity::generate().unwrap().record("Fake").unwrap();
    assert!(grant.verify(&fake_owner).is_err());
}
