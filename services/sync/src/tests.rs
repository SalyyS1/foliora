use super::*;
use foliora_sync::{DeviceIdentity, EpochKey, ManifestDraft};

const VAULT: &str = "vault:0123456789abcdef";

fn signed(
    identity: &DeviceIdentity,
    device: &DeviceRecord,
    epoch: u64,
    sequence: u64,
    parents: Vec<String>,
    objects: Vec<String>,
) -> SignedManifest {
    identity
        .sign(
            ManifestDraft {
                vault_id: VAULT.into(),
                epoch,
                parents,
                object_ids: objects,
                tombstones: vec![],
                device_id: device.device_id.clone(),
                sequence,
            }
            .finalize()
            .unwrap(),
        )
        .unwrap()
}

#[test]
fn upload_retry_and_manifest_commit_are_idempotent_and_atomic() {
    let identity = DeviceIdentity::generate().unwrap();
    let device = identity.record("Laptop").unwrap();
    let key = EpochKey::from_bytes([1; 32]);
    let object = key.encrypt(VAULT, 1, b"opaque payload").unwrap();
    let mut store = OpaqueSyncStore::default();
    store
        .create_vault(VAULT.into(), device.clone(), 1024)
        .unwrap();
    assert_eq!(
        store
            .upload_object(&device.device_id, object.clone())
            .unwrap(),
        StoreOutcome::Inserted
    );
    assert_eq!(
        store.status(VAULT, &device.device_id).unwrap().heads,
        Vec::<String>::new()
    );
    assert_eq!(
        store
            .upload_object(&device.device_id, object.clone())
            .unwrap(),
        StoreOutcome::AlreadyPresent
    );

    let missing = key.encrypt(VAULT, 1, b"not uploaded").unwrap();
    let rejected = signed(&identity, &device, 1, 1, vec![], vec![missing.object_id]);
    assert!(matches!(
        store.commit_manifest(rejected),
        Err(ServiceError::MissingObject(_))
    ));
    assert!(store
        .status(VAULT, &device.device_id)
        .unwrap()
        .heads
        .is_empty());

    let manifest = signed(
        &identity,
        &device,
        1,
        1,
        vec![],
        vec![object.object_id.clone()],
    );
    assert_eq!(
        store.commit_manifest(manifest.clone()).unwrap(),
        StoreOutcome::Inserted
    );
    assert_eq!(
        store.commit_manifest(manifest.clone()).unwrap(),
        StoreOutcome::AlreadyPresent
    );
    assert_eq!(
        store
            .object(VAULT, &device.device_id, &object.object_id)
            .unwrap(),
        Some(&object)
    );
    assert!(store
        .manifest(VAULT, &device.device_id, &manifest.manifest.revision_id)
        .unwrap()
        .is_some());
}

#[test]
fn concurrent_offline_revisions_form_heads_then_merge_explicitly() {
    let first_identity = DeviceIdentity::generate().unwrap();
    let second_identity = DeviceIdentity::generate().unwrap();
    let first = first_identity.record("Laptop").unwrap();
    let second = second_identity.record("Phone").unwrap();
    let key = EpochKey::from_bytes([2; 32]);
    let root_object = key.encrypt(VAULT, 1, b"root").unwrap();
    let left_object = key.encrypt(VAULT, 1, b"left edit").unwrap();
    let right_object = key.encrypt(VAULT, 1, b"right edit").unwrap();
    let merge_object = key.encrypt(VAULT, 1, b"explicit conflict result").unwrap();
    let mut store = OpaqueSyncStore::default();
    store
        .create_vault(VAULT.into(), first.clone(), 4096)
        .unwrap();
    let grant = first_identity
        .grant_epoch_key(VAULT, 1, &key, second.clone())
        .unwrap();
    store.pair_device(grant).unwrap();
    for object in [&root_object, &left_object, &right_object, &merge_object] {
        store
            .upload_object(&first.device_id, object.clone())
            .unwrap();
    }
    let root = signed(
        &first_identity,
        &first,
        1,
        1,
        vec![],
        vec![root_object.object_id],
    );
    store.commit_manifest(root.clone()).unwrap();
    let left = signed(
        &first_identity,
        &first,
        1,
        2,
        vec![root.manifest.revision_id.clone()],
        vec![left_object.object_id],
    );
    let right = signed(
        &second_identity,
        &second,
        1,
        1,
        vec![root.manifest.revision_id],
        vec![right_object.object_id],
    );
    store.commit_manifest(left.clone()).unwrap();
    store.commit_manifest(right.clone()).unwrap();
    let fork_heads = store.status(VAULT, &first.device_id).unwrap().heads;
    assert_eq!(fork_heads.len(), 2);

    let merge = signed(
        &first_identity,
        &first,
        1,
        3,
        fork_heads,
        vec![merge_object.object_id],
    );
    store.commit_manifest(merge.clone()).unwrap();
    assert_eq!(
        store.status(VAULT, &first.device_id).unwrap().heads,
        [merge.manifest.revision_id]
    );
}

#[test]
fn revoke_rotates_epoch_and_blocks_revoked_or_old_epoch_writes() {
    let owner_identity = DeviceIdentity::generate().unwrap();
    let lost_identity = DeviceIdentity::generate().unwrap();
    let owner = owner_identity.record("Owner").unwrap();
    let lost = lost_identity.record("Lost phone").unwrap();
    let old_key = EpochKey::from_bytes([3; 32]);
    let new_key = EpochKey::from_bytes([4; 32]);
    let mut store = OpaqueSyncStore::default();
    store
        .create_vault(VAULT.into(), owner.clone(), 1024)
        .unwrap();
    let grant = owner_identity
        .grant_epoch_key(VAULT, 1, &old_key, lost.clone())
        .unwrap();
    store.pair_device(grant).unwrap();
    assert_eq!(
        store
            .revoke_device(VAULT, &owner.device_id, &lost.device_id)
            .unwrap(),
        2
    );
    assert!(matches!(
        store.revoke_device(VAULT, &owner.device_id, &lost.device_id),
        Err(ServiceError::DeviceRevoked)
    ));
    assert_eq!(store.status(VAULT, &owner.device_id).unwrap().epoch, 2);
    assert!(matches!(
        store.upload_object(
            &lost.device_id,
            new_key.encrypt(VAULT, 2, b"revoked write").unwrap()
        ),
        Err(ServiceError::DeviceRevoked)
    ));
    assert!(matches!(
        store.upload_object(
            &owner.device_id,
            old_key.encrypt(VAULT, 1, b"stale epoch").unwrap()
        ),
        Err(ServiceError::EpochMismatch)
    ));
    assert!(store
        .upload_object(
            &owner.device_id,
            new_key.encrypt(VAULT, 2, b"future-safe write").unwrap()
        )
        .is_ok());
}

#[test]
fn quota_and_sequence_replay_fail_without_partial_commit() {
    let identity = DeviceIdentity::generate().unwrap();
    let device = identity.record("Laptop").unwrap();
    let key = EpochKey::from_bytes([5; 32]);
    let mut store = OpaqueSyncStore::default();
    store
        .create_vault(VAULT.into(), device.clone(), 20)
        .unwrap();
    let too_large = key.encrypt(VAULT, 1, b"five bytes").unwrap();
    assert!(matches!(
        store.upload_object(&device.device_id, too_large),
        Err(ServiceError::QuotaExceeded)
    ));

    let mut replay_store = OpaqueSyncStore::default();
    replay_store
        .create_vault(VAULT.into(), device.clone(), 1024)
        .unwrap();
    let first_object = key.encrypt(VAULT, 1, b"first").unwrap();
    let replay_object = key.encrypt(VAULT, 1, b"replay").unwrap();
    replay_store
        .upload_object(&device.device_id, first_object.clone())
        .unwrap();
    replay_store
        .upload_object(&device.device_id, replay_object.clone())
        .unwrap();
    let first = signed(
        &identity,
        &device,
        1,
        1,
        vec![],
        vec![first_object.object_id],
    );
    replay_store.commit_manifest(first.clone()).unwrap();
    let second_root = signed(
        &identity,
        &device,
        1,
        2,
        vec![],
        vec![replay_object.object_id.clone()],
    );
    assert!(matches!(
        replay_store.commit_manifest(second_root),
        Err(ServiceError::RootAlreadyExists)
    ));
    let replay = signed(
        &identity,
        &device,
        1,
        1,
        vec![first.manifest.revision_id],
        vec![replay_object.object_id],
    );
    assert!(matches!(
        replay_store.commit_manifest(replay),
        Err(ServiceError::SequenceReplay)
    ));
    assert_eq!(
        replay_store
            .status(VAULT, &device.device_id)
            .unwrap()
            .heads
            .len(),
        1
    );
}

#[test]
fn service_cannot_forge_or_mutate_a_device_pairing_grant() {
    let owner = DeviceIdentity::generate().unwrap();
    let recipient = DeviceIdentity::generate().unwrap();
    let owner_record = owner.record("Owner").unwrap();
    let recipient_record = recipient.record("Phone").unwrap();
    let key = EpochKey::from_bytes([6; 32]);
    let mut store = OpaqueSyncStore::default();
    store
        .create_vault(VAULT.into(), owner_record.clone(), 1024)
        .unwrap();
    let grant = owner
        .grant_epoch_key(VAULT, 1, &key, recipient_record)
        .unwrap();
    let mut tampered = grant.clone();
    tampered.grant.encrypted_epoch_key[0] ^= 1;
    assert!(matches!(
        store.pair_device(tampered),
        Err(ServiceError::Protocol(
            foliora_sync::SyncError::InvalidSignature
        ))
    ));
    assert_eq!(
        store
            .status(VAULT, &owner_record.device_id)
            .unwrap()
            .active_devices,
        1
    );
    store.pair_device(grant).unwrap();
    assert_eq!(
        store
            .status(VAULT, &owner_record.device_id)
            .unwrap()
            .active_devices,
        2
    );
}

#[test]
fn pairing_expiry_tolerates_bounded_clock_skew_without_extending_server_ttl() {
    let now = 1_700_000_000;
    let server_limit = now + crate::MAX_PAIRING_LIFETIME_SECONDS;
    let skewed_request = server_limit + crate::MAX_PAIRING_CLOCK_SKEW_SECONDS;

    assert_eq!(
        crate::normalize_pairing_expiry_at(skewed_request, now).unwrap(),
        server_limit
    );
    assert_eq!(
        crate::normalize_pairing_expiry_at(now + 1, now).unwrap(),
        now + 1
    );
    assert!(crate::normalize_pairing_expiry_at(now, now).is_err());
    assert!(crate::normalize_pairing_expiry_at(skewed_request + 1, now).is_err());
    assert!(crate::normalize_pairing_expiry_at(u64::MAX, u64::MAX - 1).is_err());
}

#[test]
fn persistent_storage_dimensions_are_bounded_and_rejections_are_atomic() {
    let identity = DeviceIdentity::generate().unwrap();
    let device = identity.record("Bounded owner").unwrap();
    let key = EpochKey::from_bytes([44; 32]);
    let mut store = OpaqueSyncStore::with_storage_limits(StorageLimits {
        max_objects_per_vault: 1,
        max_manifests_per_vault: 1,
        max_manifest_bytes_per_vault: i64::MAX as u64,
    })
    .unwrap();
    store
        .create_vault(VAULT.into(), device.clone(), 1024)
        .unwrap();
    let first_object = key.encrypt(VAULT, 1, b"first bounded object").unwrap();
    let second_object = key.encrypt(VAULT, 1, b"second bounded object").unwrap();
    store
        .upload_object(&device.device_id, first_object.clone())
        .unwrap();
    assert!(matches!(
        store.upload_object(&device.device_id, second_object),
        Err(ServiceError::StorageMetadataExceeded)
    ));
    let root = signed(
        &identity,
        &device,
        1,
        1,
        vec![],
        vec![first_object.object_id.clone()],
    );
    store.commit_manifest(root.clone()).unwrap();
    let next = signed(
        &identity,
        &device,
        1,
        2,
        vec![root.manifest.revision_id.clone()],
        vec![first_object.object_id],
    );
    assert!(matches!(
        store.commit_manifest(next),
        Err(ServiceError::StorageMetadataExceeded)
    ));
    let status = store.status(VAULT, &device.device_id).unwrap();
    assert_eq!(status.object_count, 1);
    assert_eq!(status.manifest_count, 1);
    assert!(status.manifest_bytes > 0);
    assert_eq!(status.heads, vec![root.manifest.revision_id]);
}

#[test]
fn manifest_byte_limit_rejects_before_history_or_sequence_changes() {
    let identity = DeviceIdentity::generate().unwrap();
    let device = identity.record("Byte bounded owner").unwrap();
    let key = EpochKey::from_bytes([45; 32]);
    let mut store = OpaqueSyncStore::with_storage_limits(StorageLimits {
        max_objects_per_vault: 1,
        max_manifests_per_vault: 1,
        max_manifest_bytes_per_vault: 1,
    })
    .unwrap();
    store
        .create_vault(VAULT.into(), device.clone(), 1024)
        .unwrap();
    let object = key.encrypt(VAULT, 1, b"bounded bytes").unwrap();
    store
        .upload_object(&device.device_id, object.clone())
        .unwrap();
    let root = signed(&identity, &device, 1, 1, vec![], vec![object.object_id]);
    assert!(matches!(
        store.commit_manifest(root),
        Err(ServiceError::StorageMetadataExceeded)
    ));
    let status = store.status(VAULT, &device.device_id).unwrap();
    assert_eq!(status.manifest_count, 0);
    assert_eq!(status.manifest_bytes, 0);
    assert!(status.heads.is_empty());
}
