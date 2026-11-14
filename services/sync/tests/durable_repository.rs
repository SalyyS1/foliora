use bytes::Bytes;
use foliora_sync::{DeviceIdentity, EncryptedObject, EpochKey, ManifestDraft, SignedManifest};
use foliora_sync_service::{
    durable::DurableRepository, repository::SyncRepository, StorageLimits, StoreOutcome,
};
use object_store::{
    aws::AmazonS3Builder, path::Path, ObjectStore, ObjectStoreExt, PutMode, PutOptions,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupRestoreFixture {
    vault_id: String,
    device_token: String,
    object: EncryptedObject,
    manifest: SignedManifest,
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and S3-compatible services"]
async fn encrypted_object_and_manifest_survive_repository_restart() {
    let database_url = required("DATABASE_URL");
    let objects = object_store();
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let vault_id = format!("vault:integration-{suffix}");
    let token = format!("integration-device-token-{suffix}-long-enough");
    let token_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    let identity = DeviceIdentity::generate().expect("identity");
    let device = identity.record("Integration test").expect("device");
    let recipient_identity = DeviceIdentity::generate().expect("recipient identity");
    let recipient = recipient_identity
        .record("Integration recipient")
        .expect("recipient device");
    let recipient_token = format!("integration-recipient-token-{suffix}-long-enough");
    let recipient_token_hash: [u8; 32] = Sha256::digest(recipient_token.as_bytes()).into();
    let locked_identity = DeviceIdentity::generate().expect("locked recipient identity");
    let locked_recipient = locked_identity
        .record("Locked integration recipient")
        .expect("locked recipient device");
    let locked_token = format!("integration-locked-token-{suffix}-long-enough");
    let locked_token_hash: [u8; 32] = Sha256::digest(locked_token.as_bytes()).into();
    let boundary_identity = DeviceIdentity::generate().expect("boundary recipient identity");
    let boundary_recipient = boundary_identity
        .record("Boundary integration recipient")
        .expect("boundary recipient device");
    let boundary_token = format!("integration-boundary-token-{suffix}-long-enough");
    let boundary_token_hash: [u8; 32] = Sha256::digest(boundary_token.as_bytes()).into();
    let key = EpochKey::from_bytes([73; 32]);

    let first = DurableRepository::connect(&database_url, objects.clone())
        .await
        .expect("first repository");
    let fault_injection = sqlx::PgPool::connect(&database_url)
        .await
        .expect("disposable database fault-injection connection");
    first
        .create_vault(vault_id.clone(), device.clone(), 1_048_576, token_hash)
        .await
        .expect("create vault");
    let principal = first.authenticate(token_hash).await.expect("authenticate");
    let object = key
        .encrypt(&vault_id, 1, b"durable opaque integration payload")
        .expect("encrypt");
    let legacy_object = serde_json::to_vec(&serde_json::json!({
        "protocolVersion": object.protocol_version,
        "vaultId": object.vault_id,
        "epoch": object.epoch,
        "objectId": object.object_id,
        "nonce": object.nonce,
        "ciphertext": object.ciphertext,
    }))
    .expect("serialize legacy byte-array object");
    objects
        .put_opts(
            &Path::from(durable_storage_key(&vault_id, &object.object_id)),
            Bytes::from(legacy_object).into(),
            PutOptions {
                mode: PutMode::Create,
                ..Default::default()
            },
        )
        .await
        .expect("seed interrupted legacy object upload");
    assert_eq!(
        first
            .upload_object(&principal, object.clone())
            .await
            .expect("upload"),
        StoreOutcome::Inserted
    );
    let signed = identity
        .sign(
            ManifestDraft {
                vault_id: vault_id.clone(),
                epoch: 1,
                parents: vec![],
                object_ids: vec![object.object_id.clone()],
                tombstones: vec![],
                device_id: device.device_id.clone(),
                sequence: 1,
            }
            .finalize()
            .expect("manifest"),
        )
        .expect("signature");
    // Model a crash after GC deleted bytes but before its SQL transaction
    // committed: the durable mark remains while the object is absent in S3.
    sqlx::query("UPDATE objects SET lifecycle_state='deleting', deletion_marked_at=now() WHERE vault_id=$1 AND object_id=$2")
        .bind(&vault_id)
        .bind(&object.object_id)
        .execute(&fault_injection)
        .await
        .expect("seed interrupted GC state");
    objects
        .delete(&stored_path(&fault_injection, &vault_id, &object.object_id).await)
        .await
        .expect("simulate deleted staged bytes");
    assert!(first.verify_cross_store_integrity().await.is_err());
    assert!(matches!(
        first.commit_manifest(&principal, signed.clone()).await,
        Err(foliora_sync_service::repository::RepositoryError::Service(
            foliora_sync_service::ServiceError::MissingObject(_)
        ))
    ));
    assert_eq!(first.status(&principal).await.unwrap().manifest_count, 0);
    assert_eq!(first.status(&principal).await.unwrap().object_count, 1);
    first
        .upload_object(&principal, object.clone())
        .await
        .expect("reupload repairs bytes before reactivating the staged row");
    first
        .verify_cross_store_integrity()
        .await
        .expect("repaired staged integrity");
    // Complete a delayed remote DELETE only after repair and manifest commit.
    // It must affect the retired generation, never the new committed payload.
    let retired_path = stored_path(&fault_injection, &vault_id, &object.object_id).await;
    sqlx::query("UPDATE objects SET lifecycle_state='deleting', deletion_marked_at=now() WHERE vault_id=$1 AND object_id=$2")
        .bind(&vault_id).bind(&object.object_id)
        .execute(&fault_injection).await.unwrap();
    first
        .upload_object(&principal, object.clone())
        .await
        .unwrap();
    assert_ne!(
        retired_path,
        stored_path(&fault_injection, &vault_id, &object.object_id).await
    );
    first
        .commit_manifest(&principal, signed.clone())
        .await
        .expect("commit manifest");
    objects
        .delete(&retired_path)
        .await
        .expect("complete delayed DELETE after commit");
    assert_eq!(
        first.object(&principal, &object.object_id).await.unwrap(),
        Some(object.clone())
    );
    objects
        .delete(&stored_path(&fault_injection, &vault_id, &object.object_id).await)
        .await
        .expect("simulate missing object-store payload");
    assert_eq!(
        first
            .upload_object(&principal, object.clone())
            .await
            .expect("repair missing immutable payload"),
        StoreOutcome::AlreadyPresent
    );
    // Repair an interrupted legacy-to-canonical rewrite (physical digest no
    // longer agrees with the legacy digest retained by a rolled-back SQL tx).
    sqlx::query("UPDATE objects SET payload_sha256=$3 WHERE vault_id=$1 AND object_id=$2")
        .bind(&vault_id)
        .bind(&object.object_id)
        .bind(vec![0_u8; 32])
        .execute(&fault_injection)
        .await
        .expect("seed stale physical digest");
    assert!(first.verify_cross_store_integrity().await.is_err());
    first
        .upload_object(&principal, object.clone())
        .await
        .expect("reconcile stale physical digest");
    first
        .verify_cross_store_integrity()
        .await
        .expect("full cross-store integrity after repair");
    let staged_object = key
        .encrypt(&vault_id, 1, b"abandoned staged payload")
        .expect("encrypt staged payload");
    first
        .upload_object(&principal, staged_object.clone())
        .await
        .expect("upload staged object");
    assert_eq!(first.status(&principal).await.unwrap().object_count, 2);
    // Do not depend on subsecond wall-clock timing or scheduling sleeps.
    sqlx::query(
        "UPDATE objects SET created_at=now()-interval '2 days' WHERE vault_id=$1 AND object_id=$2",
    )
    .bind(&vault_id)
    .bind(&staged_object.object_id)
    .execute(&fault_injection)
    .await
    .expect("age only the abandoned fixture");
    let gc = first
        .garbage_collect_orphans(Duration::from_secs(86_400))
        .await
        .expect("reclaim abandoned staged object");
    assert!(gc.staged_marked >= 1);
    assert!(gc.staged_reclaimed >= 1);
    assert_eq!(first.status(&principal).await.unwrap().object_count, 1);
    assert_eq!(
        first
            .object(&principal, &staged_object.object_id)
            .await
            .expect("read reclaimed object"),
        None
    );
    // A new worker must also finish a persisted deletion whose S3 side already
    // succeeded. Missing bytes are idempotent success, and counters decrement once.
    first
        .upload_object(&principal, staged_object.clone())
        .await
        .unwrap();
    sqlx::query("UPDATE objects SET lifecycle_state='deleting', deletion_marked_at=now() WHERE vault_id=$1 AND object_id=$2")
        .bind(&vault_id).bind(&staged_object.object_id)
        .execute(&fault_injection).await.unwrap();
    objects
        .delete(&stored_path(&fault_injection, &vault_id, &staged_object.object_id).await)
        .await
        .unwrap();
    let recovery_worker = DurableRepository::connect(&database_url, objects.clone())
        .await
        .unwrap();
    let recovered = recovery_worker
        .garbage_collect_orphans(Duration::from_secs(86_400))
        .await
        .unwrap();
    assert!(recovered.staged_reclaimed >= 1);
    assert_eq!(first.status(&principal).await.unwrap().object_count, 1);
    let repeated = recovery_worker
        .garbage_collect_orphans(Duration::from_secs(86_400))
        .await
        .unwrap();
    assert_eq!(repeated.staged_reclaimed, 0);
    assert_eq!(
        first.status(&principal).await.unwrap().used_bytes,
        object.ciphertext.len() as u64
    );
    drop(recovery_worker);

    let read_only = DurableRepository::connect_for_verification(&database_url, objects.clone())
        .await
        .unwrap();
    let scrub = read_only
        .verify_cross_store_integrity()
        .await
        .expect("read-only maintenance scrub");
    assert!(scrub.metadata_objects >= 1);
    assert!(read_only
        .create_vault(
            format!("vault:forbidden-{suffix}"),
            device.clone(),
            1_048_576,
            [0; 32]
        )
        .await
        .is_err());
    drop(read_only);
    let pairing = identity
        .grant_epoch_key(&vault_id, 1, &key, recipient.clone())
        .expect("pairing grant");
    let confirmation_hash: [u8; 32] =
        Sha256::digest(pairing.confirmation_code().unwrap().as_bytes()).into();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    first
        .pair_device(&principal, pairing.clone(), recipient_token_hash, now + 600)
        .await
        .expect("register pending pairing");
    let locked_pairing = identity
        .grant_epoch_key(&vault_id, 1, &key, locked_recipient)
        .expect("locked pairing grant");
    let locked_confirmation_hash: [u8; 32] =
        Sha256::digest(locked_pairing.confirmation_code().unwrap().as_bytes()).into();
    let mut wrong_confirmation_hash = locked_confirmation_hash;
    wrong_confirmation_hash[0] ^= 0xff;
    first
        .pair_device(&principal, locked_pairing, locked_token_hash, now + 600)
        .await
        .expect("register lockout pairing");
    for _ in 0..2 {
        assert!(first
            .activate_pairing(&vault_id, locked_token_hash, wrong_confirmation_hash, now,)
            .await
            .is_err());
    }
    let boundary_pairing = identity
        .grant_epoch_key(&vault_id, 1, &key, boundary_recipient.clone())
        .expect("boundary pairing grant");
    let boundary_confirmation_hash: [u8; 32] =
        Sha256::digest(boundary_pairing.confirmation_code().unwrap().as_bytes()).into();
    let mut boundary_wrong_hash = boundary_confirmation_hash;
    boundary_wrong_hash[0] ^= 0xff;
    first
        .pair_device(&principal, boundary_pairing, boundary_token_hash, now + 600)
        .await
        .expect("register four-attempt boundary pairing");
    for _ in 0..2 {
        assert!(first
            .activate_pairing(&vault_id, boundary_token_hash, boundary_wrong_hash, now)
            .await
            .is_err());
    }
    assert!(first.authenticate(recipient_token_hash).await.is_err());
    drop(first);

    let restarted = DurableRepository::connect(&database_url, objects)
        .await
        .expect("restarted repository");
    let principal = restarted
        .authenticate(token_hash)
        .await
        .expect("persisted token");
    let (first_activation, concurrent_retry) =
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(
                restarted.activate_pairing(&vault_id, recipient_token_hash, confirmation_hash, 0,),
                restarted.activate_pairing(&vault_id, recipient_token_hash, confirmation_hash, 0,)
            )
        })
        .await
        .expect("concurrent activation must not deadlock");
    assert_eq!(
        first_activation
            .expect("activate persisted pairing")
            .device_id,
        recipient.device_id
    );
    assert_eq!(
        concurrent_retry
            .expect("concurrent activation retry is idempotent")
            .device_id,
        recipient.device_id
    );
    restarted
        .activate_pairing(&vault_id, recipient_token_hash, confirmation_hash, now)
        .await
        .expect("activation retry is idempotent");
    assert_eq!(
        restarted
            .device_authorization(&principal, &recipient.device_id)
            .await
            .expect("read persisted device authorization"),
        Some(pairing)
    );
    let (third, fourth, fifth) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            restarted.activate_pairing(&vault_id, locked_token_hash, wrong_confirmation_hash, now,),
            restarted.activate_pairing(&vault_id, locked_token_hash, wrong_confirmation_hash, now,),
            restarted.activate_pairing(&vault_id, locked_token_hash, wrong_confirmation_hash, now,)
        )
    })
    .await
    .expect("concurrent confirmation failures must not deadlock");
    assert!(third.is_err());
    assert!(fourth.is_err());
    assert!(fifth.is_err());
    assert!(restarted
        .activate_pairing(&vault_id, locked_token_hash, locked_confirmation_hash, now,)
        .await
        .is_err());
    for _ in 0..2 {
        assert!(restarted
            .activate_pairing(&vault_id, boundary_token_hash, boundary_wrong_hash, now)
            .await
            .is_err());
    }
    assert_eq!(
        restarted
            .activate_pairing(
                &vault_id,
                boundary_token_hash,
                boundary_confirmation_hash,
                now,
            )
            .await
            .expect("four failures must still permit the correct code")
            .device_id,
        boundary_recipient.device_id
    );
    let status = restarted.status(&principal).await.unwrap();
    assert_eq!(status.active_devices, 3);
    assert_eq!(status.object_count, 1);
    assert_eq!(status.manifest_count, 1);
    assert!(status.manifest_bytes > 0);
    assert_eq!(
        restarted
            .object(&principal, &object.object_id)
            .await
            .expect("read object"),
        Some(object)
    );
    assert_eq!(
        restarted
            .manifest(&principal, &signed.manifest.revision_id)
            .await
            .expect("read manifest"),
        Some(signed)
    );
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and S3-compatible services"]
async fn durable_quota_boundaries_are_atomic() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let vault_id = format!("vault:quota-{suffix}");
    let token = format!("quota-device-token-{suffix}-long-enough");
    let token_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    let identity = DeviceIdentity::generate().expect("identity");
    let device = identity.record("Quota integration").expect("device");
    let key = EpochKey::from_bytes([84; 32]);
    let repository = Arc::new(
        DurableRepository::connect_with_limits(
            &required("DATABASE_URL"),
            object_store(),
            StorageLimits {
                max_objects_per_vault: 1,
                max_manifests_per_vault: 1,
                max_manifest_bytes_per_vault: 1_048_576,
            },
        )
        .await
        .expect("limited repository"),
    );
    repository
        .create_vault(vault_id.clone(), device.clone(), 1_048_576, token_hash)
        .await
        .expect("create limited vault");
    let principal = repository
        .authenticate(token_hash)
        .await
        .expect("authenticate limited vault");
    let first = key
        .encrypt(&vault_id, 1, b"first concurrent object")
        .expect("first object");
    let second = key
        .encrypt(&vault_id, 1, b"second concurrent object")
        .expect("second object");
    let (first_result, second_result) = tokio::join!(
        repository.upload_object(&principal, first.clone()),
        repository.upload_object(&principal, second.clone())
    );
    assert_eq!(
        [first_result.is_ok(), second_result.is_ok()]
            .into_iter()
            .filter(|accepted| *accepted)
            .count(),
        1
    );
    let accepted = if first_result.is_ok() { first } else { second };
    let status = repository.status(&principal).await.expect("limited status");
    assert_eq!(status.object_count, 1);
    assert_eq!(status.used_bytes, accepted.ciphertext.len() as u64);

    let root = identity
        .sign(
            ManifestDraft {
                vault_id: vault_id.clone(),
                epoch: 1,
                parents: vec![],
                object_ids: vec![accepted.object_id.clone()],
                tombstones: vec![],
                device_id: device.device_id.clone(),
                sequence: 1,
            }
            .finalize()
            .expect("root manifest"),
        )
        .expect("sign root manifest");
    repository
        .commit_manifest(&principal, root.clone())
        .await
        .expect("commit root manifest");
    let child = identity
        .sign(
            ManifestDraft {
                vault_id: vault_id.clone(),
                epoch: 1,
                parents: vec![root.manifest.revision_id.clone()],
                object_ids: vec![accepted.object_id],
                tombstones: vec![],
                device_id: device.device_id,
                sequence: 2,
            }
            .finalize()
            .expect("child manifest"),
        )
        .expect("sign child manifest");
    assert!(repository.commit_manifest(&principal, child).await.is_err());
    let status = repository.status(&principal).await.expect("final status");
    assert_eq!(status.manifest_count, 1);
    assert_eq!(status.heads, [root.manifest.revision_id]);
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and S3-compatible services"]
async fn seed_backup_restore_fixture() {
    let fixture_path = required("FOLIORA_BACKUP_FIXTURE_PATH");
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let vault_id = format!("vault:backup-restore-{suffix}");
    let device_token = format!("backup-restore-device-token-{suffix}-long-enough");
    let token_hash: [u8; 32] = Sha256::digest(device_token.as_bytes()).into();
    let identity = DeviceIdentity::generate().expect("identity");
    let device = identity.record("Backup restore fixture").expect("device");
    let key = EpochKey::from_bytes([91; 32]);
    let repository = DurableRepository::connect(&required("DATABASE_URL"), object_store())
        .await
        .expect("repository");
    // Full bucket inventory must include untracked payloads, not only rows.
    object_store()
        .put(
            &Path::from(format!("v1/restore-orphan-{suffix}.json")),
            Bytes::from_static(b"synthetic-untracked-backup-fixture").into(),
        )
        .await
        .unwrap();

    repository
        .create_vault(vault_id.clone(), device.clone(), 1_048_576, token_hash)
        .await
        .expect("create fixture vault");
    let principal = repository
        .authenticate(token_hash)
        .await
        .expect("authenticate fixture device");
    let object = key
        .encrypt(&vault_id, 1, b"backup restore opaque payload")
        .expect("encrypt fixture object");
    assert_eq!(
        repository
            .upload_object(&principal, object.clone())
            .await
            .expect("upload fixture object"),
        StoreOutcome::Inserted
    );
    let manifest = identity
        .sign(
            ManifestDraft {
                vault_id: vault_id.clone(),
                epoch: 1,
                parents: vec![],
                object_ids: vec![object.object_id.clone()],
                tombstones: vec!["fixture:tombstone".into()],
                device_id: device.device_id,
                sequence: 1,
            }
            .finalize()
            .expect("fixture manifest"),
        )
        .expect("sign fixture manifest");
    repository
        .commit_manifest(&principal, manifest.clone())
        .await
        .expect("commit fixture manifest");
    repository
        .verify_cross_store_integrity()
        .await
        .expect("verify every metadata object against live bucket before backup");

    let encoded = serde_json::to_vec_pretty(&BackupRestoreFixture {
        vault_id,
        device_token,
        object,
        manifest,
    })
    .expect("serialize fixture metadata");
    fs::write(&fixture_path, encoded).expect("write fixture metadata");
}

#[tokio::test]
#[ignore = "requires restored PostgreSQL and S3-compatible services"]
async fn verify_backup_restore_fixture() {
    let fixture: BackupRestoreFixture = serde_json::from_slice(
        &fs::read(required("FOLIORA_BACKUP_FIXTURE_PATH")).expect("read fixture metadata"),
    )
    .expect("parse fixture metadata");
    let token_hash: [u8; 32] = Sha256::digest(fixture.device_token.as_bytes()).into();
    let repository = DurableRepository::connect(&required("DATABASE_URL"), object_store())
        .await
        .expect("restored repository");
    let principal = repository
        .authenticate(token_hash)
        .await
        .expect("restored credential");
    repository
        .verify_cross_store_integrity()
        .await
        .expect("verify every restored metadata object and physical SHA-256");

    assert_eq!(principal.vault_id, fixture.vault_id);
    assert_eq!(
        repository
            .object(&principal, &fixture.object.object_id)
            .await
            .expect("read restored object"),
        Some(fixture.object)
    );
    assert_eq!(
        repository
            .manifest(&principal, &fixture.manifest.manifest.revision_id)
            .await
            .expect("read restored manifest"),
        Some(fixture.manifest.clone())
    );
    assert_eq!(
        repository
            .status(&principal)
            .await
            .expect("restored status")
            .heads,
        vec![fixture.manifest.manifest.revision_id]
    );
    let status = repository
        .status(&principal)
        .await
        .expect("restored accounting");
    assert_eq!(status.object_count, 1);
    assert_eq!(status.manifest_count, 1);
    assert!(status.manifest_bytes > 0);
}

fn object_store() -> Arc<dyn object_store::ObjectStore> {
    // Test-only fallback: exercises real SQL plus persistent local objects but
    // does not claim to validate the S3 transport or MinIO restore workflow.
    if let Ok(directory) = std::env::var("FOLIORA_INTEGRATION_LOCAL_OBJECT_DIR") {
        return Arc::new(
            object_store::local::LocalFileSystem::new_with_prefix(directory)
                .expect("existing isolated test object directory"),
        );
    }
    Arc::new(
        AmazonS3Builder::new()
            .with_bucket_name(required("FOLIORA_S3_BUCKET"))
            .with_region(required("FOLIORA_S3_REGION"))
            .with_endpoint(required("FOLIORA_S3_ENDPOINT"))
            .with_access_key_id(required("FOLIORA_S3_ACCESS_KEY_ID"))
            .with_secret_access_key(required("FOLIORA_S3_SECRET_ACCESS_KEY"))
            .with_allow_http(std::env::var("FOLIORA_S3_ALLOW_HTTP").as_deref() == Ok("1"))
            .build()
            .expect("valid test object-store configuration"),
    )
}

fn durable_storage_key(vault_id: &str, object_id: &str) -> String {
    let vault_hash: String = Sha256::digest(vault_id.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("v1/{vault_hash}/{object_id}.json")
}

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required for durable integration"))
}

async fn stored_path(pool: &sqlx::PgPool, vault_id: &str, object_id: &str) -> Path {
    let key: String =
        sqlx::query_scalar("SELECT storage_key FROM objects WHERE vault_id=$1 AND object_id=$2")
            .bind(vault_id)
            .bind(object_id)
            .fetch_one(pool)
            .await
            .unwrap();
    Path::from(key)
}
