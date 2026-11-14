//! Durable production repository: PostgreSQL owns transactional metadata and
//! an S3-compatible store owns immutable opaque encrypted-object payloads.

use crate::{
    repository::{Principal, RepositoryError, SyncRepository},
    ServiceError, StorageLimits, StoreOutcome, VaultStatus,
};
use async_trait::async_trait;
use bytes::Bytes;
use foliora_sync::{
    validate_vault_id, DeviceRecord, EncryptedObject, SignedManifest, SignedPairingGrant,
};
use futures_util::StreamExt;
use object_store::{path::Path, ObjectMeta, ObjectStore, ObjectStoreExt, PutMode, PutOptions};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{
    migrate::{Migration, MigrationType, Migrator},
    postgres::PgPoolOptions,
    PgPool, Postgres, Row, Transaction,
};
use std::{borrow::Cow, sync::Arc, time::Duration};
use subtle::ConstantTimeEq;

mod integrity;
pub use integrity::CrossStoreIntegrityReport;

fn embedded_migrator() -> Migrator {
    Migrator {
        migrations: Cow::Owned(vec![
            Migration::new(
                1,
                "initial".into(),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0001_initial.sql")),
                false,
            ),
            Migration::new(
                2,
                "pending pairings".into(),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0002_pending_pairings.sql")),
                false,
            ),
            Migration::new(
                3,
                "pairing attempts".into(),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0003_pairing_attempts.sql")),
                false,
            ),
            Migration::new(
                4,
                "retention accounting".into(),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0004_retention_accounting.sql")),
                false,
            ),
            Migration::new(
                5,
                "device authorizations".into(),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0005_device_authorizations.sql")),
                false,
            ),
            Migration::new(
                6,
                "staged object gc".into(),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0006_staged_object_gc.sql")),
                false,
            ),
        ]),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GarbageCollectionReport {
    pub scanned: u64,
    pub referenced: u64,
    pub recent: u64,
    pub deleted: u64,
    pub delete_failures: u64,
    pub staged_marked: u64,
    pub staged_reclaimed: u64,
    pub staged_reactivated: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateOutcome {
    Referenced,
    Deleted,
    DeleteFailed,
    Missing,
}

#[async_trait]
trait OrphanCoordinator: Send + Sync {
    async fn delete_if_orphan(
        &self,
        objects: &dyn ObjectStore,
        metadata: &ObjectMeta,
    ) -> Result<CandidateOutcome, RepositoryError>;
}

struct DurableOrphanCoordinator<'a> {
    pool: &'a PgPool,
}

#[async_trait]
impl OrphanCoordinator for DurableOrphanCoordinator<'_> {
    async fn delete_if_orphan(
        &self,
        objects: &dyn ObjectStore,
        metadata: &ObjectMeta,
    ) -> Result<CandidateOutcome, RepositoryError> {
        let storage_key = metadata.location.to_string();
        let mut tx = self.pool.begin().await.map_err(internal)?;
        lock_storage_key(&mut tx, &storage_key).await?;
        let referenced: bool =
            sqlx::query("SELECT EXISTS(SELECT 1 FROM objects WHERE storage_key=$1) AS referenced")
                .bind(&storage_key)
                .fetch_one(&mut *tx)
                .await
                .map_err(internal)?
                .get("referenced");
        let outcome = if referenced {
            CandidateOutcome::Referenced
        } else {
            match objects.delete(&metadata.location).await {
                Ok(()) | Err(object_store::Error::NotFound { .. }) => CandidateOutcome::Deleted,
                Err(_) => CandidateOutcome::DeleteFailed,
            }
        };
        tx.commit().await.map_err(internal)?;
        Ok(outcome)
    }
}

pub struct DurableRepository {
    pool: PgPool,
    objects: Arc<dyn ObjectStore>,
    limits: StorageLimits,
}

impl DurableRepository {
    pub async fn connect(
        database_url: &str,
        objects: Arc<dyn ObjectStore>,
    ) -> Result<Self, String> {
        Self::connect_with_limits(database_url, objects, StorageLimits::default()).await
    }

    pub async fn connect_with_limits(
        database_url: &str,
        objects: Arc<dyn ObjectStore>,
        limits: StorageLimits,
    ) -> Result<Self, String> {
        let limits = limits
            .validate()
            .map_err(|error| format!("invalid sync storage limits: {error}"))?;
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect(database_url)
            .await
            .map_err(|error| format!("could not connect to PostgreSQL: {error}"))?;
        embedded_migrator()
            .run(&pool)
            .await
            .map_err(|error| format!("could not apply sync migrations: {error}"))?;
        Ok(Self {
            pool,
            objects,
            limits,
        })
    }

    fn storage_key(vault_id: &str, object_id: &str) -> String {
        let vault_hash = hex(&Sha256::digest(vault_id.as_bytes()));
        format!("v1/{vault_hash}/{object_id}.json")
    }

    /// Collects old bucket-only orphans and old unreferenced staged objects.
    /// Staged rows are marked before deletion; retries reconcile the two stores
    /// under the same locks used by uploads and manifest commits.
    pub async fn garbage_collect_orphans(
        &self,
        grace_period: Duration,
    ) -> Result<GarbageCollectionReport, RepositoryError> {
        let grace =
            i64::try_from(grace_period.as_secs()).map_err(|_| RepositoryError::Unavailable)?;
        let database_now: i64 =
            sqlx::query("SELECT floor(extract(epoch from clock_timestamp()))::bigint AS now_unix")
                .fetch_one(&self.pool)
                .await
                .map_err(internal)?
                .get("now_unix");
        let cutoff = database_now.saturating_sub(grace);
        let mut report = collect_orphans(
            self.objects.as_ref(),
            &DurableOrphanCoordinator { pool: &self.pool },
            cutoff,
        )
        .await?;
        report.staged_marked = self.mark_staged_objects(cutoff).await?;
        let staged = self.reclaim_marked_objects().await?;
        report.staged_reclaimed = staged.0;
        report.staged_reactivated = staged.1;
        report.deleted = report.deleted.saturating_add(staged.0);
        report.delete_failures = report.delete_failures.saturating_add(staged.2);
        Ok(report)
    }

    async fn mark_staged_objects(&self, cutoff_unix: i64) -> Result<u64, RepositoryError> {
        let result = sqlx::query(
            "WITH candidates AS (\
                SELECT vault_id, object_id FROM objects o \
                WHERE lifecycle_state='active' AND created_at <= to_timestamp($1) \
                  AND NOT EXISTS (SELECT 1 FROM manifest_objects mo \
                                  WHERE mo.vault_id=o.vault_id AND mo.object_id=o.object_id) \
                ORDER BY created_at LIMIT 1000 FOR UPDATE SKIP LOCKED\
             ) \
             UPDATE objects o SET lifecycle_state='deleting', deletion_marked_at=now() \
             FROM candidates c WHERE o.vault_id=c.vault_id AND o.object_id=c.object_id",
        )
        .bind(cutoff_unix)
        .execute(&self.pool)
        .await
        .map_err(internal)?;
        Ok(result.rows_affected())
    }

    async fn reclaim_marked_objects(&self) -> Result<(u64, u64, u64), RepositoryError> {
        let candidates = sqlx::query(
            "SELECT vault_id,object_id,storage_key FROM objects \
             WHERE lifecycle_state='deleting' ORDER BY deletion_marked_at LIMIT 1000",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(internal)?;
        let mut reclaimed = 0_u64;
        let mut reactivated = 0_u64;
        let mut failures = 0_u64;
        for candidate in candidates {
            let vault_id: String = candidate.get("vault_id");
            let object_id: String = candidate.get("object_id");
            let storage_key: String = candidate.get("storage_key");
            match self
                .reclaim_marked_object(&vault_id, &object_id, &storage_key)
                .await
            {
                Ok(CandidateOutcome::Deleted) => reclaimed = reclaimed.saturating_add(1),
                Ok(CandidateOutcome::Referenced) => reactivated = reactivated.saturating_add(1),
                Ok(CandidateOutcome::Missing) => {}
                Ok(CandidateOutcome::DeleteFailed) | Err(_) => {
                    failures = failures.saturating_add(1)
                }
            }
        }
        Ok((reclaimed, reactivated, failures))
    }

    async fn reclaim_marked_object(
        &self,
        vault_id: &str,
        object_id: &str,
        storage_key: &str,
    ) -> Result<CandidateOutcome, RepositoryError> {
        let mut tx = self.pool.begin().await.map_err(internal)?;
        lock_storage_key(&mut tx, storage_key).await?;
        sqlx::query("SELECT vault_id FROM vaults WHERE vault_id=$1 FOR UPDATE")
            .bind(vault_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal)?
            .ok_or(ServiceError::VaultNotFound)?;
        let row = sqlx::query(
            "SELECT ciphertext_bytes,lifecycle_state FROM objects \
             WHERE vault_id=$1 AND object_id=$2 AND storage_key=$3 FOR UPDATE",
        )
        .bind(vault_id)
        .bind(object_id)
        .bind(storage_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?;
        let Some(row) = row else {
            tx.commit().await.map_err(internal)?;
            return Ok(CandidateOutcome::Missing);
        };
        if row.get::<String, _>("lifecycle_state") != "deleting" {
            tx.commit().await.map_err(internal)?;
            return Ok(CandidateOutcome::Referenced);
        }
        let referenced: bool = sqlx::query(
            "SELECT EXISTS(SELECT 1 FROM manifest_objects WHERE vault_id=$1 AND object_id=$2) AS referenced",
        )
        .bind(vault_id)
        .bind(object_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(internal)?
        .get("referenced");
        if referenced {
            sqlx::query(
                "UPDATE objects SET lifecycle_state='active', deletion_marked_at=NULL \
                 WHERE vault_id=$1 AND object_id=$2",
            )
            .bind(vault_id)
            .bind(object_id)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
            tx.commit().await.map_err(internal)?;
            return Ok(CandidateOutcome::Referenced);
        }
        let path = Path::from(storage_key);
        match self.objects.delete(&path).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
            Err(_) => return Ok(CandidateOutcome::DeleteFailed),
        }
        let bytes: i64 = row.get("ciphertext_bytes");
        sqlx::query("DELETE FROM objects WHERE vault_id=$1 AND object_id=$2")
            .bind(vault_id)
            .bind(object_id)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        sqlx::query(
            "UPDATE vaults SET used_bytes=used_bytes-$2, object_count=object_count-1 WHERE vault_id=$1",
        )
        .bind(vault_id)
        .bind(bytes)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
        tx.commit().await.map_err(internal)?;
        Ok(CandidateOutcome::Deleted)
    }
}

async fn collect_orphans(
    objects: &dyn ObjectStore,
    coordinator: &dyn OrphanCoordinator,
    cutoff_unix: i64,
) -> Result<GarbageCollectionReport, RepositoryError> {
    let mut report = GarbageCollectionReport::default();
    let mut listing = objects.list(Some(&Path::from("v1")));
    while let Some(result) = listing.next().await {
        let metadata = result.map_err(|_| RepositoryError::Unavailable)?;
        report.scanned = report.scanned.saturating_add(1);
        if metadata.last_modified.timestamp() > cutoff_unix {
            report.recent = report.recent.saturating_add(1);
            continue;
        }
        match coordinator.delete_if_orphan(objects, &metadata).await? {
            CandidateOutcome::Referenced => {
                report.referenced = report.referenced.saturating_add(1);
            }
            CandidateOutcome::Deleted => report.deleted = report.deleted.saturating_add(1),
            CandidateOutcome::DeleteFailed => {
                report.delete_failures = report.delete_failures.saturating_add(1);
            }
            CandidateOutcome::Missing => {}
        }
    }
    Ok(report)
}

#[async_trait]
impl SyncRepository for DurableRepository {
    async fn ready(&self) -> Result<(), RepositoryError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let legacy_active: bool = sqlx::query(
            "SELECT EXISTS(SELECT 1 FROM devices \
             WHERE active AND NOT is_root AND authorization_grant IS NULL) AS present",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(internal)?
        .get("present");
        if legacy_active {
            return Err(RepositoryError::Unavailable);
        }
        let sample =
            sqlx::query("SELECT storage_key FROM objects ORDER BY vault_id,object_id LIMIT 1")
                .fetch_optional(&self.pool)
                .await
                .map_err(internal)?;
        if let Some(row) = sample {
            self.objects
                .head(&Path::from(row.get::<String, _>("storage_key")))
                .await
                .map_err(|_| RepositoryError::Unavailable)?;
        } else {
            let mut listing = self.objects.list(Some(&Path::from("v1")));
            if let Some(result) = listing.next().await {
                result.map_err(|_| RepositoryError::Unavailable)?;
            }
        }
        Ok(())
    }

    async fn authenticate(&self, token_hash: [u8; 32]) -> Result<Principal, RepositoryError> {
        let row = sqlx::query(
            "SELECT vault_id, device_id FROM devices \
             WHERE token_hash=$1 AND active=TRUE \
               AND (is_root OR authorization_grant IS NOT NULL)",
        )
        .bind(token_hash.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| RepositoryError::Unavailable)?
        .ok_or(RepositoryError::Unauthorized)?;
        Ok(Principal {
            vault_id: row.get("vault_id"),
            device_id: row.get("device_id"),
        })
    }

    async fn create_vault(
        &self,
        vault_id: String,
        device: DeviceRecord,
        quota_bytes: u64,
        token_hash: [u8; 32],
    ) -> Result<(), RepositoryError> {
        validate_vault_id(&vault_id).map_err(ServiceError::from)?;
        device.validate().map_err(ServiceError::from)?;
        if quota_bytes == 0 {
            return Err(ServiceError::InvalidQuota.into());
        }
        let quota = as_i64(quota_bytes)?;
        let mut tx = self.pool.begin().await.map_err(internal)?;
        ensure_token_available(&mut tx, &token_hash).await?;
        sqlx::query("INSERT INTO vaults(vault_id, epoch, quota_bytes) VALUES ($1, 1, $2)")
            .bind(&vault_id)
            .bind(quota)
            .execute(&mut *tx)
            .await
            .map_err(|error| unique_or(error, ServiceError::VaultExists))?;
        sqlx::query(
            "INSERT INTO devices(vault_id, device_id, record, token_hash, is_root) \
             VALUES ($1, $2, $3, $4, TRUE)",
        )
        .bind(&vault_id)
        .bind(&device.device_id)
        .bind(json(&device)?)
        .bind(token_hash.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(|error| unique_token_or(error, ServiceError::DeviceExists))?;
        tx.commit().await.map_err(internal)?;
        Ok(())
    }

    async fn status(&self, principal: &Principal) -> Result<VaultStatus, RepositoryError> {
        ensure_active(&self.pool, principal).await?;
        let row = sqlx::query(
            "SELECT v.epoch, v.used_bytes, v.quota_bytes, v.object_count, \
             v.manifest_count, v.manifest_bytes, \
             (SELECT count(*) FROM devices d WHERE d.vault_id=v.vault_id AND d.active \
                AND (d.is_root OR d.authorization_grant IS NOT NULL)) active_devices, \
             COALESCE((SELECT array_agg(h.revision_id ORDER BY h.revision_id) \
                       FROM heads h WHERE h.vault_id=v.vault_id), ARRAY[]::text[]) heads \
             FROM vaults v WHERE v.vault_id=$1",
        )
        .bind(&principal.vault_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(internal)?
        .ok_or(ServiceError::VaultNotFound)?;
        Ok(VaultStatus {
            epoch: as_u64(row.get("epoch"))?,
            used_bytes: as_u64(row.get("used_bytes"))?,
            quota_bytes: as_u64(row.get("quota_bytes"))?,
            heads: row.get("heads"),
            active_devices: usize::try_from(row.get::<i64, _>("active_devices"))
                .map_err(|_| RepositoryError::Unavailable)?,
            object_count: as_u64(row.get("object_count"))?,
            manifest_count: as_u64(row.get("manifest_count"))?,
            manifest_bytes: as_u64(row.get("manifest_bytes"))?,
        })
    }

    async fn pair_device(
        &self,
        principal: &Principal,
        signed: SignedPairingGrant,
        token_hash: [u8; 32],
        expires_at_unix: u64,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await.map_err(internal)?;
        let database_now: i64 =
            sqlx::query("SELECT floor(extract(epoch from clock_timestamp()))::bigint AS now_unix")
                .fetch_one(&mut *tx)
                .await
                .map_err(internal)?
                .get("now_unix");
        let expires_at_unix =
            crate::normalize_pairing_expiry_at(expires_at_unix, as_u64(database_now)?)?;
        ensure_token_available(&mut tx, &token_hash).await?;
        let (epoch, authorizer) = locked_active(&mut tx, principal).await?;
        signed.verify(&authorizer).map_err(ServiceError::from)?;
        if signed.grant.vault_id != principal.vault_id
            || signed.grant.authorizing_device_id != principal.device_id
            || signed.grant.epoch != epoch
        {
            return Err(ServiceError::EpochMismatch.into());
        }
        let recipient_exists: bool = sqlx::query(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE vault_id=$1 AND device_id=$2) AS present",
        )
        .bind(&principal.vault_id)
        .bind(&signed.grant.recipient.device_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(internal)?
        .get("present");
        if recipient_exists {
            return Err(ServiceError::DeviceExists.into());
        }
        let confirmation_code = signed.confirmation_code().map_err(ServiceError::from)?;
        let confirmation_hash: [u8; 32] = Sha256::digest(confirmation_code.as_bytes()).into();
        let recipient = signed.grant.recipient.clone();
        sqlx::query(
            "INSERT INTO pending_pairings(vault_id,device_id,record,signed_grant,token_hash,confirmation_hash,expires_at) \
             VALUES($1,$2,$3,$4,$5,$6,to_timestamp($7))",
        )
        .bind(&principal.vault_id)
        .bind(&recipient.device_id)
        .bind(json(&recipient)?)
        .bind(json(&signed)?)
        .bind(token_hash.as_slice())
        .bind(confirmation_hash.as_slice())
        .bind(as_i64(expires_at_unix)?)
        .execute(&mut *tx)
        .await
        .map_err(|error| unique_token_or(error, ServiceError::DeviceExists))?;
        tx.commit().await.map_err(internal)?;
        Ok(())
    }

    async fn activate_pairing(
        &self,
        vault_id: &str,
        token_hash: [u8; 32],
        confirmation_hash: [u8; 32],
        _now_unix: u64,
    ) -> Result<Principal, RepositoryError> {
        let mut tx = self.pool.begin().await.map_err(internal)?;
        lock_token_hash(&mut tx, &token_hash).await?;
        if let Some(row) = sqlx::query(
            "SELECT vault_id,device_id FROM devices WHERE token_hash=$1 AND active=TRUE \
             AND (is_root OR authorization_grant IS NOT NULL)",
        )
        .bind(token_hash.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?
        {
            let principal = Principal {
                vault_id: row.get("vault_id"),
                device_id: row.get("device_id"),
            };
            let result = if principal.vault_id == vault_id {
                Ok(principal)
            } else {
                Err(RepositoryError::Unauthorized)
            };
            tx.commit().await.map_err(internal)?;
            return result;
        }
        let preview = sqlx::query(
            "SELECT signed_grant FROM pending_pairings WHERE vault_id=$1 AND token_hash=$2",
        )
        .bind(vault_id)
        .bind(token_hash.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?
        .ok_or(RepositoryError::Unauthorized)?;
        let preview_grant: SignedPairingGrant = serde_json::from_value(preview.get("signed_grant"))
            .map_err(|_| RepositoryError::Unavailable)?;
        let authorizing = Principal {
            vault_id: vault_id.to_string(),
            device_id: preview_grant.grant.authorizing_device_id,
        };
        let (epoch, authorizer) = locked_active(&mut tx, &authorizing).await?;
        let row = sqlx::query(
            "SELECT device_id,record,signed_grant,confirmation_hash,failed_attempts,\
             (expires_at <= clock_timestamp()) AS expired \
             FROM pending_pairings WHERE vault_id=$1 AND token_hash=$2 FOR UPDATE",
        )
        .bind(vault_id)
        .bind(token_hash.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?
        .ok_or(RepositoryError::Unauthorized)?;
        if row.get::<bool, _>("expired") {
            sqlx::query("DELETE FROM pending_pairings WHERE vault_id=$1 AND token_hash=$2")
                .bind(vault_id)
                .bind(token_hash.as_slice())
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
            tx.commit().await.map_err(internal)?;
            return Err(ServiceError::PairingExpired.into());
        }
        let expected: Vec<u8> = row.get("confirmation_hash");
        if expected.len() != confirmation_hash.len()
            || !bool::from(expected.as_slice().ct_eq(&confirmation_hash))
        {
            let failed_attempts: i16 = row.get("failed_attempts");
            let next_attempt = failed_attempts
                .checked_add(1)
                .ok_or(RepositoryError::Unavailable)?;
            if next_attempt >= i16::from(crate::MAX_PAIRING_CONFIRMATION_ATTEMPTS) {
                sqlx::query("DELETE FROM pending_pairings WHERE vault_id=$1 AND token_hash=$2")
                    .bind(vault_id)
                    .bind(token_hash.as_slice())
                    .execute(&mut *tx)
                    .await
                    .map_err(internal)?;
            } else {
                sqlx::query(
                    "UPDATE pending_pairings SET failed_attempts=$3 \
                     WHERE vault_id=$1 AND token_hash=$2",
                )
                .bind(vault_id)
                .bind(token_hash.as_slice())
                .bind(next_attempt)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
            }
            tx.commit().await.map_err(internal)?;
            return Err(RepositoryError::Unauthorized);
        }
        let signed: SignedPairingGrant = serde_json::from_value(row.get("signed_grant"))
            .map_err(|_| RepositoryError::Unavailable)?;
        signed.verify(&authorizer).map_err(ServiceError::from)?;
        if signed.grant.epoch != epoch {
            return Err(ServiceError::EpochMismatch.into());
        }
        let device_id: String = row.get("device_id");
        sqlx::query(
            "INSERT INTO devices(vault_id,device_id,record,token_hash,authorization_grant,is_root) \
             VALUES($1,$2,$3,$4,$5,FALSE)",
        )
        .bind(vault_id)
        .bind(&device_id)
        .bind(row.get::<Value, _>("record"))
        .bind(token_hash.as_slice())
        .bind(json(&signed)?)
        .execute(&mut *tx)
        .await
        .map_err(|error| unique_token_or(error, ServiceError::DeviceExists))?;
        sqlx::query("DELETE FROM pending_pairings WHERE vault_id=$1 AND device_id=$2")
            .bind(vault_id)
            .bind(&device_id)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        tx.commit().await.map_err(internal)?;
        Ok(Principal {
            vault_id: vault_id.to_string(),
            device_id,
        })
    }

    async fn cleanup_expired_pairings(&self, _now_unix: u64) -> Result<u64, RepositoryError> {
        let result =
            sqlx::query("DELETE FROM pending_pairings WHERE expires_at <= clock_timestamp()")
                .execute(&self.pool)
                .await
                .map_err(internal)?;
        Ok(result.rows_affected())
    }

    async fn revoke_device(
        &self,
        principal: &Principal,
        device_id: &str,
    ) -> Result<u64, RepositoryError> {
        let mut tx = self.pool.begin().await.map_err(internal)?;
        let (epoch, _) = locked_active(&mut tx, principal).await?;
        let pending =
            sqlx::query("DELETE FROM pending_pairings WHERE vault_id=$1 AND device_id=$2")
                .bind(&principal.vault_id)
                .bind(device_id)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
        if pending.rows_affected() > 0 {
            tx.commit().await.map_err(internal)?;
            return Ok(epoch);
        }
        let next_epoch = epoch.checked_add(1).ok_or(ServiceError::EpochMismatch)?;
        let result = sqlx::query("UPDATE devices SET active=FALSE, token_hash=NULL WHERE vault_id=$1 AND device_id=$2 AND active=TRUE")
            .bind(&principal.vault_id)
            .bind(device_id)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        if result.rows_affected() == 0 {
            return Err(ServiceError::DeviceNotFound.into());
        }
        sqlx::query("UPDATE vaults SET epoch=$2 WHERE vault_id=$1")
            .bind(&principal.vault_id)
            .bind(as_i64(next_epoch)?)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        tx.commit().await.map_err(internal)?;
        Ok(next_epoch)
    }

    async fn upload_object(
        &self,
        principal: &Principal,
        object: EncryptedObject,
    ) -> Result<StoreOutcome, RepositoryError> {
        object.validate().map_err(ServiceError::from)?;
        let encoded = serde_json::to_vec(&object).map_err(|_| RepositoryError::Unavailable)?;
        let digest: [u8; 32] = Sha256::digest(&encoded).into();
        let logical_key = Self::storage_key(&object.vault_id, &object.object_id);
        // Never reuse a physical location after an ambiguous remote DELETE or
        // PUT. A late completion can affect only the retired generation.
        let mut generation = [0_u8; 32];
        getrandom::fill(&mut generation).map_err(|_| RepositoryError::Unavailable)?;
        let key = format!("{logical_key}.{}", hex(&generation));
        let path = Path::from(key.clone());
        let mut tx = self.pool.begin().await.map_err(internal)?;
        lock_storage_key(&mut tx, &logical_key).await?;
        lock_storage_key(&mut tx, &key).await?;
        let (epoch, _) = locked_active(&mut tx, principal).await?;
        if object.vault_id != principal.vault_id || object.epoch != epoch {
            return Err(ServiceError::EpochMismatch.into());
        }
        if let Some(row) = sqlx::query(
            "SELECT payload_sha256,storage_key,lifecycle_state FROM objects \
             WHERE vault_id=$1 AND object_id=$2 FOR UPDATE",
        )
        .bind(&object.vault_id)
        .bind(&object.object_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?
        {
            let stored: Vec<u8> = row.get("payload_sha256");
            let stored_key = row.get::<String, _>("storage_key");
            let stored_path = Path::from(stored_key.clone());
            let verified = if row.get::<String, _>("lifecycle_state") == "deleting" {
                None
            } else {
                match self.objects.get(&stored_path).await {
                    Ok(result) => {
                        let existing = result
                            .bytes()
                            .await
                            .map_err(|_| RepositoryError::Unavailable)?;
                        let existing_digest: [u8; 32] = Sha256::digest(&existing).into();
                        if stored != existing_digest || stored != digest {
                            match serde_json::from_slice::<EncryptedObject>(&existing) {
                                Ok(existing_object) if existing_object == object => {
                                    Some(existing_digest)
                                }
                                _ => None,
                            }
                        } else {
                            Some(existing_digest)
                        }
                    }
                    Err(object_store::Error::NotFound { .. }) => None,
                    Err(_) => return Err(RepositoryError::Unavailable),
                }
            };
            let (physical_digest, physical_key) = if let Some(verified) = verified {
                (verified, stored_key)
            } else {
                self.objects
                    .put_opts(
                        &path,
                        Bytes::from(encoded).into(),
                        PutOptions {
                            mode: PutMode::Create,
                            ..Default::default()
                        },
                    )
                    .await
                    .map_err(|_| RepositoryError::Unavailable)?;
                (digest, key)
            };
            sqlx::query(
                "UPDATE objects SET payload_sha256=$3, lifecycle_state='active', \
                 deletion_marked_at=NULL, created_at=now(), storage_key=$4 \
                 WHERE vault_id=$1 AND object_id=$2",
            )
            .bind(&object.vault_id)
            .bind(&object.object_id)
            .bind(physical_digest.as_slice())
            .bind(physical_key)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
            tx.commit().await.map_err(internal)?;
            return Ok(StoreOutcome::AlreadyPresent);
        }
        let bytes =
            i64::try_from(object.ciphertext.len()).map_err(|_| RepositoryError::Unavailable)?;
        let quota = sqlx::query(
            "SELECT used_bytes, quota_bytes, object_count FROM vaults WHERE vault_id=$1 FOR UPDATE",
        )
        .bind(&object.vault_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(internal)?;
        let used: i64 = quota.get("used_bytes");
        let limit: i64 = quota.get("quota_bytes");
        let object_count: i64 = quota.get("object_count");
        if as_u64(object_count)? >= self.limits.max_objects_per_vault {
            return Err(ServiceError::StorageMetadataExceeded.into());
        }
        if used
            .checked_add(bytes)
            .filter(|value| *value <= limit)
            .is_none()
        {
            return Err(ServiceError::QuotaExceeded.into());
        }
        self.objects
            .put_opts(
                &path,
                Bytes::from(encoded).into(),
                PutOptions {
                    mode: PutMode::Create,
                    ..Default::default()
                },
            )
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        sqlx::query("INSERT INTO objects(vault_id,object_id,epoch,ciphertext_bytes,storage_key,payload_sha256,accounting_version,lifecycle_state) VALUES($1,$2,$3,$4,$5,$6,1,'active')")
            .bind(&object.vault_id).bind(&object.object_id).bind(as_i64(object.epoch)?).bind(bytes).bind(key).bind(digest.as_slice())
            .execute(&mut *tx).await.map_err(|error| unique_or(error, ServiceError::ObjectConflict))?;
        sqlx::query(
            "UPDATE vaults SET used_bytes=used_bytes+$2, object_count=object_count+1 WHERE vault_id=$1",
        )
            .bind(&object.vault_id)
            .bind(bytes)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        tx.commit().await.map_err(internal)?;
        Ok(StoreOutcome::Inserted)
    }

    async fn object(
        &self,
        principal: &Principal,
        object_id: &str,
    ) -> Result<Option<EncryptedObject>, RepositoryError> {
        ensure_active(&self.pool, principal).await?;
        let row = sqlx::query(
            "SELECT storage_key,payload_sha256 FROM objects WHERE vault_id=$1 AND object_id=$2",
        )
        .bind(&principal.vault_id)
        .bind(object_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(internal)?;
        let Some(row) = row else { return Ok(None) };
        let path = Path::from(row.get::<String, _>("storage_key"));
        let bytes = self
            .objects
            .get(&path)
            .await
            .map_err(|_| RepositoryError::Unavailable)?
            .bytes()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let expected: Vec<u8> = row.get("payload_sha256");
        if Sha256::digest(&bytes)[..] != expected {
            return Err(RepositoryError::Unavailable);
        }
        let object = serde_json::from_slice(&bytes).map_err(|_| RepositoryError::Unavailable)?;
        Ok(Some(object))
    }

    async fn commit_manifest(
        &self,
        principal: &Principal,
        signed: SignedManifest,
    ) -> Result<StoreOutcome, RepositoryError> {
        let mut tx = self.pool.begin().await.map_err(internal)?;
        let (epoch, device) = locked_active(&mut tx, principal).await?;
        signed.verify(&device).map_err(ServiceError::from)?;
        let manifest = &signed.manifest;
        if manifest.vault_id != principal.vault_id
            || manifest.device_id != principal.device_id
            || manifest.epoch != epoch
        {
            return Err(ServiceError::EpochMismatch.into());
        }
        if let Some(row) = sqlx::query(
            "SELECT signed_manifest FROM manifests WHERE vault_id=$1 AND revision_id=$2",
        )
        .bind(&manifest.vault_id)
        .bind(&manifest.revision_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?
        {
            let existing: Value = row.get("signed_manifest");
            return if existing == json(&signed)? {
                Ok(StoreOutcome::AlreadyPresent)
            } else {
                Err(ServiceError::ManifestConflict.into())
            };
        }
        let signed_json = json(&signed)?;
        let signed_bytes: i64 =
            sqlx::query("SELECT octet_length($1::jsonb::text)::bigint AS encoded_bytes")
                .bind(&signed_json)
                .fetch_one(&mut *tx)
                .await
                .map_err(internal)?
                .get("encoded_bytes");
        let accounting = sqlx::query(
            "SELECT manifest_count,manifest_bytes FROM vaults WHERE vault_id=$1 FOR UPDATE",
        )
        .bind(&manifest.vault_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(internal)?;
        let manifest_count: i64 = accounting.get("manifest_count");
        let manifest_bytes: i64 = accounting.get("manifest_bytes");
        if as_u64(manifest_count)? >= self.limits.max_manifests_per_vault
            || manifest_bytes
                .checked_add(signed_bytes)
                .and_then(|value| as_u64(value).ok())
                .filter(|value| *value <= self.limits.max_manifest_bytes_per_vault)
                .is_none()
        {
            return Err(ServiceError::StorageMetadataExceeded.into());
        }
        let sequence = as_i64(manifest.sequence)?;
        let last: i64 = sqlx::query(
            "SELECT last_sequence FROM devices WHERE vault_id=$1 AND device_id=$2 FOR UPDATE",
        )
        .bind(&manifest.vault_id)
        .bind(&manifest.device_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(internal)?
        .get("last_sequence");
        if sequence <= last {
            return Err(ServiceError::SequenceReplay.into());
        }
        for object_id in &manifest.object_ids {
            let found = sqlx::query(
                "SELECT epoch,lifecycle_state FROM objects \
                 WHERE vault_id=$1 AND object_id=$2 FOR UPDATE",
            )
            .bind(&manifest.vault_id)
            .bind(object_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal)?
            .ok_or_else(|| ServiceError::MissingObject(object_id.clone()))?;
            if as_u64(found.get("epoch"))? != manifest.epoch {
                return Err(ServiceError::EpochMismatch.into());
            }
            if found.get::<String, _>("lifecycle_state") == "deleting" {
                // GC may have deleted S3 bytes before its metadata transaction
                // rolled back. Only upload_object can verify/repair the payload
                // and reactivate this row; a commit must never resurrect it.
                return Err(ServiceError::MissingObject(object_id.clone()).into());
            }
        }
        if manifest_count == 0 && !manifest.parents.is_empty() {
            return Err(ServiceError::MissingParent(manifest.parents[0].clone()).into());
        }
        if manifest_count > 0 && manifest.parents.is_empty() {
            return Err(ServiceError::RootAlreadyExists.into());
        }
        for parent in &manifest.parents {
            let exists: bool = sqlx::query("SELECT EXISTS(SELECT 1 FROM manifests WHERE vault_id=$1 AND revision_id=$2) AS present")
                .bind(&manifest.vault_id).bind(parent).fetch_one(&mut *tx).await.map_err(internal)?.get("present");
            if !exists {
                return Err(ServiceError::MissingParent(parent.clone()).into());
            }
        }
        sqlx::query("INSERT INTO manifests(vault_id,revision_id,epoch,device_id,sequence,signed_manifest,encoded_bytes) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(&manifest.vault_id).bind(&manifest.revision_id).bind(as_i64(manifest.epoch)?).bind(&manifest.device_id).bind(sequence).bind(signed_json).bind(signed_bytes)
            .execute(&mut *tx).await.map_err(|error| unique_or(error, ServiceError::ManifestConflict))?;
        for object_id in &manifest.object_ids {
            sqlx::query(
                "INSERT INTO manifest_objects(vault_id,revision_id,object_id) VALUES($1,$2,$3)",
            )
            .bind(&manifest.vault_id)
            .bind(&manifest.revision_id)
            .bind(object_id)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        }
        for parent in &manifest.parents {
            sqlx::query(
                "INSERT INTO manifest_parents(vault_id,revision_id,parent_id) VALUES($1,$2,$3)",
            )
            .bind(&manifest.vault_id)
            .bind(&manifest.revision_id)
            .bind(parent)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
            sqlx::query("DELETE FROM heads WHERE vault_id=$1 AND revision_id=$2")
                .bind(&manifest.vault_id)
                .bind(parent)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
        }
        sqlx::query("INSERT INTO heads(vault_id,revision_id) VALUES($1,$2)")
            .bind(&manifest.vault_id)
            .bind(&manifest.revision_id)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        sqlx::query("UPDATE devices SET last_sequence=$3 WHERE vault_id=$1 AND device_id=$2")
            .bind(&manifest.vault_id)
            .bind(&manifest.device_id)
            .bind(sequence)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        sqlx::query(
            "UPDATE vaults SET manifest_count=manifest_count+1, manifest_bytes=manifest_bytes+$2 WHERE vault_id=$1",
        )
        .bind(&manifest.vault_id)
        .bind(signed_bytes)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
        tx.commit().await.map_err(internal)?;
        Ok(StoreOutcome::Inserted)
    }

    async fn manifest(
        &self,
        principal: &Principal,
        revision_id: &str,
    ) -> Result<Option<SignedManifest>, RepositoryError> {
        ensure_active(&self.pool, principal).await?;
        let row = sqlx::query(
            "SELECT signed_manifest FROM manifests WHERE vault_id=$1 AND revision_id=$2",
        )
        .bind(&principal.vault_id)
        .bind(revision_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(internal)?;
        row.map(|row| {
            serde_json::from_value(row.get("signed_manifest"))
                .map_err(|_| RepositoryError::Unavailable)
        })
        .transpose()
    }

    async fn device_authorization(
        &self,
        principal: &Principal,
        device_id: &str,
    ) -> Result<Option<SignedPairingGrant>, RepositoryError> {
        ensure_active(&self.pool, principal).await?;
        sqlx::query("SELECT authorization_grant FROM devices WHERE vault_id=$1 AND device_id=$2")
            .bind(&principal.vault_id)
            .bind(device_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(internal)?
            .and_then(|row| row.get::<Option<Value>, _>("authorization_grant"))
            .map(|value| serde_json::from_value(value).map_err(|_| RepositoryError::Unavailable))
            .transpose()
    }
}

async fn ensure_active(pool: &PgPool, principal: &Principal) -> Result<(), RepositoryError> {
    let active: bool = sqlx::query("SELECT EXISTS(SELECT 1 FROM devices WHERE vault_id=$1 AND device_id=$2 AND active AND (is_root OR authorization_grant IS NOT NULL)) AS active")
        .bind(&principal.vault_id).bind(&principal.device_id).fetch_one(pool).await.map_err(internal)?.get("active");
    if active {
        Ok(())
    } else {
        Err(ServiceError::DeviceRevoked.into())
    }
}

async fn locked_active(
    tx: &mut Transaction<'_, Postgres>,
    principal: &Principal,
) -> Result<(u64, DeviceRecord), RepositoryError> {
    let epoch = sqlx::query("SELECT epoch FROM vaults WHERE vault_id=$1 FOR UPDATE")
        .bind(&principal.vault_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(internal)?
        .ok_or(ServiceError::VaultNotFound)?
        .get("epoch");
    let row = sqlx::query(
        "SELECT record,(active AND (is_root OR authorization_grant IS NOT NULL)) AS active \
         FROM devices WHERE vault_id=$1 AND device_id=$2 FOR UPDATE",
    )
    .bind(&principal.vault_id)
    .bind(&principal.device_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(internal)?
    .ok_or(ServiceError::DeviceNotFound)?;
    if !row.get::<bool, _>("active") {
        return Err(ServiceError::DeviceRevoked.into());
    }
    let device =
        serde_json::from_value(row.get("record")).map_err(|_| RepositoryError::Unavailable)?;
    Ok((as_u64(epoch)?, device))
}

async fn lock_storage_key(
    tx: &mut Transaction<'_, Postgres>,
    storage_key: &str,
) -> Result<(), RepositoryError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(storage_key)
        .execute(&mut **tx)
        .await
        .map_err(internal)?;
    Ok(())
}

async fn ensure_token_available(
    tx: &mut Transaction<'_, Postgres>,
    token_hash: &[u8; 32],
) -> Result<(), RepositoryError> {
    lock_token_hash(tx, token_hash).await?;
    let exists: bool = sqlx::query(
        "SELECT (EXISTS(SELECT 1 FROM devices WHERE token_hash=$1) OR \
         EXISTS(SELECT 1 FROM pending_pairings WHERE token_hash=$1)) AS present",
    )
    .bind(token_hash.as_slice())
    .fetch_one(&mut **tx)
    .await
    .map_err(internal)?
    .get("present");
    if exists {
        Err(RepositoryError::TokenConflict)
    } else {
        Ok(())
    }
}

async fn lock_token_hash(
    tx: &mut Transaction<'_, Postgres>,
    token_hash: &[u8; 32],
) -> Result<(), RepositoryError> {
    let token_key = hex(token_hash);
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 1))")
        .bind(&token_key)
        .execute(&mut **tx)
        .await
        .map_err(internal)?;
    Ok(())
}

fn json<T: serde::Serialize>(value: &T) -> Result<Value, RepositoryError> {
    serde_json::to_value(value).map_err(|_| RepositoryError::Unavailable)
}
fn as_i64(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value).map_err(|_| RepositoryError::Unavailable)
}
fn as_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::Unavailable)
}
fn internal(_: sqlx::Error) -> RepositoryError {
    RepositoryError::Unavailable
}
fn unique_or(error: sqlx::Error, conflict: ServiceError) -> RepositoryError {
    if error
        .as_database_error()
        .and_then(|value| value.code())
        .as_deref()
        == Some("23505")
    {
        conflict.into()
    } else {
        RepositoryError::Unavailable
    }
}
fn unique_token_or(error: sqlx::Error, conflict: ServiceError) -> RepositoryError {
    if matches!(
        error
            .as_database_error()
            .and_then(|value| value.constraint()),
        Some("devices_token_hash_key" | "pending_pairings_token_hash_key")
    ) {
        RepositoryError::TokenConflict
    } else {
        unique_or(error, conflict)
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;
    use std::collections::BTreeSet;

    struct StaticCoordinator {
        referenced: BTreeSet<String>,
    }

    #[async_trait]
    impl OrphanCoordinator for StaticCoordinator {
        async fn delete_if_orphan(
            &self,
            objects: &dyn ObjectStore,
            metadata: &ObjectMeta,
        ) -> Result<CandidateOutcome, RepositoryError> {
            if self.referenced.contains(metadata.location.as_ref()) {
                return Ok(CandidateOutcome::Referenced);
            }
            objects
                .delete(&metadata.location)
                .await
                .map_err(|_| RepositoryError::Unavailable)?;
            Ok(CandidateOutcome::Deleted)
        }
    }

    #[tokio::test]
    async fn garbage_collection_keeps_referenced_and_removes_old_orphans() {
        let objects = InMemory::new();
        let referenced_path = Path::from("v1/vault/object:referenced.json");
        let orphan_path = Path::from("v1/vault/object:orphan.json");
        objects
            .put(&referenced_path, Bytes::from_static(b"referenced").into())
            .await
            .unwrap();
        objects
            .put(&orphan_path, Bytes::from_static(b"orphan").into())
            .await
            .unwrap();

        let coordinator = StaticCoordinator {
            referenced: BTreeSet::from([referenced_path.to_string()]),
        };
        let report = collect_orphans(&objects, &coordinator, i64::MAX)
            .await
            .unwrap();

        assert_eq!(report.scanned, 2);
        assert_eq!(report.referenced, 1);
        assert_eq!(report.deleted, 1);
        assert_eq!(report.recent, 0);
        assert_eq!(report.delete_failures, 0);
        assert!(objects.get(&referenced_path).await.is_ok());
        assert!(matches!(
            objects.get(&orphan_path).await,
            Err(object_store::Error::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn garbage_collection_respects_the_upload_grace_window() {
        let objects = InMemory::new();
        let recent_path = Path::from("v1/vault/object:recent.json");
        objects
            .put(&recent_path, Bytes::from_static(b"recent").into())
            .await
            .unwrap();

        let coordinator = StaticCoordinator {
            referenced: BTreeSet::new(),
        };
        let report = collect_orphans(&objects, &coordinator, i64::MIN)
            .await
            .unwrap();

        assert_eq!(report.scanned, 1);
        assert_eq!(report.recent, 1);
        assert_eq!(report.deleted, 0);
        assert!(objects.get(&recent_path).await.is_ok());
    }
}
