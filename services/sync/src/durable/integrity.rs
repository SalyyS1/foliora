//! Offline cross-store scrub: no migrations, writes, or HTTP listener.
use super::*;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossStoreIntegrityReport {
    pub metadata_objects: u64,
    pub bucket_objects: u64,
    pub untracked_bucket_objects: u64,
}

impl DurableRepository {
    /// Stream independent live SHA-256 hashes for every bucket entry, including
    /// untracked orphans. Keep writers stopped and sort JSON lines externally.
    pub async fn write_bucket_inventory(
        &self,
        output: &mut impl std::io::Write,
    ) -> Result<(), RepositoryError> {
        let mut listing = self.objects.list(Some(&Path::from("v1")));
        while let Some(result) = listing.next().await {
            let metadata = result.map_err(|_| RepositoryError::Unavailable)?;
            let mut bytes = self
                .objects
                .get(&metadata.location)
                .await
                .map_err(|_| RepositoryError::Unavailable)?
                .into_stream();
            let mut digest = Sha256::new();
            while let Some(chunk) = bytes.next().await {
                digest.update(chunk.map_err(|_| RepositoryError::Unavailable)?);
            }
            serde_json::to_writer(
                &mut *output,
                &serde_json::json!({
                    "key": metadata.location.to_string(), "sha256": hex(&digest.finalize())
                }),
            )
            .map_err(|_| RepositoryError::Unavailable)?;
            output
                .write_all(b"\n")
                .map_err(|_| RepositoryError::Unavailable)?;
        }
        output.flush().map_err(|_| RepositoryError::Unavailable)
    }

    /// Open only for maintenance verification. PostgreSQL enforces read-only
    /// transactions on every connection; this does not apply pending migrations.
    pub async fn connect_for_verification(
        database_url: &str,
        objects: Arc<dyn ObjectStore>,
    ) -> Result<Self, String> {
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::query("SET default_transaction_read_only = on")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(database_url)
            .await
            .map_err(|_| {
                "could not open read-only PostgreSQL verification connection".to_string()
            })?;
        Ok(Self {
            pool,
            objects,
            limits: StorageLimits::default(),
        })
    }

    /// Exhaustive validation for quiesced restore drills, not a readiness probe.
    /// Stream rows and payload chunks so memory does not grow with vault count
    /// or payload size. Callers must stop *all* writers and GC for the entire run.
    pub async fn verify_cross_store_integrity(
        &self,
    ) -> Result<CrossStoreIntegrityReport, RepositoryError> {
        let mut report = CrossStoreIntegrityReport::default();
        let mut rows =
            sqlx::query("SELECT storage_key,payload_sha256 FROM objects ORDER BY storage_key")
                .fetch(&self.pool);
        while let Some(result) = rows.next().await {
            let row = result.map_err(internal)?;
            let expected: Vec<u8> = row.get("payload_sha256");
            let expected: [u8; 32] = expected
                .try_into()
                .map_err(|_| RepositoryError::Unavailable)?;
            let location = Path::from(row.get::<String, _>("storage_key"));
            let mut bytes = self
                .objects
                .get(&location)
                .await
                .map_err(|_| RepositoryError::Unavailable)?
                .into_stream();
            let mut digest = Sha256::new();
            while let Some(chunk) = bytes.next().await {
                digest.update(chunk.map_err(|_| RepositoryError::Unavailable)?);
            }
            if <[u8; 32]>::from(digest.finalize()) != expected {
                return Err(RepositoryError::Unavailable);
            }
            report.metadata_objects += 1;
        }
        drop(rows);
        let mut listing = self.objects.list(Some(&Path::from("v1")));
        while let Some(result) = listing.next().await {
            let metadata = result.map_err(|_| RepositoryError::Unavailable)?;
            report.bucket_objects += 1;
            let tracked: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM objects WHERE storage_key=$1)")
                    .bind(metadata.location.to_string())
                    .fetch_one(&self.pool)
                    .await
                    .map_err(internal)?;
            if !tracked {
                report.untracked_bucket_objects += 1;
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
#[path = "integrity_tests.rs"]
mod tests;
