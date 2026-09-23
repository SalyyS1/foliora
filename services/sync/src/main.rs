use foliora_sync_service::api::{
    router, ApiState, DEFAULT_MAX_VAULT_BYTES, DEFAULT_OBJECT_CONCURRENCY, DEFAULT_REQUEST_DEADLINE,
};
use foliora_sync_service::{
    durable::DurableRepository,
    metrics::ServiceMetrics,
    rate_limit::{
        RateLimitConfig, DEFAULT_GLOBAL_BURST, DEFAULT_GLOBAL_PER_MINUTE, DEFAULT_MAX_CREDENTIALS,
        DEFAULT_PER_CREDENTIAL_BURST, DEFAULT_PER_CREDENTIAL_PER_MINUTE,
    },
    repository::{MemoryRepository, SyncRepository},
    StorageLimits, DEFAULT_MAX_MANIFESTS_PER_VAULT, DEFAULT_MAX_MANIFEST_BYTES_PER_VAULT,
    DEFAULT_MAX_OBJECTS_PER_VAULT,
};
use object_store::aws::AmazonS3Builder;
use std::{sync::Arc, time::Duration};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("foliora-sync-service: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let (verification_only, inventory_jsonl) =
        match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
            [] => (false, false),
            [argument] if argument == "--verify-integrity" => (true, false),
            [argument, inventory]
                if argument == "--verify-integrity" && inventory == "--inventory-jsonl" =>
            {
                (true, true)
            }
            _ => {
                return Err(
                    "usage: foliora-sync-service [--verify-integrity [--inventory-jsonl]]".into(),
                )
            }
        };
    let bind = std::env::var("FOLIORA_SYNC_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let bootstrap = if verification_only {
        String::new()
    } else {
        required("FOLIORA_SYNC_BOOTSTRAP_TOKEN")?
    };
    let metrics = Arc::new(ServiceMetrics::default());
    let max_vault_bytes = byte_setting(
        "FOLIORA_SYNC_MAX_VAULT_BYTES",
        DEFAULT_MAX_VAULT_BYTES,
        1024 * 1024,
    )?;
    let storage_limits = StorageLimits {
        max_objects_per_vault: count_setting(
            "FOLIORA_SYNC_MAX_OBJECTS_PER_VAULT",
            DEFAULT_MAX_OBJECTS_PER_VAULT,
        )?,
        max_manifests_per_vault: count_setting(
            "FOLIORA_SYNC_MAX_MANIFESTS_PER_VAULT",
            DEFAULT_MAX_MANIFESTS_PER_VAULT,
        )?,
        max_manifest_bytes_per_vault: byte_setting(
            "FOLIORA_SYNC_MAX_MANIFEST_BYTES_PER_VAULT",
            DEFAULT_MAX_MANIFEST_BYTES_PER_VAULT,
            1024 * 1024,
        )?,
    }
    .validate()
    .map_err(|error| error.to_string())?;
    let rate_limit = RateLimitConfig {
        per_credential_per_minute: u32_setting(
            "FOLIORA_SYNC_RATE_PER_CREDENTIAL_PER_MINUTE",
            DEFAULT_PER_CREDENTIAL_PER_MINUTE,
        )?,
        per_credential_burst: u32_setting(
            "FOLIORA_SYNC_RATE_PER_CREDENTIAL_BURST",
            DEFAULT_PER_CREDENTIAL_BURST,
        )?,
        global_per_minute: u32_setting(
            "FOLIORA_SYNC_RATE_GLOBAL_PER_MINUTE",
            DEFAULT_GLOBAL_PER_MINUTE,
        )?,
        global_burst: u32_setting("FOLIORA_SYNC_RATE_GLOBAL_BURST", DEFAULT_GLOBAL_BURST)?,
        max_credentials: usize_setting(
            "FOLIORA_SYNC_RATE_MAX_CREDENTIALS",
            DEFAULT_MAX_CREDENTIALS,
            1_000_000,
        )?,
    }
    .validate()?;
    let request_deadline = duration_setting(
        "FOLIORA_SYNC_REQUEST_DEADLINE_SECONDS",
        DEFAULT_REQUEST_DEADLINE.as_secs(),
        1,
    )?;
    let object_concurrency = usize_setting(
        "FOLIORA_SYNC_OBJECT_CONCURRENCY",
        DEFAULT_OBJECT_CONCURRENCY,
        1_024,
    )?;
    let repository: Arc<dyn foliora_sync_service::repository::SyncRepository> =
        if std::env::var("FOLIORA_SYNC_EPHEMERAL").as_deref() == Ok("1") {
            if verification_only {
                return Err("integrity verification requires durable PostgreSQL/S3 mode".into());
            }
            eprintln!("WARNING: ephemeral sync mode enabled; all server state is lost on restart.");
            Arc::new(
                MemoryRepository::with_storage_limits(storage_limits)
                    .map_err(|error| error.to_string())?,
            )
        } else {
            let database_url = required("DATABASE_URL")?;
            let bucket = required("FOLIORA_S3_BUCKET")?;
            let region = required("FOLIORA_S3_REGION")?;
            let endpoint = required("FOLIORA_S3_ENDPOINT")?;
            let access_key = required("FOLIORA_S3_ACCESS_KEY_ID")?;
            let secret_key = required("FOLIORA_S3_SECRET_ACCESS_KEY")?;
            let allow_http = std::env::var("FOLIORA_S3_ALLOW_HTTP").as_deref() == Ok("1");
            if endpoint.starts_with("http://") && !allow_http {
                return Err("HTTP object storage requires explicit FOLIORA_S3_ALLOW_HTTP=1".into());
            }
            let objects = AmazonS3Builder::new()
                .with_bucket_name(bucket)
                .with_region(region)
                .with_endpoint(endpoint)
                .with_access_key_id(access_key)
                .with_secret_access_key(secret_key)
                .with_allow_http(allow_http)
                .build()
                .map_err(|error| format!("invalid S3 configuration: {error}"))?;
            if verification_only {
                let durable =
                    DurableRepository::connect_for_verification(&database_url, Arc::new(objects))
                        .await?;
                let report = durable.verify_cross_store_integrity().await.map_err(|_| {
                    "cross-store integrity verification failed; keep writers stopped".to_string()
                })?;
                if inventory_jsonl {
                    durable
                        .write_bucket_inventory(&mut std::io::stdout().lock())
                        .await
                        .map_err(|_| "bucket inventory failed; discard partial output")?;
                } else {
                    println!(
                        "{}",
                        serde_json::to_string(&report)
                            .map_err(|_| "could not encode integrity report")?
                    );
                }
                return Ok(());
            }
            let durable = Arc::new(
                DurableRepository::connect_with_limits(
                    &database_url,
                    Arc::new(objects),
                    storage_limits,
                )
                .await?,
            );
            spawn_garbage_collection(durable.clone(), metrics.clone())?;
            durable
        };
    spawn_pairing_cleanup(repository.clone(), metrics.clone())?;
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|error| error.to_string())?;
    eprintln!("Foliora sync listening on {bind}; terminate TLS at a trusted reverse proxy.");
    axum::serve(
        listener,
        router(
            ApiState::with_repository_metrics_and_limit(
                &bootstrap,
                repository,
                metrics,
                max_vault_bytes,
            )?
            .with_rate_limit(rate_limit)?
            .with_resource_limits(request_deadline, object_concurrency)?,
        ),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(|error| error.to_string())
}

fn spawn_pairing_cleanup(
    repository: Arc<dyn SyncRepository>,
    metrics: Arc<ServiceMetrics>,
) -> Result<(), String> {
    let interval = duration_setting("FOLIORA_SYNC_PAIRING_CLEANUP_SECONDS", 60, 10)?;
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(interval);
        timer.tick().await;
        loop {
            timer.tick().await;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_secs());
            match now {
                Ok(now) => match repository.cleanup_expired_pairings(now).await {
                    Ok(deleted) => metrics.observe_pairing_cleanup(deleted, false),
                    Err(_) => {
                        metrics.observe_pairing_cleanup(0, true);
                        eprintln!("Foliora sync pairing cleanup failed; retrying.");
                    }
                },
                Err(_) => {
                    metrics.observe_pairing_cleanup(0, true);
                    eprintln!("Foliora sync pairing cleanup skipped: system clock is invalid.");
                }
            }
        }
    });
    Ok(())
}

fn spawn_garbage_collection(
    repository: Arc<DurableRepository>,
    metrics: Arc<ServiceMetrics>,
) -> Result<(), String> {
    let interval = duration_setting("FOLIORA_SYNC_GC_INTERVAL_SECONDS", 6 * 60 * 60, 60)?;
    let grace = duration_setting("FOLIORA_SYNC_GC_GRACE_SECONDS", 24 * 60 * 60, 5 * 60)?;
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(interval);
        timer.tick().await;
        loop {
            timer.tick().await;
            match repository.garbage_collect_orphans(grace).await {
                Ok(report) => {
                    metrics.observe_garbage_collection(
                        report.scanned,
                        report.deleted,
                        report.delete_failures,
                    );
                    eprintln!(
                        "Foliora sync GC: scanned={}, referenced={}, recent={}, deleted={}, staged_marked={}, staged_reclaimed={}, staged_reactivated={}, failures={}",
                        report.scanned,
                        report.referenced,
                        report.recent,
                        report.deleted,
                        report.staged_marked,
                        report.staged_reclaimed,
                        report.staged_reactivated,
                        report.delete_failures
                    );
                }
                Err(_) => {
                    metrics.observe_garbage_collection(0, 0, 1);
                    eprintln!("Foliora sync GC failed; retrying on the next interval.");
                }
            }
        }
    });
    Ok(())
}

fn duration_setting(
    name: &str,
    default_seconds: u64,
    minimum_seconds: u64,
) -> Result<Duration, String> {
    let seconds = match std::env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|_| format!("{name} must be an integer number of seconds"))?,
        Err(std::env::VarError::NotPresent) => default_seconds,
        Err(_) => return Err(format!("{name} is not valid Unicode")),
    };
    if seconds < minimum_seconds {
        return Err(format!("{name} must be at least {minimum_seconds} seconds"));
    }
    Ok(Duration::from_secs(seconds))
}

fn byte_setting(name: &str, default_bytes: u64, minimum_bytes: u64) -> Result<u64, String> {
    let bytes = match std::env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|_| format!("{name} must be an integer number of bytes"))?,
        Err(std::env::VarError::NotPresent) => default_bytes,
        Err(_) => return Err(format!("{name} is not valid Unicode")),
    };
    if bytes < minimum_bytes || bytes > i64::MAX as u64 {
        return Err(format!(
            "{name} must be between {minimum_bytes} and {} bytes",
            i64::MAX
        ));
    }
    Ok(bytes)
}

fn count_setting(name: &str, default_value: u64) -> Result<u64, String> {
    let value = match std::env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|_| format!("{name} must be a positive integer"))?,
        Err(std::env::VarError::NotPresent) => default_value,
        Err(_) => return Err(format!("{name} is not valid Unicode")),
    };
    if value == 0 || value > i64::MAX as u64 {
        return Err(format!("{name} must be between 1 and {}", i64::MAX));
    }
    Ok(value)
}

fn u32_setting(name: &str, default_value: u32) -> Result<u32, String> {
    let value = match std::env::var(name) {
        Ok(value) => value
            .parse::<u32>()
            .map_err(|_| format!("{name} must be a positive integer"))?,
        Err(std::env::VarError::NotPresent) => default_value,
        Err(_) => return Err(format!("{name} is not valid Unicode")),
    };
    if value == 0 {
        return Err(format!("{name} must be a positive integer"));
    }
    Ok(value)
}

fn usize_setting(name: &str, default_value: usize, maximum: usize) -> Result<usize, String> {
    let value = match std::env::var(name) {
        Ok(value) => value
            .parse::<usize>()
            .map_err(|_| format!("{name} must be a positive integer"))?,
        Err(std::env::VarError::NotPresent) => default_value,
        Err(_) => return Err(format!("{name} is not valid Unicode")),
    };
    if value == 0 || value > maximum {
        return Err(format!("{name} must be between 1 and {maximum}"));
    }
    Ok(value)
}

fn required(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is required unless FOLIORA_SYNC_EPHEMERAL=1"))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
