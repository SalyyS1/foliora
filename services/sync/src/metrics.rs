use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub uptime_seconds: u64,
    pub http_requests: u64,
    pub http_client_errors: u64,
    pub http_server_errors: u64,
    pub rate_limited_requests: u64,
    pub readiness_checks: u64,
    pub readiness_failures: u64,
    pub garbage_collection_runs: u64,
    pub garbage_collection_scanned: u64,
    pub garbage_collection_deleted: u64,
    pub garbage_collection_failures: u64,
    pub pairing_cleanup_runs: u64,
    pub pairing_cleanup_deleted: u64,
    pub pairing_cleanup_failures: u64,
}

pub struct ServiceMetrics {
    started_at: Instant,
    http_requests: AtomicU64,
    http_client_errors: AtomicU64,
    http_server_errors: AtomicU64,
    rate_limited_requests: AtomicU64,
    readiness_checks: AtomicU64,
    readiness_failures: AtomicU64,
    garbage_collection_runs: AtomicU64,
    garbage_collection_scanned: AtomicU64,
    garbage_collection_deleted: AtomicU64,
    garbage_collection_failures: AtomicU64,
    pairing_cleanup_runs: AtomicU64,
    pairing_cleanup_deleted: AtomicU64,
    pairing_cleanup_failures: AtomicU64,
}

impl Default for ServiceMetrics {
    fn default() -> Self {
        Self {
            started_at: Instant::now(),
            http_requests: AtomicU64::new(0),
            http_client_errors: AtomicU64::new(0),
            http_server_errors: AtomicU64::new(0),
            rate_limited_requests: AtomicU64::new(0),
            readiness_checks: AtomicU64::new(0),
            readiness_failures: AtomicU64::new(0),
            garbage_collection_runs: AtomicU64::new(0),
            garbage_collection_scanned: AtomicU64::new(0),
            garbage_collection_deleted: AtomicU64::new(0),
            garbage_collection_failures: AtomicU64::new(0),
            pairing_cleanup_runs: AtomicU64::new(0),
            pairing_cleanup_deleted: AtomicU64::new(0),
            pairing_cleanup_failures: AtomicU64::new(0),
        }
    }
}

impl ServiceMetrics {
    pub fn observe_http_status(&self, status: u16) {
        self.http_requests.fetch_add(1, Ordering::Relaxed);
        if (400..500).contains(&status) {
            self.http_client_errors.fetch_add(1, Ordering::Relaxed);
        } else if status >= 500 {
            self.http_server_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn observe_readiness(&self, ready: bool) {
        self.readiness_checks.fetch_add(1, Ordering::Relaxed);
        if !ready {
            self.readiness_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn observe_rate_limited(&self) {
        self.rate_limited_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn observe_garbage_collection(&self, scanned: u64, deleted: u64, failures: u64) {
        self.garbage_collection_runs.fetch_add(1, Ordering::Relaxed);
        self.garbage_collection_scanned
            .fetch_add(scanned, Ordering::Relaxed);
        self.garbage_collection_deleted
            .fetch_add(deleted, Ordering::Relaxed);
        self.garbage_collection_failures
            .fetch_add(failures, Ordering::Relaxed);
    }

    pub fn observe_pairing_cleanup(&self, deleted: u64, failed: bool) {
        self.pairing_cleanup_runs.fetch_add(1, Ordering::Relaxed);
        self.pairing_cleanup_deleted
            .fetch_add(deleted, Ordering::Relaxed);
        if failed {
            self.pairing_cleanup_failures
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            uptime_seconds: self.started_at.elapsed().as_secs(),
            http_requests: self.http_requests.load(Ordering::Relaxed),
            http_client_errors: self.http_client_errors.load(Ordering::Relaxed),
            http_server_errors: self.http_server_errors.load(Ordering::Relaxed),
            rate_limited_requests: self.rate_limited_requests.load(Ordering::Relaxed),
            readiness_checks: self.readiness_checks.load(Ordering::Relaxed),
            readiness_failures: self.readiness_failures.load(Ordering::Relaxed),
            garbage_collection_runs: self.garbage_collection_runs.load(Ordering::Relaxed),
            garbage_collection_scanned: self.garbage_collection_scanned.load(Ordering::Relaxed),
            garbage_collection_deleted: self.garbage_collection_deleted.load(Ordering::Relaxed),
            garbage_collection_failures: self.garbage_collection_failures.load(Ordering::Relaxed),
            pairing_cleanup_runs: self.pairing_cleanup_runs.load(Ordering::Relaxed),
            pairing_cleanup_deleted: self.pairing_cleanup_deleted.load(Ordering::Relaxed),
            pairing_cleanup_failures: self.pairing_cleanup_failures.load(Ordering::Relaxed),
        }
    }

    pub fn render_prometheus(&self) -> String {
        let value = self.snapshot();
        format!(
            "# TYPE foliora_sync_uptime_seconds gauge\n\
foliora_sync_uptime_seconds {}\n\
# TYPE foliora_sync_http_requests_total counter\n\
foliora_sync_http_requests_total {}\n\
foliora_sync_http_client_errors_total {}\n\
foliora_sync_http_server_errors_total {}\n\
# TYPE foliora_sync_rate_limited_requests_total counter\n\
foliora_sync_rate_limited_requests_total {}\n\
# TYPE foliora_sync_readiness_checks_total counter\n\
foliora_sync_readiness_checks_total {}\n\
foliora_sync_readiness_failures_total {}\n\
# TYPE foliora_sync_gc_runs_total counter\n\
foliora_sync_gc_runs_total {}\n\
foliora_sync_gc_scanned_total {}\n\
foliora_sync_gc_deleted_total {}\n\
foliora_sync_gc_failures_total {}\n",
            value.uptime_seconds,
            value.http_requests,
            value.http_client_errors,
            value.http_server_errors,
            value.rate_limited_requests,
            value.readiness_checks,
            value.readiness_failures,
            value.garbage_collection_runs,
            value.garbage_collection_scanned,
            value.garbage_collection_deleted,
            value.garbage_collection_failures,
        ) + &format!(
            "# TYPE foliora_sync_pairing_cleanup_runs_total counter\n\
foliora_sync_pairing_cleanup_runs_total {}\n\
foliora_sync_pairing_cleanup_deleted_total {}\n\
foliora_sync_pairing_cleanup_failures_total {}\n",
            value.pairing_cleanup_runs,
            value.pairing_cleanup_deleted,
            value.pairing_cleanup_failures,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_are_aggregate_and_contain_no_tenant_labels() {
        let metrics = ServiceMetrics::default();
        metrics.observe_http_status(204);
        metrics.observe_http_status(404);
        metrics.observe_http_status(503);
        metrics.observe_readiness(false);
        metrics.observe_rate_limited();
        metrics.observe_garbage_collection(7, 2, 1);
        metrics.observe_pairing_cleanup(3, false);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.http_requests, 3);
        assert_eq!(snapshot.http_client_errors, 1);
        assert_eq!(snapshot.http_server_errors, 1);
        assert_eq!(snapshot.rate_limited_requests, 1);
        assert_eq!(snapshot.readiness_failures, 1);
        assert_eq!(snapshot.garbage_collection_deleted, 2);
        assert_eq!(snapshot.pairing_cleanup_deleted, 3);
        let rendered = metrics.render_prometheus();
        assert!(rendered.contains("foliora_sync_gc_failures_total 1"));
        assert!(rendered.contains("foliora_sync_rate_limited_requests_total 1"));
        assert!(!rendered.contains('{'));
    }
}
