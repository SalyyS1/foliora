use reqwest::{header::HeaderMap, Method, StatusCode};
use std::time::Duration;

pub(crate) const MAX_ATTEMPTS: usize = 3;
const MAX_RETRY_AFTER_SECONDS: u64 = 5;

pub(crate) fn safe_to_retry(method: &Method, path: &str) -> bool {
    method == Method::GET
        || method == Method::PUT
        || method == Method::POST && path.ends_with("/pairings/activate")
}

pub(crate) fn retryable_status(status: StatusCode) -> bool {
    status.is_server_error()
        || matches!(
            status,
            StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_EARLY | StatusCode::TOO_MANY_REQUESTS
        )
}

pub(crate) fn delay(headers: Option<&HeaderMap>, failed_attempt: usize) -> Duration {
    if let Some(seconds) = headers
        .and_then(|values| values.get(reqwest::header::RETRY_AFTER))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
    {
        return Duration::from_secs(seconds.min(MAX_RETRY_AFTER_SECONDS));
    }
    Duration::from_millis(match failed_attempt {
        0 => 100,
        1 => 300,
        _ => 900,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_policy_is_limited_to_proven_idempotent_operations() {
        assert!(safe_to_retry(&Method::GET, "/healthz"));
        assert!(safe_to_retry(&Method::PUT, "/v1/vaults/v/objects/o"));
        assert!(safe_to_retry(
            &Method::POST,
            "/v1/vaults/v/pairings/activate"
        ));
        assert!(!safe_to_retry(&Method::POST, "/v1/vaults"));
        assert!(!safe_to_retry(&Method::POST, "/v1/vaults/v/pairings"));
        assert!(!safe_to_retry(&Method::DELETE, "/v1/vaults/v/devices/d"));
    }

    #[test]
    fn retryable_statuses_exclude_auth_conflict_and_validation_failures() {
        for status in [
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::TOO_EARLY,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::NOT_IMPLEMENTED,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
            StatusCode::INSUFFICIENT_STORAGE,
        ] {
            assert!(retryable_status(status));
        }
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::CONFLICT,
        ] {
            assert!(!retryable_status(status));
        }
    }

    #[test]
    fn retry_after_is_bounded() {
        let mut headers = HeaderMap::new();
        headers.insert(reqwest::header::RETRY_AFTER, "9999".parse().unwrap());
        assert_eq!(delay(Some(&headers), 0), Duration::from_secs(5));
        headers.insert(reqwest::header::RETRY_AFTER, "0".parse().unwrap());
        assert_eq!(delay(Some(&headers), 0), Duration::ZERO);
    }
}
