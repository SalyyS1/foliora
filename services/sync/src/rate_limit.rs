use axum::http::{header::AUTHORIZATION, HeaderMap};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

pub const DEFAULT_PER_CREDENTIAL_PER_MINUTE: u32 = 240;
pub const DEFAULT_PER_CREDENTIAL_BURST: u32 = 60;
pub const DEFAULT_GLOBAL_PER_MINUTE: u32 = 6_000;
pub const DEFAULT_GLOBAL_BURST: u32 = 600;
pub const DEFAULT_MAX_CREDENTIALS: usize = 10_000;
const IDLE_CREDENTIAL_TTL: Duration = Duration::from_secs(10 * 60);
const MIN_TOKEN_BYTES: usize = 32;
const MAX_TOKEN_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitConfig {
    pub per_credential_per_minute: u32,
    pub per_credential_burst: u32,
    pub global_per_minute: u32,
    pub global_burst: u32,
    pub max_credentials: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_credential_per_minute: DEFAULT_PER_CREDENTIAL_PER_MINUTE,
            per_credential_burst: DEFAULT_PER_CREDENTIAL_BURST,
            global_per_minute: DEFAULT_GLOBAL_PER_MINUTE,
            global_burst: DEFAULT_GLOBAL_BURST,
            max_credentials: DEFAULT_MAX_CREDENTIALS,
        }
    }
}

impl RateLimitConfig {
    pub fn validate(self) -> Result<Self, String> {
        if self.per_credential_per_minute == 0
            || self.per_credential_burst == 0
            || self.global_per_minute == 0
            || self.global_burst == 0
            || self.max_credentials == 0
        {
            return Err("rate-limit values must be positive".into());
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RateLimitError {
    Limited { retry_after_seconds: u64 },
    Unavailable,
}

pub(crate) struct RateLimiter {
    config: RateLimitConfig,
    state: Mutex<LimiterState>,
}

struct LimiterState {
    global: Bucket,
    anonymous: Bucket,
    overflow: Bucket,
    credentials: HashMap<[u8; 32], CredentialBucket>,
}

struct CredentialBucket {
    bucket: Bucket,
    last_seen: Instant,
}

struct Bucket {
    tokens: f64,
    updated_at: Instant,
}

#[derive(Clone, Copy)]
enum ClientBucket {
    Anonymous,
    Credential([u8; 32]),
    Overflow,
}

impl RateLimiter {
    pub(crate) fn new(config: RateLimitConfig) -> Result<Self, String> {
        let config = config.validate()?;
        let now = Instant::now();
        Ok(Self {
            config,
            state: Mutex::new(LimiterState {
                global: Bucket::full(config.global_burst, now),
                anonymous: Bucket::full(config.per_credential_burst, now),
                overflow: Bucket::full(config.per_credential_burst, now),
                credentials: HashMap::new(),
            }),
        })
    }

    pub(crate) fn check(&self, headers: &HeaderMap) -> Result<(), RateLimitError> {
        self.check_at(headers, Instant::now())
    }

    fn check_at(&self, headers: &HeaderMap, now: Instant) -> Result<(), RateLimitError> {
        let credential = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|token| validate_token(token).is_ok())
            .map(token_hash);
        let mut state = self.state.lock().map_err(|_| RateLimitError::Unavailable)?;

        let global_wait =
            state
                .global
                .retry_after(self.config.global_per_minute, self.config.global_burst, now);
        let target = match credential {
            None => ClientBucket::Anonymous,
            Some(hash) if state.credentials.contains_key(&hash) => ClientBucket::Credential(hash),
            Some(hash) => {
                if state.credentials.len() >= self.config.max_credentials {
                    state.credentials.retain(|_, entry| {
                        now.checked_duration_since(entry.last_seen)
                            .unwrap_or_default()
                            < IDLE_CREDENTIAL_TTL
                    });
                }
                if state.credentials.len() >= self.config.max_credentials {
                    ClientBucket::Overflow
                } else {
                    state.credentials.insert(
                        hash,
                        CredentialBucket {
                            bucket: Bucket::full(self.config.per_credential_burst, now),
                            last_seen: now,
                        },
                    );
                    ClientBucket::Credential(hash)
                }
            }
        };
        let client_wait = match target {
            ClientBucket::Anonymous => state.anonymous.retry_after(
                self.config.per_credential_per_minute,
                self.config.per_credential_burst,
                now,
            ),
            ClientBucket::Credential(hash) => {
                let entry = state
                    .credentials
                    .get_mut(&hash)
                    .expect("credential bucket was inserted before use");
                entry.last_seen = now;
                entry.bucket.retry_after(
                    self.config.per_credential_per_minute,
                    self.config.per_credential_burst,
                    now,
                )
            }
            ClientBucket::Overflow => state.overflow.retry_after(
                self.config.per_credential_per_minute,
                self.config.per_credential_burst,
                now,
            ),
        };

        if let Some(wait) = [global_wait, client_wait].into_iter().flatten().max() {
            return Err(RateLimitError::Limited {
                retry_after_seconds: (wait.as_secs_f64().ceil() as u64).max(1),
            });
        }

        state.global.consume();
        match target {
            ClientBucket::Anonymous => state.anonymous.consume(),
            ClientBucket::Credential(hash) => state
                .credentials
                .get_mut(&hash)
                .expect("credential bucket was inserted before use")
                .bucket
                .consume(),
            ClientBucket::Overflow => state.overflow.consume(),
        }
        Ok(())
    }
}

pub(crate) fn validate_token(token: &str) -> Result<(), String> {
    if token.len() < MIN_TOKEN_BYTES
        || token.len() > MAX_TOKEN_BYTES
        || token.chars().any(char::is_whitespace)
    {
        Err("token must contain 32 to 512 non-whitespace bytes".into())
    } else {
        Ok(())
    }
}

pub(crate) fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

impl Bucket {
    fn full(capacity: u32, now: Instant) -> Self {
        Self {
            tokens: f64::from(capacity),
            updated_at: now,
        }
    }

    fn retry_after(&mut self, per_minute: u32, capacity: u32, now: Instant) -> Option<Duration> {
        let elapsed = now
            .checked_duration_since(self.updated_at)
            .unwrap_or_default()
            .as_secs_f64();
        let refill_per_second = f64::from(per_minute) / 60.0;
        self.tokens = (self.tokens + elapsed * refill_per_second).min(f64::from(capacity));
        self.updated_at = now;
        if self.tokens >= 1.0 {
            None
        } else {
            Some(Duration::from_secs_f64(
                ((1.0 - self.tokens) / refill_per_second).max(0.001),
            ))
        }
    }

    fn consume(&mut self) {
        self.tokens = (self.tokens - 1.0).max(0.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const TOKEN_A: &str = "Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TOKEN_B: &str = "Bearer bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const TOKEN_C: &str = "Bearer cccccccccccccccccccccccccccccccc";

    fn config() -> RateLimitConfig {
        RateLimitConfig {
            per_credential_per_minute: 60,
            per_credential_burst: 2,
            global_per_minute: 600,
            global_burst: 10,
            max_credentials: 2,
        }
    }

    fn headers(token: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(token) = token {
            headers.insert(AUTHORIZATION, HeaderValue::from_str(token).unwrap());
        }
        headers
    }

    #[test]
    fn credential_budget_refills_and_reports_a_bounded_wait() {
        let limiter = RateLimiter::new(config()).unwrap();
        let now = Instant::now();
        let headers = headers(Some(TOKEN_A));
        assert_eq!(limiter.check_at(&headers, now), Ok(()));
        assert_eq!(limiter.check_at(&headers, now), Ok(()));
        assert_eq!(
            limiter.check_at(&headers, now),
            Err(RateLimitError::Limited {
                retry_after_seconds: 1
            })
        );
        assert_eq!(
            limiter.check_at(&headers, now + Duration::from_secs(1)),
            Ok(())
        );
    }

    #[test]
    fn rotating_credentials_cannot_bypass_the_global_budget() {
        let limiter = RateLimiter::new(RateLimitConfig {
            global_burst: 2,
            ..config()
        })
        .unwrap();
        let now = Instant::now();
        assert_eq!(limiter.check_at(&headers(Some(TOKEN_A)), now), Ok(()));
        assert_eq!(limiter.check_at(&headers(Some(TOKEN_B)), now), Ok(()));
        assert!(matches!(
            limiter.check_at(&headers(Some(TOKEN_C)), now),
            Err(RateLimitError::Limited { .. })
        ));
    }

    #[test]
    fn credential_table_is_bounded_and_uses_a_shared_overflow_bucket() {
        let limiter = RateLimiter::new(RateLimitConfig {
            per_credential_burst: 1,
            max_credentials: 1,
            ..config()
        })
        .unwrap();
        let now = Instant::now();
        assert_eq!(limiter.check_at(&headers(Some(TOKEN_A)), now), Ok(()));
        assert_eq!(limiter.check_at(&headers(Some(TOKEN_B)), now), Ok(()));
        assert!(matches!(
            limiter.check_at(&headers(Some(TOKEN_C)), now),
            Err(RateLimitError::Limited { .. })
        ));
        assert_eq!(limiter.state.lock().unwrap().credentials.len(), 1);
    }

    #[test]
    fn invalid_configuration_fails_closed() {
        assert!(RateLimiter::new(RateLimitConfig {
            per_credential_burst: 0,
            ..config()
        })
        .is_err());
    }

    #[test]
    fn rotating_malformed_bearers_share_the_anonymous_budget() {
        let limiter = RateLimiter::new(RateLimitConfig {
            per_credential_burst: 1,
            ..config()
        })
        .unwrap();
        let now = Instant::now();
        assert_eq!(
            limiter.check_at(&headers(Some("Bearer short-a")), now),
            Ok(())
        );
        assert!(matches!(
            limiter.check_at(&headers(Some("Bearer short-b")), now),
            Err(RateLimitError::Limited { .. })
        ));
        assert!(limiter.state.lock().unwrap().credentials.is_empty());
    }
}
