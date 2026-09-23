//! Bounded HTTP v1 client for the optional encrypted sync feature.
//!
//! This layer transports protocol objects only. It never accepts epoch keys,
//! plaintext, or arbitrary JSON and it never follows redirects, which avoids
//! accidentally forwarding a bearer token to another origin.

use crate::retry::{delay, retryable_status, safe_to_retry, MAX_ATTEMPTS};
use crate::{
    DeviceRecord, EncryptedObject, SignedManifest, SignedPairingGrant, SyncError,
    MAX_OBJECT_JSON_BYTES,
};
use futures_util::StreamExt;
use reqwest::{header, Method, StatusCode, Url};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::time::Duration;
use zeroize::Zeroizing;

const METADATA_RESPONSE_LIMIT: usize = 4 * 1024 * 1024;
const OBJECT_RESPONSE_LIMIT: usize = MAX_OBJECT_JSON_BYTES;
const MIN_TOKEN_BYTES: usize = 32;
const MAX_TOKEN_BYTES: usize = 512;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Debug)]
pub enum ClientError {
    InvalidEndpoint,
    InsecureEndpoint,
    InvalidToken,
    InvalidPathSegment,
    Transport,
    HttpStatus(StatusCode),
    ResponseTooLarge,
    InvalidResponse,
    Protocol(SyncError),
    Serialize,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidEndpoint => "sync endpoint is invalid",
            Self::InsecureEndpoint => "sync endpoint must use HTTPS",
            Self::InvalidToken => "sync token is invalid",
            Self::InvalidPathSegment => "sync identifier contains unsupported characters",
            Self::Transport => "sync service could not be reached",
            Self::HttpStatus(status) => {
                return write!(formatter, "sync service returned HTTP {status}")
            }
            Self::ResponseTooLarge => "sync response exceeded the configured limit",
            Self::InvalidResponse => "sync service returned an invalid response",
            Self::Protocol(error) => return error.fmt(formatter),
            Self::Serialize => "sync message serialization failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ClientError {}

impl From<SyncError> for ClientError {
    fn from(value: SyncError) -> Self {
        Self::Protocol(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    pub epoch: u64,
    pub used_bytes: u64,
    pub quota_bytes: u64,
    pub heads: Vec<String>,
    pub active_devices: usize,
    #[serde(default)]
    pub object_count: u64,
    #[serde(default)]
    pub manifest_count: u64,
    #[serde(default)]
    pub manifest_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SyncOutcome {
    Inserted,
    AlreadyPresent,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OutcomeResponse {
    outcome: SyncOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub service: String,
    #[serde(rename = "protocolVersion")]
    pub protocol_version: u16,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateVaultRequest<'a> {
    vault_id: &'a str,
    initial_device: &'a DeviceRecord,
    quota_bytes: u64,
    device_token: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PairDeviceRequest<'a> {
    signed_grant: &'a SignedPairingGrant,
    recipient_device_token: &'a str,
    expires_at_unix: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ActivatePairingRequest<'a> {
    confirmation_code: &'a str,
}

pub struct SyncHttpClient {
    endpoint: Url,
    token: Zeroizing<String>,
    http: reqwest::Client,
}

impl SyncHttpClient {
    /// Creates a client for HTTPS. `http://127.0.0.1` and `http://[::1]` are
    /// accepted only when `allow_insecure_loopback` is explicitly true.
    pub fn new(
        endpoint: &str,
        token: impl Into<String>,
        allow_insecure_loopback: bool,
    ) -> Result<Self, ClientError> {
        let token = Zeroizing::new(token.into());
        let endpoint = Url::parse(endpoint.trim()).map_err(|_| ClientError::InvalidEndpoint)?;
        if endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/" && !endpoint.path().is_empty()
        {
            return Err(ClientError::InvalidEndpoint);
        }
        let secure = endpoint.scheme() == "https";
        let loopback = endpoint.scheme() == "http"
            && endpoint.host_str().is_some_and(|host| {
                host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]"
            });
        if !secure && !(allow_insecure_loopback && loopback) {
            return Err(if loopback {
                ClientError::InsecureEndpoint
            } else {
                ClientError::InvalidEndpoint
            });
        }
        validate_token(token.as_str())?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|_| ClientError::Transport)?;
        Ok(Self {
            endpoint,
            token,
            http,
        })
    }

    pub async fn health(&self) -> Result<HealthResponse, ClientError> {
        self.send(
            Method::GET,
            "/healthz",
            None::<&()>,
            METADATA_RESPONSE_LIMIT,
            false,
        )
        .await
    }

    pub async fn create_vault(
        &self,
        bootstrap_token: &str,
        vault_id: &str,
        initial_device: &DeviceRecord,
        quota_bytes: u64,
        device_token: &str,
    ) -> Result<(), ClientError> {
        validate_token(bootstrap_token)?;
        validate_token(device_token)?;
        let payload = CreateVaultRequest {
            vault_id,
            initial_device,
            quota_bytes,
            device_token,
        };
        self.send_with_token(
            Method::POST,
            "/v1/vaults",
            Some(&payload),
            METADATA_RESPONSE_LIMIT,
            bootstrap_token,
        )
        .await
        .map(|_: serde_json::Value| ())
    }

    pub async fn status(&self, vault_id: &str) -> Result<VaultStatus, ClientError> {
        let status: VaultStatus = self
            .send(
                Method::GET,
                &path("/v1/vaults", vault_id, "status")?,
                None::<&()>,
                METADATA_RESPONSE_LIMIT,
                true,
            )
            .await?;
        if status.epoch == 0
            || status.quota_bytes == 0
            || status.used_bytes > status.quota_bytes
            || status.heads.len() > 32
            || !status.heads.windows(2).all(|pair| pair[0] < pair[1])
            || !status
                .heads
                .iter()
                .all(|head| valid_hash_id(head, "revision:"))
        {
            return Err(ClientError::InvalidResponse);
        }
        Ok(status)
    }

    pub async fn pair_device(
        &self,
        vault_id: &str,
        signed_grant: &SignedPairingGrant,
        recipient_device_token: &str,
        expires_at_unix: u64,
    ) -> Result<(), ClientError> {
        validate_segment(vault_id)?;
        validate_token(recipient_device_token)?;
        let payload = PairDeviceRequest {
            signed_grant,
            recipient_device_token,
            expires_at_unix,
        };
        self.send(
            Method::POST,
            &format!("/v1/vaults/{vault_id}/pairings"),
            Some(&payload),
            METADATA_RESPONSE_LIMIT,
            true,
        )
        .await
        .map(|_: serde_json::Value| ())
    }

    pub async fn activate_pairing(
        &self,
        vault_id: &str,
        confirmation_code: &str,
    ) -> Result<(), ClientError> {
        validate_segment(vault_id)?;
        let payload = ActivatePairingRequest { confirmation_code };
        self.send(
            Method::POST,
            &format!("/v1/vaults/{vault_id}/pairings/activate"),
            Some(&payload),
            METADATA_RESPONSE_LIMIT,
            true,
        )
        .await
        .map(|_: serde_json::Value| ())
    }

    pub async fn revoke_device(&self, vault_id: &str, device_id: &str) -> Result<u64, ClientError> {
        validate_segment(vault_id)?;
        validate_segment(device_id)?;
        let response: serde_json::Value = self
            .send(
                Method::DELETE,
                &format!("/v1/vaults/{vault_id}/devices/{device_id}"),
                None::<&()>,
                METADATA_RESPONSE_LIMIT,
                true,
            )
            .await?;
        response
            .get("epoch")
            .and_then(serde_json::Value::as_u64)
            .ok_or(ClientError::InvalidResponse)
    }

    pub async fn get_device_authorization(
        &self,
        vault_id: &str,
        device_id: &str,
    ) -> Result<SignedPairingGrant, ClientError> {
        validate_segment(vault_id)?;
        validate_segment(device_id)?;
        let grant: SignedPairingGrant = self
            .send(
                Method::GET,
                &format!("/v1/vaults/{vault_id}/devices/{device_id}"),
                None::<&()>,
                METADATA_RESPONSE_LIMIT,
                true,
            )
            .await?;
        grant.grant.validate()?;
        if grant.grant.vault_id != vault_id || grant.grant.recipient.device_id != device_id {
            return Err(ClientError::InvalidResponse);
        }
        Ok(grant)
    }

    pub async fn upload_object(
        &self,
        object: &EncryptedObject,
    ) -> Result<SyncOutcome, ClientError> {
        object.validate()?;
        validate_segment(&object.vault_id)?;
        validate_segment(&object.object_id)?;
        let path = format!(
            "/v1/vaults/{}/objects/{}",
            object.vault_id, object.object_id
        );
        let response: OutcomeResponse = self
            .send(
                Method::PUT,
                &path,
                Some(object),
                OBJECT_RESPONSE_LIMIT,
                true,
            )
            .await?;
        Ok(response.outcome)
    }

    pub async fn get_object(
        &self,
        vault_id: &str,
        object_id: &str,
    ) -> Result<EncryptedObject, ClientError> {
        validate_segment(vault_id)?;
        validate_segment(object_id)?;
        let object: EncryptedObject = self
            .send(
                Method::GET,
                &format!("/v1/vaults/{vault_id}/objects/{object_id}"),
                None::<&()>,
                OBJECT_RESPONSE_LIMIT,
                true,
            )
            .await?;
        object.validate()?;
        if object.vault_id != vault_id || object.object_id != object_id {
            return Err(ClientError::InvalidResponse);
        }
        Ok(object)
    }

    pub async fn commit_manifest(
        &self,
        manifest: &SignedManifest,
    ) -> Result<SyncOutcome, ClientError> {
        manifest.manifest.validate()?;
        let path = format!(
            "/v1/vaults/{}/manifests/{}",
            manifest.manifest.vault_id, manifest.manifest.revision_id
        );
        let response: OutcomeResponse = self
            .send(
                Method::PUT,
                &path,
                Some(manifest),
                METADATA_RESPONSE_LIMIT,
                true,
            )
            .await?;
        Ok(response.outcome)
    }

    pub async fn get_manifest(
        &self,
        vault_id: &str,
        revision_id: &str,
    ) -> Result<SignedManifest, ClientError> {
        validate_segment(vault_id)?;
        validate_segment(revision_id)?;
        let manifest: SignedManifest = self
            .send(
                Method::GET,
                &format!("/v1/vaults/{vault_id}/manifests/{revision_id}"),
                None::<&()>,
                METADATA_RESPONSE_LIMIT,
                true,
            )
            .await?;
        manifest.manifest.validate()?;
        if manifest.manifest.vault_id != vault_id || manifest.manifest.revision_id != revision_id {
            return Err(ClientError::InvalidResponse);
        }
        Ok(manifest)
    }

    async fn send<T, R>(
        &self,
        method: Method,
        path: &str,
        body: Option<&T>,
        limit: usize,
        authenticate: bool,
    ) -> Result<R, ClientError>
    where
        T: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        if authenticate {
            self.send_with_token(method, path, body, limit, self.token.as_str())
                .await
        } else {
            self.send_with_token(method, path, body, limit, "").await
        }
    }

    async fn send_with_token<T, R>(
        &self,
        method: Method,
        path: &str,
        body: Option<&T>,
        limit: usize,
        token: &str,
    ) -> Result<R, ClientError>
    where
        T: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let url = self
            .endpoint
            .join(path.trim_start_matches('/'))
            .map_err(|_| ClientError::InvalidEndpoint)?;
        let body = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| ClientError::Serialize)?
            .map(Zeroizing::new);
        let retry_safe = safe_to_retry(&method, path);
        let operation = async {
            for attempt in 0..MAX_ATTEMPTS {
                let mut request = self.http.request(method.clone(), url.clone());
                if !token.is_empty() {
                    request = request.bearer_auth(token);
                }
                if let Some(body) = &body {
                    request = request
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(body.to_vec());
                }
                let response = match request.send().await {
                    Ok(response) => response,
                    Err(_) if retry_safe && attempt + 1 < MAX_ATTEMPTS => {
                        tokio::time::sleep(delay(None, attempt)).await;
                        continue;
                    }
                    Err(_) => return Err(ClientError::Transport),
                };
                let status = response.status();
                if retry_safe && retryable_status(status) && attempt + 1 < MAX_ATTEMPTS {
                    let wait = delay(Some(response.headers()), attempt);
                    drop(response);
                    tokio::time::sleep(wait).await;
                    continue;
                }
                if status == StatusCode::NO_CONTENT {
                    return serde_json::from_slice(b"null")
                        .map_err(|_| ClientError::InvalidResponse);
                }
                if !status.is_success() {
                    return Err(ClientError::HttpStatus(status));
                }
                let bytes = match bounded_bytes(response, limit).await {
                    Ok(bytes) => bytes,
                    Err(ClientError::Transport) if retry_safe && attempt + 1 < MAX_ATTEMPTS => {
                        tokio::time::sleep(delay(None, attempt)).await;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                return serde_json::from_slice(&bytes).map_err(|_| ClientError::InvalidResponse);
            }
            Err(ClientError::Transport)
        };
        tokio::time::timeout(OPERATION_TIMEOUT, operation)
            .await
            .map_err(|_| ClientError::Transport)?
    }
}

async fn bounded_bytes(response: reqwest::Response, limit: usize) -> Result<Vec<u8>, ClientError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(ClientError::ResponseTooLarge);
    }
    let mut stream = response.bytes_stream();
    let mut result = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ClientError::Transport)?;
        if result
            .len()
            .checked_add(chunk.len())
            .is_none_or(|size| size > limit)
        {
            return Err(ClientError::ResponseTooLarge);
        }
        result.extend_from_slice(&chunk);
    }
    Ok(result)
}

fn path(prefix: &str, first: &str, suffix: &str) -> Result<String, ClientError> {
    validate_segment(first)?;
    Ok(format!("{prefix}/{first}/{suffix}"))
}

fn validate_segment(value: &str) -> Result<(), ClientError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'/' | b'\\' | b'?' | b'#'))
    {
        Err(ClientError::InvalidPathSegment)
    } else {
        Ok(())
    }
}

fn validate_token(token: &str) -> Result<(), ClientError> {
    if token.len() < MIN_TOKEN_BYTES
        || token.len() > MAX_TOKEN_BYTES
        || token.chars().any(char::is_whitespace)
    {
        Err(ClientError::InvalidToken)
    } else {
        Ok(())
    }
}

fn valid_hash_id(value: &str, prefix: &str) -> bool {
    value.len() == prefix.len() + 64
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceIdentity;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const TOKEN: &str = "client-token-with-at-least-32-bytes-long";

    #[test]
    fn endpoint_policy_requires_tls_or_explicit_loopback_http() {
        assert!(SyncHttpClient::new("https://sync.example", TOKEN, false).is_ok());
        assert!(matches!(
            SyncHttpClient::new("http://127.0.0.1:8787", TOKEN, false),
            Err(ClientError::InsecureEndpoint)
        ));
        assert!(SyncHttpClient::new("http://127.0.0.1:8787", TOKEN, true).is_ok());
        assert!(matches!(
            SyncHttpClient::new("http://10.0.0.2:8787", TOKEN, true),
            Err(ClientError::InvalidEndpoint)
        ));
        assert!(SyncHttpClient::new("https://sync.example/?token=secret", TOKEN, false).is_err());
    }

    #[test]
    fn identifiers_cannot_escape_the_api_path() {
        assert!(path("/v1/vaults", "vault:ok", "status").is_ok());
        assert!(path("/v1/vaults", "vault:bad/id", "status").is_err());
        assert!(path("/v1/vaults", "vault:bad?x", "status").is_err());
    }

    #[tokio::test]
    async fn response_limit_rejects_chunked_body_without_content_length() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await;
            let body = "{".to_owned() + &"x".repeat(METADATA_RESPONSE_LIMIT + 1) + "}";
            let response = format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        let client = SyncHttpClient::new(&format!("http://{address}"), TOKEN, true).unwrap();
        assert!(matches!(
            client.health().await,
            Err(ClientError::ResponseTooLarge)
        ));
    }

    #[tokio::test]
    async fn temporary_get_failure_is_retried_then_succeeds() {
        let body = r#"{"status":"ok","service":"foliora-sync","protocolVersion":1}"#;
        let first = temporary_response();
        let second = json_response(StatusCode::OK, body);
        let (address, server) = serve(vec![first, second]).await;
        let client = SyncHttpClient::new(&format!("http://{address}"), TOKEN, true).unwrap();

        let health = client.health().await.unwrap();
        assert_eq!(health.status, "ok");
        assert_eq!(server.await.unwrap(), 2);
    }

    #[tokio::test]
    async fn dropped_get_connection_is_retried_after_partition() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let _ = first.read(&mut request).await;
            drop(first);
            let (mut second, _) = listener.accept().await.unwrap();
            let _ = second.read(&mut request).await;
            let body = r#"{"status":"ok","service":"foliora-sync","protocolVersion":1}"#;
            second
                .write_all(json_response(StatusCode::OK, body).as_bytes())
                .await
                .unwrap();
        });
        let client = SyncHttpClient::new(&format!("http://{address}"), TOKEN, true).unwrap();

        assert_eq!(client.health().await.unwrap().status, "ok");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn authentication_failure_is_never_retried() {
        let (address, server) = serve(vec![json_response(StatusCode::UNAUTHORIZED, "")]).await;
        let client = SyncHttpClient::new(&format!("http://{address}"), TOKEN, true).unwrap();

        assert!(matches!(
            client.status("vault:0123456789abcdef").await,
            Err(ClientError::HttpStatus(StatusCode::UNAUTHORIZED))
        ));
        assert_eq!(server.await.unwrap(), 1);
    }

    #[tokio::test]
    async fn status_rejects_unbounded_or_noncanonical_server_heads() {
        let revision = format!("revision:{}", "a".repeat(64));
        let malformed = [
            r#"{"epoch":0,"usedBytes":0,"quotaBytes":1,"heads":[],"activeDevices":1}"#.to_string(),
            format!(
                r#"{{"epoch":1,"usedBytes":0,"quotaBytes":1,"heads":["{revision}","{revision}"],"activeDevices":1}}"#
            ),
            r#"{"epoch":1,"usedBytes":2,"quotaBytes":1,"heads":[],"activeDevices":1}"#.to_string(),
        ];

        for body in malformed {
            let (address, server) = serve(vec![json_response(StatusCode::OK, &body)]).await;
            let client = SyncHttpClient::new(&format!("http://{address}"), TOKEN, true).unwrap();
            assert!(matches!(
                client.status("vault:0123456789abcdef").await,
                Err(ClientError::InvalidResponse)
            ));
            assert_eq!(server.await.unwrap(), 1);
        }
    }

    #[tokio::test]
    async fn non_idempotent_create_vault_is_never_retried() {
        let (address, server) = serve(vec![temporary_response()]).await;
        let client = SyncHttpClient::new(&format!("http://{address}"), TOKEN, true).unwrap();
        let identity = DeviceIdentity::generate().unwrap();
        let device = identity.record("Owner").unwrap();

        assert!(matches!(
            client
                .create_vault(
                    "bootstrap-token-with-at-least-32-bytes",
                    "vault:0123456789abcdef",
                    &device,
                    1024,
                    "device-token-with-at-least-32-bytes"
                )
                .await,
            Err(ClientError::HttpStatus(StatusCode::SERVICE_UNAVAILABLE))
        ));
        assert_eq!(server.await.unwrap(), 1);
    }

    #[tokio::test]
    async fn non_idempotent_pairing_registration_is_never_retried() {
        let (address, server) = serve(vec![temporary_response()]).await;
        let client = SyncHttpClient::new(&format!("http://{address}"), TOKEN, true).unwrap();
        let result: Result<serde_json::Value, ClientError> = client
            .send(
                Method::POST,
                "/v1/vaults/vault:1/pairings",
                Some(&serde_json::json!({"pairingCode":"1234-5678"})),
                METADATA_RESPONSE_LIMIT,
                true,
            )
            .await;

        assert!(matches!(
            result,
            Err(ClientError::HttpStatus(StatusCode::SERVICE_UNAVAILABLE))
        ));
        assert_eq!(server.await.unwrap(), 1);
    }

    #[tokio::test]
    async fn crash_safe_pairing_activation_retries_temporary_failure() {
        let responses = vec![
            temporary_response(),
            json_response(StatusCode::OK, r#"{"activated":true}"#),
        ];
        let (address, server) = serve(responses).await;
        let client = SyncHttpClient::new(&format!("http://{address}"), TOKEN, true).unwrap();

        client
            .activate_pairing("vault:0123456789abcdef", "1234-5678")
            .await
            .unwrap();
        assert_eq!(server.await.unwrap(), 2);
    }

    #[tokio::test]
    async fn retry_budget_is_three_and_request_body_is_serialized_once() {
        struct CountingBody(Arc<AtomicUsize>);
        impl Serialize for CountingBody {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.0.fetch_add(1, Ordering::Relaxed);
                serializer.serialize_str("opaque")
            }
        }

        let (address, server) = serve(vec![
            temporary_response(),
            temporary_response(),
            temporary_response(),
        ])
        .await;
        let client = SyncHttpClient::new(&format!("http://{address}"), TOKEN, true).unwrap();
        let serializations = Arc::new(AtomicUsize::new(0));
        let result: Result<serde_json::Value, ClientError> = client
            .send(
                Method::PUT,
                "/v1/vaults/vault:1/objects/object:1",
                Some(&CountingBody(Arc::clone(&serializations))),
                METADATA_RESPONSE_LIMIT,
                true,
            )
            .await;

        assert!(matches!(
            result,
            Err(ClientError::HttpStatus(StatusCode::SERVICE_UNAVAILABLE))
        ));
        assert_eq!(server.await.unwrap(), MAX_ATTEMPTS);
        assert_eq!(serializations.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn revoke_delete_is_never_retried() {
        let (address, server) = serve(vec![temporary_response()]).await;
        let client = SyncHttpClient::new(&format!("http://{address}"), TOKEN, true).unwrap();
        let result: Result<serde_json::Value, ClientError> = client
            .send(
                Method::DELETE,
                "/v1/vaults/vault:1/devices/device:2",
                None::<&()>,
                METADATA_RESPONSE_LIMIT,
                true,
            )
            .await;

        assert!(matches!(
            result,
            Err(ClientError::HttpStatus(StatusCode::SERVICE_UNAVAILABLE))
        ));
        assert_eq!(server.await.unwrap(), 1);
    }

    async fn serve(
        responses: Vec<String>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut served = 0;
            for response in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 4096];
                let _ = socket.read(&mut request).await;
                socket.write_all(response.as_bytes()).await.unwrap();
                served += 1;
            }
            served
        });
        (address, server)
    }

    fn temporary_response() -> String {
        concat!(
            "HTTP/1.1 503 Service Unavailable\r\n",
            "Content-Length: 0\r\n",
            "Retry-After: 0\r\n",
            "Connection: close\r\n\r\n"
        )
        .to_owned()
    }

    fn json_response(status: StatusCode, body: &str) -> String {
        format!(
            "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status.as_u16(),
            status.canonical_reason().unwrap_or("Unknown"),
            body.len(),
            body
        )
    }
}
