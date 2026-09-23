use crate::{
    metrics::ServiceMetrics,
    rate_limit::{token_hash, validate_token, RateLimitConfig, RateLimitError, RateLimiter},
    repository::{MemoryRepository, Principal, RepositoryError, SyncRepository},
    ServiceError, StoreOutcome,
};
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, FromRequest, Path, State},
    http::{
        header::{AUTHORIZATION, CACHE_CONTROL, RETRY_AFTER},
        HeaderMap, HeaderValue, Request, StatusCode,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use foliora_sync::{
    DeviceRecord, EncryptedObject, SignedManifest, SignedPairingGrant, MAX_OBJECT_JSON_BYTES,
};
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const METADATA_BODY_LIMIT: usize = 4 * 1024 * 1024;
const OBJECT_BODY_LIMIT: usize = MAX_OBJECT_JSON_BYTES;
pub const DEFAULT_MAX_VAULT_BYTES: u64 = 10 * 1024 * 1024 * 1024;
pub const DEFAULT_REQUEST_DEADLINE: Duration = Duration::from_secs(120);
pub const DEFAULT_OBJECT_CONCURRENCY: usize = 32;
const MAX_REQUEST_DEADLINE: Duration = Duration::from_secs(10 * 60);
const MAX_OBJECT_CONCURRENCY: usize = 1_024;

#[derive(Clone)]
pub struct ApiState {
    repository: Arc<dyn SyncRepository>,
    bootstrap_hash: [u8; 32],
    metrics: Arc<ServiceMetrics>,
    max_vault_bytes: u64,
    rate_limiter: Arc<RateLimiter>,
    request_deadline: Duration,
    object_transfers: Arc<Semaphore>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateVaultRequest {
    vault_id: String,
    initial_device: DeviceRecord,
    quota_bytes: u64,
    device_token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PairDeviceRequest {
    signed_grant: SignedPairingGrant,
    recipient_device_token: String,
    expires_at_unix: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActivatePairingRequest {
    confirmation_code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OutcomeResponse {
    outcome: StoreOutcome,
}

impl ApiState {
    pub fn new(bootstrap_token: &str) -> Result<Self, String> {
        Self::with_repository(bootstrap_token, Arc::new(MemoryRepository::default()))
    }

    pub fn with_repository(
        bootstrap_token: &str,
        repository: Arc<dyn SyncRepository>,
    ) -> Result<Self, String> {
        Self::with_repository_and_metrics(
            bootstrap_token,
            repository,
            Arc::new(ServiceMetrics::default()),
        )
    }

    pub fn with_repository_and_metrics(
        bootstrap_token: &str,
        repository: Arc<dyn SyncRepository>,
        metrics: Arc<ServiceMetrics>,
    ) -> Result<Self, String> {
        Self::with_repository_metrics_and_limit(
            bootstrap_token,
            repository,
            metrics,
            DEFAULT_MAX_VAULT_BYTES,
        )
    }

    pub fn with_repository_metrics_and_limit(
        bootstrap_token: &str,
        repository: Arc<dyn SyncRepository>,
        metrics: Arc<ServiceMetrics>,
        max_vault_bytes: u64,
    ) -> Result<Self, String> {
        validate_token(bootstrap_token)?;
        if max_vault_bytes == 0 || max_vault_bytes > i64::MAX as u64 {
            return Err("maximum vault quota must fit a positive PostgreSQL BIGINT".into());
        }
        Ok(Self {
            repository,
            bootstrap_hash: token_hash(bootstrap_token),
            metrics,
            max_vault_bytes,
            rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig::default())?),
            request_deadline: DEFAULT_REQUEST_DEADLINE,
            object_transfers: Arc::new(Semaphore::new(DEFAULT_OBJECT_CONCURRENCY)),
        })
    }

    pub fn with_rate_limit(mut self, config: RateLimitConfig) -> Result<Self, String> {
        self.rate_limiter = Arc::new(RateLimiter::new(config)?);
        Ok(self)
    }

    pub fn with_resource_limits(
        mut self,
        request_deadline: Duration,
        object_concurrency: usize,
    ) -> Result<Self, String> {
        if request_deadline.is_zero() || request_deadline > MAX_REQUEST_DEADLINE {
            return Err("request deadline must be between 1 ns and 10 minutes".into());
        }
        if object_concurrency == 0 || object_concurrency > MAX_OBJECT_CONCURRENCY {
            return Err("object concurrency must be between 1 and 1024".into());
        }
        self.request_deadline = request_deadline;
        self.object_transfers = Arc::new(Semaphore::new(object_concurrency));
        Ok(self)
    }
}

pub fn router(state: ApiState) -> Router {
    let metrics = state.metrics.clone();
    let limiter_state = state.clone();
    let resource_state = state.clone();
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/metrics", get(metrics_endpoint))
        .route("/v1/vaults", post(create_vault))
        .route("/v1/vaults/{vault_id}/status", get(status))
        .route("/v1/vaults/{vault_id}/pairings", post(pair_device))
        .route(
            "/v1/vaults/{vault_id}/pairings/activate",
            post(activate_pairing),
        )
        .route(
            "/v1/vaults/{vault_id}/devices/{device_id}",
            delete(revoke_device).get(get_device_authorization),
        )
        .route(
            "/v1/vaults/{vault_id}/objects/{object_id}",
            put(upload_object)
                .get(get_object)
                .layer(DefaultBodyLimit::max(OBJECT_BODY_LIMIT)),
        )
        .route(
            "/v1/vaults/{vault_id}/manifests/{revision_id}",
            put(commit_manifest).get(get_manifest),
        )
        .layer(DefaultBodyLimit::max(METADATA_BODY_LIMIT))
        .layer(middleware::from_fn_with_state(
            limiter_state,
            enforce_rate_limit,
        ))
        .layer(middleware::from_fn_with_state(
            resource_state,
            enforce_resource_limits,
        ))
        .layer(middleware::from_fn_with_state(metrics, observe_request))
        .with_state(state)
}

async fn health() -> Json<Value> {
    Json(json!({"status": "ok", "service": crate::SERVICE_NAME, "protocolVersion": 1}))
}

async fn ready(State(state): State<ApiState>) -> Result<Json<Value>, ApiError> {
    let result = state.repository.ready().await;
    state.metrics.observe_readiness(result.is_ok());
    result.map_err(ApiError::repository)?;
    Ok(Json(json!({"status": "ready"})))
}

async fn metrics_endpoint(State(state): State<ApiState>) -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.metrics.render_prometheus(),
    )
}

async fn observe_request(
    State(metrics): State<Arc<ServiceMetrics>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let response = next.run(request).await;
    metrics.observe_http_status(response.status().as_u16());
    response
}

async fn enforce_rate_limit(
    State(state): State<ApiState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if !request.uri().path().starts_with("/v1/") {
        return next.run(request).await;
    }
    match state.rate_limiter.check(request.headers()) {
        Ok(()) => next.run(request).await,
        Err(RateLimitError::Limited {
            retry_after_seconds,
        }) => {
            state.metrics.observe_rate_limited();
            rate_limited_response(retry_after_seconds)
        }
        Err(RateLimitError::Unavailable) => ApiError::internal().into_response(),
    }
}

async fn enforce_resource_limits(
    State(state): State<ApiState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if !request.uri().path().starts_with("/v1/") {
        return next.run(request).await;
    }
    let object_permit: Option<OwnedSemaphorePermit> = if is_object_route(request.uri().path()) {
        match Arc::clone(&state.object_transfers).try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                state.metrics.observe_rate_limited();
                return rate_limited_response(1);
            }
        }
    } else {
        None
    };
    match tokio::time::timeout(state.request_deadline, next.run(request)).await {
        Ok(response) => match object_permit {
            Some(permit) => hold_object_permit(response, permit),
            None => response,
        },
        Err(_) => {
            let mut response = ApiError::request_timeout().into_response();
            response
                .headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
    }
}

struct PermitBodyStream {
    inner: Pin<Box<dyn Stream<Item = Result<bytes::Bytes, axum::Error>> + Send>>,
    _permit: OwnedSemaphorePermit,
}

impl Stream for PermitBodyStream {
    type Item = Result<bytes::Bytes, axum::Error>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(context)
    }
}

fn hold_object_permit(response: Response, permit: OwnedSemaphorePermit) -> Response {
    let (parts, body) = response.into_parts();
    let guarded = PermitBodyStream {
        inner: Box::pin(body.into_data_stream()),
        _permit: permit,
    };
    Response::from_parts(parts, Body::from_stream(guarded))
}

fn is_object_route(path: &str) -> bool {
    let segments: Vec<_> = path.split('/').collect();
    segments.len() == 6
        && segments[1] == "v1"
        && segments[2] == "vaults"
        && !segments[3].is_empty()
        && segments[4] == "objects"
        && !segments[5].is_empty()
}

fn rate_limited_response(retry_after_seconds: u64) -> Response {
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({
            "error": {
                "code": "rate_limited",
                "message": "request rate limit exceeded; retry later",
                "retryAfterSeconds": retry_after_seconds
            }
        })),
    )
        .into_response();
    response.headers_mut().insert(
        RETRY_AFTER,
        HeaderValue::from_str(&retry_after_seconds.to_string())
            .expect("a retry delay is always a valid header value"),
    );
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn create_vault(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<CreateVaultRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    require_bootstrap(&state, &headers)?;
    validate_token(&request.device_token).map_err(ApiError::bad_request)?;
    if request.initial_device.device_id.is_empty() {
        return Err(ApiError::bad_request("initial device is required"));
    }
    if request.quota_bytes > state.max_vault_bytes {
        return Err(ApiError::service(ServiceError::QuotaExceeded));
    }
    let hash = token_hash(&request.device_token);
    state
        .repository
        .create_vault(
            request.vault_id.clone(),
            request.initial_device.clone(),
            request.quota_bytes,
            hash,
        )
        .await
        .map_err(ApiError::repository)?;
    Ok((StatusCode::CREATED, Json(json!({"created": true}))))
}

async fn status(
    State(state): State<ApiState>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let principal = require_device(&state, &headers, &vault_id).await?;
    let value = state
        .repository
        .status(&principal)
        .await
        .map_err(ApiError::repository)?;
    Ok(Json(
        serde_json::to_value(value).map_err(|_| ApiError::internal())?,
    ))
}

async fn pair_device(
    State(state): State<ApiState>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<PairDeviceRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let principal = require_device(&state, &headers, &vault_id).await?;
    if request.signed_grant.grant.authorizing_device_id != principal.device_id
        || request.signed_grant.grant.vault_id != vault_id
    {
        return Err(ApiError::forbidden());
    }
    validate_token(&request.recipient_device_token).map_err(ApiError::bad_request)?;
    let token = token_hash(&request.recipient_device_token);
    state
        .repository
        .pair_device(
            &principal,
            request.signed_grant,
            token,
            request.expires_at_unix,
        )
        .await
        .map_err(ApiError::repository)?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"pendingActivation": true})),
    ))
}

async fn activate_pairing(
    State(state): State<ApiState>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ActivatePairingRequest>,
) -> Result<Json<Value>, ApiError> {
    let token = bearer(&headers)?;
    validate_token(token).map_err(|_| ApiError::unauthorized())?;
    let confirmation = confirmation_hash(&request.confirmation_code)
        .ok_or_else(|| ApiError::bad_request("confirmation code is invalid"))?;
    let principal = state
        .repository
        .activate_pairing(
            &vault_id,
            token_hash(token),
            confirmation,
            unix_time_seconds().map_err(|_| ApiError::internal())?,
        )
        .await
        .map_err(ApiError::repository)?;
    if principal.vault_id != vault_id {
        return Err(ApiError::forbidden());
    }
    Ok(Json(json!({"activated": true})))
}

async fn revoke_device(
    State(state): State<ApiState>,
    Path((vault_id, device_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let principal = require_device(&state, &headers, &vault_id).await?;
    if principal.device_id == device_id {
        return Err(ApiError::bad_request(
            "the active device cannot revoke itself",
        ));
    }
    let epoch = state
        .repository
        .revoke_device(&principal, &device_id)
        .await
        .map_err(ApiError::repository)?;
    Ok(Json(json!({"epoch": epoch, "revoked": true})))
}

async fn get_device_authorization(
    State(state): State<ApiState>,
    Path((vault_id, device_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<SignedPairingGrant>, ApiError> {
    let principal = require_device(&state, &headers, &vault_id).await?;
    state
        .repository
        .device_authorization(&principal, &device_id)
        .await
        .map_err(ApiError::repository)?
        .map(Json)
        .ok_or_else(ApiError::not_found)
}

async fn upload_object(
    State(state): State<ApiState>,
    Path((vault_id, object_id)): Path<(String, String)>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Result<(StatusCode, Json<OutcomeResponse>), ApiError> {
    let principal = require_device(&state, &headers, &vault_id).await?;
    let Json(object) = Json::<EncryptedObject>::from_request(request, &state)
        .await
        .map_err(ApiError::json_rejection)?;
    if object.vault_id != vault_id || object.object_id != object_id {
        return Err(ApiError::bad_request("object path does not match payload"));
    }
    let outcome = state
        .repository
        .upload_object(&principal, object)
        .await
        .map_err(ApiError::repository)?;
    let status = if outcome == StoreOutcome::Inserted {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(OutcomeResponse { outcome })))
}

async fn get_object(
    State(state): State<ApiState>,
    Path((vault_id, object_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<EncryptedObject>, ApiError> {
    let principal = require_device(&state, &headers, &vault_id).await?;
    state
        .repository
        .object(&principal, &object_id)
        .await
        .map_err(ApiError::repository)?
        .map(Json)
        .ok_or_else(ApiError::not_found)
}

async fn commit_manifest(
    State(state): State<ApiState>,
    Path((vault_id, revision_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(signed): Json<SignedManifest>,
) -> Result<(StatusCode, Json<OutcomeResponse>), ApiError> {
    let principal = require_device(&state, &headers, &vault_id).await?;
    if signed.manifest.vault_id != vault_id
        || signed.manifest.revision_id != revision_id
        || signed.manifest.device_id != principal.device_id
    {
        return Err(ApiError::bad_request(
            "manifest path or signer does not match payload",
        ));
    }
    let outcome = state
        .repository
        .commit_manifest(&principal, signed)
        .await
        .map_err(ApiError::repository)?;
    let status = if outcome == StoreOutcome::Inserted {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(OutcomeResponse { outcome })))
}

async fn get_manifest(
    State(state): State<ApiState>,
    Path((vault_id, revision_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<SignedManifest>, ApiError> {
    let principal = require_device(&state, &headers, &vault_id).await?;
    state
        .repository
        .manifest(&principal, &revision_id)
        .await
        .map_err(ApiError::repository)?
        .map(Json)
        .ok_or_else(ApiError::not_found)
}

fn require_bootstrap(state: &ApiState, headers: &HeaderMap) -> Result<(), ApiError> {
    let token = bearer(headers)?;
    let hash = token_hash(token);
    if bool::from(hash.ct_eq(&state.bootstrap_hash)) {
        Ok(())
    } else {
        Err(ApiError::unauthorized())
    }
}

async fn require_device(
    state: &ApiState,
    headers: &HeaderMap,
    vault_id: &str,
) -> Result<Principal, ApiError> {
    let token = bearer(headers)?;
    validate_token(token).map_err(|_| ApiError::unauthorized())?;
    let principal = state
        .repository
        .authenticate(token_hash(token))
        .await
        .map_err(|error| match error {
            RepositoryError::Unauthorized => ApiError::unauthorized(),
            other => ApiError::repository(other),
        })?;
    if principal.vault_id != vault_id {
        return Err(ApiError::forbidden());
    }
    Ok(principal)
}

fn bearer(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(ApiError::unauthorized)
}

fn confirmation_hash(code: &str) -> Option<[u8; 32]> {
    let normalized = code.trim().to_ascii_uppercase();
    let bytes = normalized.as_bytes();
    if bytes.len() != 9
        || bytes[4] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 4 && !byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some(Sha256::digest(normalized.as_bytes()).into())
}

fn unix_time_seconds() -> Result<u64, ()> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ())
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message: message.into(),
        }
    }
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: "valid bearer credentials are required".into(),
        }
    }
    fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
            message: "credentials do not authorize this operation".into(),
        }
    }
    fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: "sync resource was not found".into(),
        }
    }
    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "conflict",
            message: message.into(),
        }
    }
    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal",
            message: "sync service is temporarily unavailable".into(),
        }
    }
    fn request_timeout() -> Self {
        Self {
            status: StatusCode::REQUEST_TIMEOUT,
            code: "request_timeout",
            message: "request deadline exceeded".into(),
        }
    }
    fn json_rejection(error: axum::extract::rejection::JsonRejection) -> Self {
        Self {
            status: error.status(),
            code: "invalid_json",
            message: "request JSON is invalid or exceeds the route limit".into(),
        }
    }
    fn service(error: ServiceError) -> Self {
        let status = match error {
            ServiceError::VaultNotFound
            | ServiceError::DeviceNotFound
            | ServiceError::MissingObject(_)
            | ServiceError::MissingParent(_) => StatusCode::NOT_FOUND,
            ServiceError::DeviceRevoked => StatusCode::FORBIDDEN,
            ServiceError::PairingExpired => StatusCode::GONE,
            ServiceError::QuotaExceeded | ServiceError::StorageMetadataExceeded => {
                StatusCode::PAYLOAD_TOO_LARGE
            }
            ServiceError::VaultExists
            | ServiceError::DeviceExists
            | ServiceError::ObjectConflict
            | ServiceError::ManifestConflict
            | ServiceError::RootAlreadyExists
            | ServiceError::SequenceReplay
            | ServiceError::EpochMismatch => StatusCode::CONFLICT,
            ServiceError::Protocol(_)
            | ServiceError::InvalidQuota
            | ServiceError::InvalidStorageLimits
            | ServiceError::InvalidPairingExpiry => StatusCode::BAD_REQUEST,
        };
        Self {
            status,
            code: "sync_rejected",
            message: error.to_string(),
        }
    }

    fn repository(error: RepositoryError) -> Self {
        match error {
            RepositoryError::Service(error) => Self::service(error),
            RepositoryError::TokenConflict => Self::conflict("device token is already registered"),
            RepositoryError::Unauthorized => Self::unauthorized(),
            RepositoryError::Unavailable => Self::internal(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({"error": {"code": self.code, "message": self.message}})),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use foliora_sync::{DeviceIdentity, EpochKey, ManifestDraft};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const VAULT: &str = "vault:0123456789abcdef";
    const BOOTSTRAP: &str = "bootstrap-token-with-at-least-32-bytes";
    const OWNER_TOKEN: &str = "owner-device-token-with-at-least-32-bytes";
    const SECOND_TOKEN: &str = "second-device-token-with-at-least-32-bytes";

    async fn call(
        app: &Router,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Value,
    ) -> (StatusCode, Value) {
        let response = call_response(app, method, uri, token, body).await;
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, body)
    }

    async fn call_response(
        app: &Router,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Value,
    ) -> Response {
        call_bytes(app, method, uri, token, serde_json::to_vec(&body).unwrap()).await
    }

    async fn call_bytes(
        app: &Router,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Vec<u8>,
    ) -> Response {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        app.clone()
            .oneshot(builder.body(Body::from(body)).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn authenticated_http_flow_is_idempotent_and_revocation_removes_credentials() {
        let owner_identity = DeviceIdentity::generate().unwrap();
        let second_identity = DeviceIdentity::generate().unwrap();
        let owner = owner_identity.record("Owner laptop").unwrap();
        let second = second_identity.record("Second laptop").unwrap();
        let key = EpochKey::from_bytes([9; 32]);
        let app = router(ApiState::new(BOOTSTRAP).unwrap());

        let (status, _) = call(
            &app,
            "POST",
            "/v1/vaults",
            Some(BOOTSTRAP),
            json!({"vaultId": VAULT, "initialDevice": owner, "quotaBytes": 4096, "deviceToken": OWNER_TOKEN}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            call(
                &app,
                "GET",
                &format!("/v1/vaults/{VAULT}/status"),
                None,
                json!({})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );

        let object = key.encrypt(VAULT, 1, b"opaque HTTP payload").unwrap();
        let object_uri = format!("/v1/vaults/{VAULT}/objects/{}", object.object_id);
        assert_eq!(
            call(
                &app,
                "PUT",
                &object_uri,
                Some(OWNER_TOKEN),
                serde_json::to_value(&object).unwrap()
            )
            .await
            .0,
            StatusCode::CREATED
        );
        assert_eq!(
            call(
                &app,
                "PUT",
                &object_uri,
                Some(OWNER_TOKEN),
                serde_json::to_value(&object).unwrap()
            )
            .await
            .0,
            StatusCode::OK
        );

        let manifest = owner_identity
            .sign(
                ManifestDraft {
                    vault_id: VAULT.into(),
                    epoch: 1,
                    parents: vec![],
                    object_ids: vec![object.object_id.clone()],
                    tombstones: vec![],
                    device_id: owner.device_id.clone(),
                    sequence: 1,
                }
                .finalize()
                .unwrap(),
            )
            .unwrap();
        let manifest_uri = format!(
            "/v1/vaults/{VAULT}/manifests/{}",
            manifest.manifest.revision_id
        );
        assert_eq!(
            call(
                &app,
                "PUT",
                &manifest_uri,
                Some(OWNER_TOKEN),
                serde_json::to_value(manifest).unwrap()
            )
            .await
            .0,
            StatusCode::CREATED
        );

        let pairing = owner_identity
            .grant_epoch_key(VAULT, 1, &key, second.clone())
            .unwrap();
        let confirmation_code = pairing.confirmation_code().unwrap();
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("/v1/vaults/{VAULT}/pairings"),
                Some(OWNER_TOKEN),
                json!({
                    "signedGrant": pairing,
                    "recipientDeviceToken": SECOND_TOKEN,
                    "expiresAtUnix": unix_time_seconds().unwrap() + crate::MAX_PAIRING_LIFETIME_SECONDS
                })
            )
            .await
            .0,
            StatusCode::CREATED
        );
        assert_eq!(
            call(
                &app,
                "GET",
                &format!("/v1/vaults/{VAULT}/status"),
                Some(SECOND_TOKEN),
                json!({})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("/v1/vaults/{VAULT}/pairings/activate"),
                Some(SECOND_TOKEN),
                json!({"confirmationCode": "0000-0000"})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("/v1/vaults/{VAULT}/pairings/activate"),
                Some(SECOND_TOKEN),
                json!({"confirmationCode": confirmation_code})
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("/v1/vaults/{VAULT}/pairings/activate"),
                Some(SECOND_TOKEN),
                json!({"confirmationCode": confirmation_code})
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            call(
                &app,
                "GET",
                &format!("/v1/vaults/{VAULT}/status"),
                Some(SECOND_TOKEN),
                json!({})
            )
            .await
            .0,
            StatusCode::OK
        );

        let authorization_uri = format!("/v1/vaults/{VAULT}/devices/{}", second.device_id);
        let (authorization_status, authorization) = call(
            &app,
            "GET",
            &authorization_uri,
            Some(OWNER_TOKEN),
            json!({}),
        )
        .await;
        assert_eq!(authorization_status, StatusCode::OK);
        let authorization: SignedPairingGrant = serde_json::from_value(authorization).unwrap();
        authorization.verify(&owner).unwrap();

        let revoke_uri = format!("/v1/vaults/{VAULT}/devices/{}", second.device_id);
        assert_eq!(
            call(&app, "DELETE", &revoke_uri, Some(OWNER_TOKEN), json!({}))
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            call(
                &app,
                "GET",
                &format!("/v1/vaults/{VAULT}/status"),
                Some(SECOND_TOKEN),
                json!({})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn pairing_activation_hides_and_enforces_the_five_attempt_lockout() {
        let owner_identity = DeviceIdentity::generate().unwrap();
        let recipient_identity = DeviceIdentity::generate().unwrap();
        let owner = owner_identity.record("Lockout owner").unwrap();
        let recipient = recipient_identity.record("Lockout recipient").unwrap();
        let key = EpochKey::from_bytes([19; 32]);
        let app = router(ApiState::new(BOOTSTRAP).unwrap());

        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/vaults",
                Some(BOOTSTRAP),
                json!({"vaultId": VAULT, "initialDevice": owner, "quotaBytes": 4096, "deviceToken": OWNER_TOKEN}),
            )
            .await
            .0,
            StatusCode::CREATED
        );
        let grant = owner_identity
            .grant_epoch_key(VAULT, 1, &key, recipient)
            .unwrap();
        let correct_code = grant.confirmation_code().unwrap();
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("/v1/vaults/{VAULT}/pairings"),
                Some(OWNER_TOKEN),
                json!({
                    "signedGrant": grant.clone(),
                    "recipientDeviceToken": SECOND_TOKEN,
                    "expiresAtUnix": unix_time_seconds().unwrap() + crate::MAX_PAIRING_LIFETIME_SECONDS
                }),
            )
            .await
            .0,
            StatusCode::CREATED
        );
        let mut wrong_code = correct_code.into_bytes();
        wrong_code[0] = if wrong_code[0] == b'0' { b'1' } else { b'0' };
        let wrong_code = String::from_utf8(wrong_code).unwrap();

        for _ in 0..crate::MAX_PAIRING_CONFIRMATION_ATTEMPTS {
            let (status, body) = call(
                &app,
                "POST",
                &format!("/v1/vaults/{VAULT}/pairings/activate"),
                Some(SECOND_TOKEN),
                json!({"confirmationCode": wrong_code}),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(body["error"]["code"], "unauthorized");
        }
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("/v1/vaults/{VAULT}/pairings/activate"),
                Some(SECOND_TOKEN),
                json!({"confirmationCode": grant.confirmation_code().unwrap()}),
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        let (_, status) = call(
            &app,
            "GET",
            &format!("/v1/vaults/{VAULT}/status"),
            Some(OWNER_TOKEN),
            json!({}),
        )
        .await;
        assert_eq!(status["activeDevices"], 1);
    }

    #[tokio::test]
    async fn path_binding_and_bootstrap_auth_fail_closed() {
        let identity = DeviceIdentity::generate().unwrap();
        let device = identity.record("Laptop").unwrap();
        let app = router(ApiState::new(BOOTSTRAP).unwrap());
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/vaults",
                Some("wrong-token-with-more-than-thirty-two-bytes"),
                json!({"vaultId": VAULT, "initialDevice": device, "quotaBytes": 4096, "deviceToken": OWNER_TOKEN})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/vaults",
                Some(BOOTSTRAP),
                json!({"vaultId": VAULT, "initialDevice": device, "quotaBytes": 4096, "deviceToken": OWNER_TOKEN})
            )
            .await
            .0,
            StatusCode::CREATED
        );
        let object = EpochKey::from_bytes([4; 32])
            .encrypt(VAULT, 1, b"opaque")
            .unwrap();
        let wrong_path = format!("/v1/vaults/{VAULT}/objects/object:{}", "0".repeat(64));
        assert_eq!(
            call(
                &app,
                "PUT",
                &wrong_path,
                Some(OWNER_TOKEN),
                serde_json::to_value(object).unwrap()
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn object_route_has_a_larger_bound_than_metadata_routes() {
        let identity = DeviceIdentity::generate().unwrap();
        let device = identity.record("Large-object laptop").unwrap();
        let app = router(ApiState::new(BOOTSTRAP).unwrap());
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/vaults",
                Some(BOOTSTRAP),
                json!({"vaultId": VAULT, "initialDevice": device, "quotaBytes": 8 * 1024 * 1024, "deviceToken": OWNER_TOKEN})
            )
            .await
            .0,
            StatusCode::CREATED
        );
        let object = EpochKey::from_bytes([7; 32])
            .encrypt(VAULT, 1, &vec![42_u8; 5 * 1024 * 1024])
            .unwrap();
        let object_uri = format!("/v1/vaults/{VAULT}/objects/{}", object.object_id);
        assert_eq!(
            call(
                &app,
                "PUT",
                &object_uri,
                Some(OWNER_TOKEN),
                serde_json::to_value(object).unwrap()
            )
            .await
            .0,
            StatusCode::CREATED
        );

        let oversized_metadata = json!({"padding": "x".repeat(METADATA_BODY_LIMIT + 1)});
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("/v1/vaults/{VAULT}/pairings"),
                Some(OWNER_TOKEN),
                oversized_metadata
            )
            .await
            .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn object_upload_authenticates_before_parsing_untrusted_json() {
        let app = router(ApiState::new(BOOTSTRAP).unwrap());
        let response = call_bytes(
            &app,
            "PUT",
            &format!("/v1/vaults/{VAULT}/objects/object:{}", "0".repeat(64)),
            Some("unknown-device-token-with-at-least-32-bytes"),
            b"this is deliberately invalid JSON".to_vec(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn metrics_are_prometheus_compatible_and_do_not_expose_tenant_labels() {
        let app = router(ApiState::new(BOOTSTRAP).unwrap());
        assert_eq!(
            call(&app, "GET", "/healthz", None, json!({})).await.0,
            StatusCode::OK
        );
        assert_eq!(
            call(&app, "GET", "/readyz", None, json!({})).await.0,
            StatusCode::OK
        );
        let (status, body) = call(&app, "GET", "/metrics", None, json!({})).await;
        assert_eq!(status, StatusCode::OK);
        let rendered = body.as_str().unwrap();
        assert!(rendered.contains("foliora_sync_http_requests_total 2"));
        assert!(rendered.contains("foliora_sync_readiness_checks_total 1"));
        assert!(!rendered.contains("vault_id"));
        assert!(!rendered.contains("device_id"));
    }

    #[tokio::test]
    async fn operator_quota_ceiling_rejects_before_vault_creation() {
        let app = router(
            ApiState::with_repository_metrics_and_limit(
                BOOTSTRAP,
                Arc::new(MemoryRepository::default()),
                Arc::new(ServiceMetrics::default()),
                1024,
            )
            .unwrap(),
        );
        let device = DeviceIdentity::generate()
            .unwrap()
            .record("Quota test")
            .unwrap();
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/vaults",
                Some(BOOTSTRAP),
                json!({"vaultId": VAULT, "initialDevice": device, "quotaBytes": 1025, "deviceToken": OWNER_TOKEN})
            )
            .await
            .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/vaults",
                Some(BOOTSTRAP),
                json!({"vaultId": VAULT, "initialDevice": device, "quotaBytes": 1024, "deviceToken": OWNER_TOKEN})
            )
            .await
            .0,
            StatusCode::CREATED
        );
    }

    #[tokio::test]
    async fn protected_routes_return_429_with_retry_after_and_private_metrics() {
        let metrics = Arc::new(ServiceMetrics::default());
        let state = ApiState::with_repository_and_metrics(
            BOOTSTRAP,
            Arc::new(MemoryRepository::default()),
            metrics,
        )
        .unwrap()
        .with_rate_limit(RateLimitConfig {
            per_credential_per_minute: 60,
            per_credential_burst: 2,
            global_per_minute: 600,
            global_burst: 10,
            max_credentials: 10,
        })
        .unwrap();
        let app = router(state);
        let uri = format!("/v1/vaults/{VAULT}/status");

        assert_eq!(
            call(&app, "GET", &uri, Some(OWNER_TOKEN), json!({}))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(&app, "GET", &uri, Some(OWNER_TOKEN), json!({}))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        let response = call_response(&app, "GET", &uri, Some(OWNER_TOKEN), json!({})).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "1");
        assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["code"], "rate_limited");
        assert_eq!(body["error"]["retryAfterSeconds"], 1);

        let (_, metrics) = call(&app, "GET", "/metrics", None, json!({})).await;
        let metrics = metrics.as_str().unwrap();
        assert!(metrics.contains("foliora_sync_rate_limited_requests_total 1"));
        assert!(!metrics.contains(OWNER_TOKEN));
        assert!(!metrics.contains(VAULT));
    }

    #[tokio::test]
    async fn operational_routes_are_not_starved_by_sync_traffic() {
        let app = router(
            ApiState::new(BOOTSTRAP)
                .unwrap()
                .with_rate_limit(RateLimitConfig {
                    per_credential_per_minute: 1,
                    per_credential_burst: 1,
                    global_per_minute: 1,
                    global_burst: 1,
                    max_credentials: 1,
                })
                .unwrap(),
        );
        for _ in 0..3 {
            assert_eq!(
                call(&app, "GET", "/healthz", None, json!({})).await.0,
                StatusCode::OK
            );
        }
    }

    #[tokio::test]
    async fn exhausted_limit_rejects_before_an_oversized_body_is_parsed() {
        let app = router(
            ApiState::new(BOOTSTRAP)
                .unwrap()
                .with_rate_limit(RateLimitConfig {
                    per_credential_per_minute: 1,
                    per_credential_burst: 1,
                    global_per_minute: 10,
                    global_burst: 10,
                    max_credentials: 10,
                })
                .unwrap(),
        );
        let status_uri = format!("/v1/vaults/{VAULT}/status");
        assert_eq!(
            call(&app, "GET", &status_uri, Some(OWNER_TOKEN), json!({}))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );

        let response = call_bytes(
            &app,
            "POST",
            "/v1/vaults",
            Some(OWNER_TOKEN),
            vec![b'x'; METADATA_BODY_LIMIT + 1],
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn request_deadline_covers_streaming_body_parsing() {
        let state = ApiState::new(BOOTSTRAP)
            .unwrap()
            .with_resource_limits(Duration::from_millis(10), 1)
            .unwrap();
        let permits = Arc::clone(&state.object_transfers);
        let app = router(state);
        let device = DeviceIdentity::generate()
            .unwrap()
            .record("Deadline owner")
            .unwrap();
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/vaults",
                Some(BOOTSTRAP),
                json!({"vaultId": VAULT, "initialDevice": device, "quotaBytes": 4096, "deviceToken": OWNER_TOKEN}),
            )
            .await
            .0,
            StatusCode::CREATED
        );
        let body = Body::from_stream(futures_util::stream::pending::<
            Result<bytes::Bytes, std::convert::Infallible>,
        >());
        let request = Request::builder()
            .method("PUT")
            .uri(format!(
                "/v1/vaults/{VAULT}/objects/object:{}",
                "2".repeat(64)
            ))
            .header("content-type", "application/json")
            .header(AUTHORIZATION, format!("Bearer {OWNER_TOKEN}"))
            .body(body)
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["code"], "request_timeout");
        assert_eq!(permits.available_permits(), 1);
    }

    #[tokio::test]
    async fn object_concurrency_is_rejected_before_a_second_body_is_read() {
        let state = ApiState::new(BOOTSTRAP)
            .unwrap()
            .with_resource_limits(Duration::from_secs(5), 1)
            .unwrap();
        let permits = Arc::clone(&state.object_transfers);
        let app = router(state);
        let object_uri = format!("/v1/vaults/{VAULT}/objects/object:{}", "0".repeat(64));
        let stalled_body = Body::from_stream(futures_util::stream::pending::<
            Result<bytes::Bytes, std::convert::Infallible>,
        >());
        let stalled_request = Request::builder()
            .method("PUT")
            .uri(&object_uri)
            .header("content-type", "application/json")
            .header(AUTHORIZATION, format!("Bearer {OWNER_TOKEN}"))
            .body(stalled_body)
            .unwrap();
        let first_app = app.clone();
        let first = tokio::spawn(async move { first_app.oneshot(stalled_request).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while permits.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the first request must acquire the only object permit");

        let response = call_response(&app, "GET", &object_uri, Some(OWNER_TOKEN), json!({})).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "1");
        first.abort();
        let _ = first.await;
    }

    #[tokio::test]
    async fn object_permit_is_held_until_the_response_body_is_dropped() {
        let state = ApiState::new(BOOTSTRAP)
            .unwrap()
            .with_resource_limits(Duration::from_secs(1), 1)
            .unwrap();
        let permits = Arc::clone(&state.object_transfers);
        let app = router(state);
        let object_uri = format!("/v1/vaults/{VAULT}/objects/object:{}", "1".repeat(64));

        let response = call_response(&app, "GET", &object_uri, Some(OWNER_TOKEN), json!({})).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(permits.available_permits(), 0);
        drop(response);
        assert_eq!(permits.available_permits(), 1);
    }

    #[test]
    fn resource_limit_configuration_and_object_route_shape_fail_closed() {
        assert!(ApiState::new(BOOTSTRAP)
            .unwrap()
            .with_resource_limits(Duration::ZERO, 1)
            .is_err());
        assert!(ApiState::new(BOOTSTRAP)
            .unwrap()
            .with_resource_limits(Duration::from_secs(1), 0)
            .is_err());
        assert!(is_object_route("/v1/vaults/vault:1/objects/object:123"));
        assert!(!is_object_route(
            "/v1/vaults/vault:1/objects/object:123/extra"
        ));
        assert!(!is_object_route("/healthz"));
    }
}
