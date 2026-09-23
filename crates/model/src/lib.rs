//! Explicit, preview-first boundary for optional model assistance.
//!
//! Foliora treats provider output as untrusted suggestions. This crate never
//! persists a suggestion and never accepts a claim without an exact quote that
//! can be located uniquely in the disclosed source text.

mod client;
mod preview;
mod response;

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

pub use client::request_suggestions;
pub use preview::prepare_request;

pub const OPENAI_RESPONSES_ENDPOINT: &str = "https://api.openai.com/v1/responses";
pub const MAX_DISCLOSED_SOURCE_BYTES: usize = 64 * 1024;
pub const MAX_PROVIDER_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_PROVIDER_REQUEST_BYTES: usize = 768 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelRequestPreview {
    pub schema_version: u16,
    pub provider: &'static str,
    pub endpoint: &'static str,
    pub model: String,
    pub source_id: String,
    pub source_fingerprint: String,
    pub payload: String,
    pub payload_sha256: String,
    pub disclosed_bytes: usize,
    pub omitted_bytes: usize,
    pub redaction_count: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PreparedRequest {
    pub preview: ModelRequestPreview,
    original_text: String,
    disclosed_text: String,
}

impl Drop for PreparedRequest {
    fn drop(&mut self) {
        self.original_text.zeroize();
        self.disclosed_text.zeroize();
        self.preview.payload.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelSuggestion {
    pub claim_type: String,
    pub subject: String,
    pub quote: String,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelError {
    EmptyModel,
    ModelTooLong,
    EmptySource,
    TooManyRedactions,
    RedactionTooLong,
    RequestTooLarge,
    InvalidApiKey,
    RequestFailed,
    ProviderRejected(u16),
    ResponseTooLarge,
    InvalidResponse,
    InvalidSuggestion,
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyModel => "model name must not be empty",
            Self::ModelTooLong => "model name exceeds 128 characters",
            Self::EmptySource => "source contains no text to disclose",
            Self::TooManyRedactions => "at most 100 redaction phrases are allowed",
            Self::RedactionTooLong => "a redaction phrase exceeds 512 bytes",
            Self::RequestTooLarge => "the prepared model request exceeds the safety limit",
            Self::InvalidApiKey => "API key is malformed",
            Self::RequestFailed => "the model provider request failed",
            Self::ProviderRejected(status) => {
                return write!(
                    formatter,
                    "the model provider rejected the request (HTTP {status})"
                )
            }
            Self::ResponseTooLarge => "the model provider response exceeds the safety limit",
            Self::InvalidResponse => "the model provider returned an invalid response",
            Self::InvalidSuggestion => {
                "the model returned a suggestion that is not exactly grounded in the source"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ModelError {}
