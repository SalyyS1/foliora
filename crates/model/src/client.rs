use crate::{
    response::parse_response, ModelError, ModelSuggestion, PreparedRequest,
    MAX_PROVIDER_RESPONSE_BYTES, OPENAI_RESPONSES_ENDPOINT,
};
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use std::time::Duration;
use zeroize::Zeroizing;

pub async fn request_suggestions(
    prepared: &PreparedRequest,
    api_key: Zeroizing<String>,
) -> Result<Vec<ModelSuggestion>, ModelError> {
    validate_api_key(api_key.as_str())?;
    let bearer = Zeroizing::new(format!("Bearer {}", api_key.as_str()));
    let mut authorization =
        HeaderValue::from_str(bearer.as_str()).map_err(|_| ModelError::InvalidApiKey)?;
    authorization.set_sensitive(true);
    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|_| ModelError::RequestFailed)?;
    let mut response = client
        .post(OPENAI_RESPONSES_ENDPOINT)
        .header(AUTHORIZATION, authorization)
        .header(CONTENT_TYPE, "application/json")
        .body(prepared.preview.payload.clone())
        .send()
        .await
        .map_err(|_| ModelError::RequestFailed)?;
    if !response.status().is_success() {
        return Err(ModelError::ProviderRejected(response.status().as_u16()));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PROVIDER_RESPONSE_BYTES as u64)
    {
        return Err(ModelError::ResponseTooLarge);
    }

    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ModelError::RequestFailed)?
    {
        append_bounded(&mut bytes, &chunk)?;
    }
    parse_response(prepared, &bytes)
}

fn append_bounded(target: &mut Vec<u8>, chunk: &[u8]) -> Result<(), ModelError> {
    if target.len().saturating_add(chunk.len()) > MAX_PROVIDER_RESPONSE_BYTES {
        return Err(ModelError::ResponseTooLarge);
    }
    target.extend_from_slice(chunk);
    Ok(())
}

fn validate_api_key(api_key: &str) -> Result<(), ModelError> {
    if api_key.len() < 20
        || api_key.len() > 512
        || api_key.chars().any(char::is_whitespace)
        || !api_key.is_ascii()
    {
        return Err(ModelError::InvalidApiKey);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_keys_that_could_break_headers_or_leak_in_errors() {
        let non_ascii = "é".repeat(20);
        for key in ["short", "sk-test\nX-Bad: injected", non_ascii.as_str()] {
            assert_eq!(validate_api_key(key), Err(ModelError::InvalidApiKey));
        }
    }

    #[test]
    fn response_body_limit_is_enforced_across_chunks() {
        let mut target = vec![0; MAX_PROVIDER_RESPONSE_BYTES - 2];
        append_bounded(&mut target, &[1, 2]).unwrap();
        assert_eq!(
            append_bounded(&mut target, &[3]),
            Err(ModelError::ResponseTooLarge)
        );
    }
}
