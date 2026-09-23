use crate::{preview::overlapping_match_offsets, ModelError, ModelSuggestion, PreparedRequest};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct SuggestionEnvelope {
    suggestions: Vec<RawSuggestion>,
}

#[derive(Debug, Deserialize)]
struct RawSuggestion {
    claim_type: String,
    subject: String,
    quote: String,
}

pub(crate) fn parse_response(
    prepared: &PreparedRequest,
    response: &[u8],
) -> Result<Vec<ModelSuggestion>, ModelError> {
    let root: Value = serde_json::from_slice(response).map_err(|_| ModelError::InvalidResponse)?;
    if root.get("status").and_then(Value::as_str) != Some("completed") {
        return Err(ModelError::InvalidResponse);
    }
    let output = root
        .get("output")
        .and_then(Value::as_array)
        .ok_or(ModelError::InvalidResponse)?;
    let mut texts = Vec::new();
    for item in output {
        let Some(content) = item.get("content").and_then(Value::as_array) else {
            continue;
        };
        for part in content {
            if part.get("type").and_then(Value::as_str) == Some("output_text") {
                if let Some(text) = part.get("text").and_then(Value::as_str) {
                    texts.push(text);
                }
            }
        }
    }
    if texts.len() != 1 {
        return Err(ModelError::InvalidResponse);
    }
    let envelope: SuggestionEnvelope =
        serde_json::from_str(texts[0]).map_err(|_| ModelError::InvalidResponse)?;
    if envelope.suggestions.len() > 8 {
        return Err(ModelError::InvalidResponse);
    }
    envelope
        .suggestions
        .into_iter()
        .map(|raw| validate_suggestion(prepared, raw))
        .collect()
}

fn validate_suggestion(
    prepared: &PreparedRequest,
    raw: RawSuggestion,
) -> Result<ModelSuggestion, ModelError> {
    let claim_type = raw.claim_type.trim();
    let subject = raw.subject.trim();
    let quote = raw.quote.trim();
    if claim_type.is_empty()
        || claim_type.len() > 128
        || subject.is_empty()
        || subject.len() > 256
        || quote.is_empty()
        || quote.len() > 4096
        || quote.contains("[REDACTED]")
    {
        return Err(ModelError::InvalidSuggestion);
    }
    let disclosed_matches = overlapping_match_offsets(prepared.disclosed_text(), quote);
    let original_matches = overlapping_match_offsets(prepared.original_text(), quote);
    if disclosed_matches.len() != 1 || original_matches.len() != 1 {
        return Err(ModelError::InvalidSuggestion);
    }
    let start = original_matches[0];
    Ok(ModelSuggestion {
        claim_type: claim_type.to_owned(),
        subject: subject.to_owned(),
        quote: quote.to_owned(),
        start,
        end: start + quote.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prepare_request;

    fn response(suggestions: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "status": "completed",
            "output": [{"type": "message", "content": [{
                "type": "output_text",
                "text": suggestions
            }]}]
        }))
        .unwrap()
    }

    #[test]
    fn scans_output_and_maps_unique_quote_to_original_bytes() {
        let prepared = prepare_request(
            "s",
            "sha256:f",
            "Mật khẩu 1234. Ngày giao: 12/09/2026.",
            "model",
            &["1234".into()],
        )
        .unwrap();
        let parsed = parse_response(
            &prepared,
            &response(r#"{"suggestions":[{"claim_type":"delivery.date","subject":"order:1","quote":"12/09/2026"}]}"#),
        )
        .unwrap();
        assert_eq!(
            &prepared.original_text()[parsed[0].start..parsed[0].end],
            "12/09/2026"
        );
    }

    #[test]
    fn rejects_hallucinated_repeated_and_redacted_quotes() {
        let prepared =
            prepare_request("s", "f", "Lan Lan secret", "model", &["secret".into()]).unwrap();
        for quote in ["Minh", "Lan", "[REDACTED]"] {
            let body = format!(
                r#"{{"suggestions":[{{"claim_type":"person.name","subject":"person:1","quote":"{quote}"}}]}}"#
            );
            assert_eq!(
                parse_response(&prepared, &response(&body)),
                Err(ModelError::InvalidSuggestion)
            );
        }
    }

    #[test]
    fn rejects_overlapping_duplicate_quotes() {
        let prepared = prepare_request("s", "f", "aaa", "model", &[]).unwrap();
        let body = r#"{"suggestions":[{"claim_type":"value","subject":"item:1","quote":"aa"}]}"#;
        assert_eq!(
            parse_response(&prepared, &response(body)),
            Err(ModelError::InvalidSuggestion)
        );
    }

    #[test]
    fn does_not_assume_first_output_item_is_text() {
        let prepared = prepare_request("s", "f", "Value ABC", "model", &[]).unwrap();
        let response = serde_json::to_vec(&serde_json::json!({
            "status": "completed",
            "output": [
                {"type": "reasoning"},
                {"type": "message", "content": [{"type": "output_text", "text":
                    r#"{"suggestions":[{"claim_type":"code","subject":"item:1","quote":"ABC"}]}"#
                }]}
            ]
        }))
        .unwrap();
        assert_eq!(
            parse_response(&prepared, &response).unwrap()[0].quote,
            "ABC"
        );
    }

    #[test]
    fn rejects_incomplete_responses_even_when_partial_text_exists() {
        let prepared = prepare_request("s", "f", "Value ABC", "model", &[]).unwrap();
        let response = serde_json::to_vec(&serde_json::json!({
            "status": "incomplete",
            "output": [{"content": [{"type": "output_text", "text": "{\"suggestions\":[]}"}]}]
        }))
        .unwrap();
        assert_eq!(
            parse_response(&prepared, &response),
            Err(ModelError::InvalidResponse)
        );
    }
}
