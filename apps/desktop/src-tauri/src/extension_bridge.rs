use foliora_domain::{detect_conflicts, Claim, ClaimStatus};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FIELDS: usize = 100;
pub const MAX_GRANT_LIFETIME_MS: u64 = 10 * 60 * 1_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedGrant {
    pub id: String,
    pub top_origin: String,
    pub approved_claim_ids: Vec<String>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    #[serde(skip)]
    frozen_claims: Vec<FrozenClaim>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareFillRequest {
    pub protocol_version: u16,
    pub tab_id: u64,
    pub top_origin: String,
    pub document_token: String,
    pub dom_revision: u64,
    pub field_fingerprint: String,
    pub fields: Vec<FieldDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldDescriptor {
    pub field_id: String,
    pub tag: String,
    #[serde(rename = "type")]
    pub input_type: String,
    pub name: String,
    pub autocomplete: String,
    pub disabled: bool,
    pub read_only: bool,
    pub hidden: bool,
    pub frame_origin: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FrozenClaim {
    pub id: String,
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OriginGrant {
    pub id: String,
    pub top_origin: String,
    pub frame_origins: Vec<String>,
    pub document_token: String,
    pub approved_claim_ids: Vec<String>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Mapping {
    pub field_id: String,
    pub claim_id: String,
    pub confidence_milli: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FillPreview {
    pub protocol_version: u16,
    pub grant_id: String,
    pub top_origin: String,
    pub document_token: String,
    pub dom_revision: u64,
    pub field_fingerprint: String,
    pub mappings: Vec<Mapping>,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativePreview {
    #[serde(rename = "type")]
    pub message_type: &'static str,
    pub grant: OriginGrant,
    pub claims: Vec<FrozenClaim>,
    pub preview: FillPreview,
}

pub fn authorize(
    top_origin: &str,
    approved_claim_ids: Vec<String>,
    now_ms: u64,
    lifetime_ms: u64,
    claims: &[Claim],
) -> Result<AuthorizedGrant, String> {
    if !valid_https_origin(top_origin) {
        return Err("extension origin must be an exact HTTPS origin".into());
    }
    if lifetime_ms == 0 || lifetime_ms > MAX_GRANT_LIFETIME_MS {
        return Err("extension grant lifetime must be between 1 ms and 10 minutes".into());
    }
    let mut ids = approved_claim_ids;
    ids.sort();
    ids.dedup();
    if ids.is_empty() {
        return Err("select at least one claim for the extension".into());
    }
    let conflicts: BTreeSet<_> = detect_conflicts(claims)
        .into_iter()
        .flat_map(|set| set.claim_ids)
        .collect();
    let mut frozen_claims = Vec::with_capacity(ids.len());
    for id in &ids {
        let claim = claims
            .iter()
            .find(|claim| &claim.id == id)
            .ok_or_else(|| "an approved extension claim no longer exists".to_string())?;
        if claim.status != ClaimStatus::Confirmed || conflicts.contains(id) || !claim.attributable()
        {
            return Err(
                "only confirmed, attributable, conflict-free claims can be approved".into(),
            );
        }
        frozen_claims.push(FrozenClaim {
            id: claim.id.clone(),
            label: claim.claim_type.clone(),
            value: scalar_value(&claim.value)?,
        });
    }
    let expires_at_ms = now_ms
        .checked_add(lifetime_ms)
        .ok_or_else(|| "extension grant expiry overflow".to_string())?;
    let mut nonce = [0_u8; 16];
    OsRng.fill_bytes(&mut nonce);
    Ok(AuthorizedGrant {
        id: format!("grant:{}", hex(&nonce)),
        top_origin: top_origin.into(),
        approved_claim_ids: ids,
        issued_at_ms: now_ms,
        expires_at_ms,
        frozen_claims,
    })
}

pub fn prepare(
    grant: &AuthorizedGrant,
    request: PrepareFillRequest,
    claims: &[Claim],
    now_ms: u64,
) -> Result<NativePreview, String> {
    validate_request(grant, &request, now_ms)?;
    let by_id: BTreeMap<_, _> = claims
        .iter()
        .map(|claim| (claim.id.as_str(), claim))
        .collect();
    let conflicts: BTreeSet<_> = detect_conflicts(claims)
        .into_iter()
        .flat_map(|set| set.claim_ids)
        .collect();
    for frozen in &grant.frozen_claims {
        let id = &frozen.id;
        let claim = by_id
            .get(id.as_str())
            .ok_or_else(|| "an approved extension claim no longer exists".to_string())?;
        if claim.status != ClaimStatus::Confirmed
            || !claim.attributable()
            || conflicts.contains(id)
            || claim.claim_type != frozen.label
            || scalar_value(&claim.value)? != frozen.value
        {
            return Err("an approved extension claim is no longer eligible".into());
        }
    }
    let mappings = map_fields(&request.fields, &grant.frozen_claims);
    if mappings.is_empty() {
        return Err("no safely supported fields match the approved claims".into());
    }
    Ok(NativePreview {
        message_type: "fillPreview",
        grant: OriginGrant {
            id: grant.id.clone(),
            top_origin: grant.top_origin.clone(),
            frame_origins: vec![grant.top_origin.clone()],
            document_token: request.document_token.clone(),
            approved_claim_ids: grant.approved_claim_ids.clone(),
            issued_at_ms: grant.issued_at_ms,
            expires_at_ms: grant.expires_at_ms,
        },
        claims: grant.frozen_claims.clone(),
        preview: FillPreview {
            protocol_version: PROTOCOL_VERSION,
            grant_id: grant.id.clone(),
            top_origin: request.top_origin,
            document_token: request.document_token,
            dom_revision: request.dom_revision,
            field_fingerprint: request.field_fingerprint,
            mappings,
            created_at_ms: now_ms,
        },
    })
}

fn validate_request(
    grant: &AuthorizedGrant,
    request: &PrepareFillRequest,
    now_ms: u64,
) -> Result<(), String> {
    let field_ids: BTreeSet<_> = request.fields.iter().map(|field| &field.field_id).collect();
    if request.protocol_version != PROTOCOL_VERSION
        || request.top_origin != grant.top_origin
        || now_ms < grant.issued_at_ms
        || now_ms > grant.expires_at_ms
        || request.document_token.is_empty()
        || request.document_token.len() > 256
        || request.field_fingerprint.is_empty()
        || request.field_fingerprint.len() > 128 * 1024
        || request.fields.is_empty()
        || request.fields.len() > MAX_FIELDS
        || field_ids.len() != request.fields.len()
        || request.fields.iter().any(|field| {
            field.field_id.is_empty()
                || field.field_id.len() > 256
                || field.name.len() > 1_024
                || field.autocomplete.len() > 1_024
        })
        || request
            .fields
            .iter()
            .any(|field| field.frame_origin != grant.top_origin)
    {
        return Err("extension request does not match the active origin grant".into());
    }
    Ok(())
}

fn map_fields(fields: &[FieldDescriptor], claims: &[FrozenClaim]) -> Vec<Mapping> {
    fields
        .iter()
        .filter_map(|field| {
            if !safe_field(field) {
                return None;
            }
            let hint = format!("{} {}", field.autocomplete, field.name).to_ascii_lowercase();
            let matches: Vec<_> = claims
                .iter()
                .filter(|claim| claim_matches(&claim.label, &hint))
                .collect();
            (matches.len() == 1).then(|| Mapping {
                field_id: field.field_id.clone(),
                claim_id: matches[0].id.clone(),
                confidence_milli: if field.autocomplete.is_empty() {
                    700
                } else {
                    950
                },
            })
        })
        .collect()
}

fn safe_field(field: &FieldDescriptor) -> bool {
    if field.disabled || field.read_only || field.hidden {
        return false;
    }
    let tag = field.tag.to_ascii_lowercase();
    let input_type = field.input_type.to_ascii_lowercase();
    if !matches!(tag.as_str(), "input" | "textarea" | "select") {
        return false;
    }
    if tag == "input"
        && !matches!(
            input_type.as_str(),
            "text" | "email" | "tel" | "url" | "date" | "month" | "number" | "search"
        )
    {
        return false;
    }
    let hint = format!("{} {}", field.autocomplete, field.name).to_ascii_lowercase();
    ![
        "password",
        "passwd",
        "one-time-code",
        "cc-",
        "card_number",
        "card-number",
        "cvv",
        "cvc",
        "security_code",
        "security-code",
        "iban",
        "routing",
        "bank_account",
        "bank-account",
    ]
    .iter()
    .any(|token| hint.contains(token))
}

fn claim_matches(claim_type: &str, hint: &str) -> bool {
    let kind = claim_type.to_ascii_lowercase();
    [
        (&["email"][..], &["email"][..]),
        (
            &["phone", "tel", "mobile"][..],
            &["tel", "phone", "mobile"][..],
        ),
        (&["name"][..], &["name"][..]),
        (&["postal", "zip"][..], &["postal", "zip"][..]),
        (&["address"][..], &["address", "street"][..]),
        (
            &["organization", "company"][..],
            &["organization", "company"][..],
        ),
        (&["url", "website"][..], &["url", "website"][..]),
    ]
    .iter()
    .any(|(claim_words, field_words)| {
        claim_words.iter().any(|word| kind.contains(word))
            && field_words.iter().any(|word| hint.contains(word))
    })
}

fn scalar_value(value: &Value) -> Result<String, String> {
    match value {
        Value::String(value) if !value.is_empty() && value.len() <= 10_000 => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        _ => Err("extension claims must be non-empty bounded scalar values".into()),
    }
}

fn valid_https_origin(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|parsed| {
        parsed.scheme() == "https"
            && parsed.host_str().is_some()
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.path() == "/"
            && parsed.query().is_none()
            && parsed.fragment().is_none()
            && parsed.origin().ascii_serialization() == value
    })
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                DIGITS[(byte >> 4) as usize] as char,
                DIGITS[(byte & 0xf) as usize] as char,
            ]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use foliora_domain::{
        Provenance, Sensitivity, SourceLocator, SourceProvenance, ValidityWindow, SCHEMA_VERSION,
    };

    fn claim(id: &str, kind: &str, value: Value) -> Claim {
        Claim {
            schema_version: SCHEMA_VERSION,
            id: id.into(),
            claim_type: kind.into(),
            subject: "me".into(),
            value,
            status: ClaimStatus::Confirmed,
            provenance: Provenance::Source(SourceProvenance {
                source_id: "source:1".into(),
                locator: SourceLocator::Span { start: 0, end: 1 },
                extractor: None,
            }),
            captured_at: "2026-01-01T00:00:00Z".into(),
            validity: ValidityWindow::default(),
            sensitivity: Sensitivity::Private,
            revision: 1,
        }
    }

    fn request(origin: &str) -> PrepareFillRequest {
        PrepareFillRequest {
            protocol_version: 1,
            tab_id: 7,
            top_origin: origin.into(),
            document_token: "doc:1".into(),
            dom_revision: 2,
            field_fingerprint: "fingerprint".into(),
            fields: vec![FieldDescriptor {
                field_id: "field:1".into(),
                tag: "input".into(),
                input_type: "email".into(),
                name: "contact_email".into(),
                autocomplete: "email".into(),
                disabled: false,
                read_only: false,
                hidden: false,
                frame_origin: origin.into(),
            }],
        }
    }

    #[test]
    fn exact_origin_and_approved_subset_produce_frozen_preview() {
        let claims = vec![
            claim(
                "claim:email",
                "contact.email",
                Value::String("a@example.com".into()),
            ),
            claim("claim:name", "person.name", Value::String("An".into())),
        ];
        let grant = authorize(
            "https://forms.example",
            vec!["claim:email".into()],
            100,
            1_000,
            &claims,
        )
        .unwrap();
        let preview = prepare(&grant, request("https://forms.example"), &claims, 200).unwrap();
        assert_eq!(preview.claims.len(), 1);
        assert_eq!(preview.claims[0].value, "a@example.com");
        assert_eq!(preview.preview.mappings[0].claim_id, "claim:email");
    }

    #[test]
    fn origin_swap_expiry_and_unapproved_claim_fail_closed() {
        let claims = vec![claim(
            "claim:email",
            "contact.email",
            Value::String("a@example.com".into()),
        )];
        let grant = authorize(
            "https://forms.example",
            vec!["claim:email".into()],
            100,
            100,
            &claims,
        )
        .unwrap();
        assert!(prepare(&grant, request("https://evil.example"), &claims, 150).is_err());
        assert!(prepare(&grant, request("https://forms.example"), &claims, 201).is_err());
        assert!(authorize(
            "https://forms.example",
            vec!["missing".into()],
            100,
            100,
            &claims
        )
        .is_err());
    }

    #[test]
    fn ambiguous_mapping_and_structured_values_are_not_released() {
        let claims = vec![
            claim("a", "work.email", Value::String("a@example.com".into())),
            claim("b", "home.email", Value::String("b@example.com".into())),
        ];
        let grant = authorize(
            "https://forms.example",
            vec!["a".into(), "b".into()],
            100,
            100,
            &claims,
        )
        .unwrap();
        assert!(prepare(&grant, request("https://forms.example"), &claims, 150).is_err());
        let structured = vec![claim(
            "object",
            "contact.email",
            serde_json::json!({"email": "x"}),
        )];
        assert!(authorize(
            "https://forms.example",
            vec!["object".into()],
            100,
            100,
            &structured
        )
        .is_err());
    }

    #[test]
    fn claim_change_after_consent_invalidates_the_frozen_grant() {
        let mut claims = vec![claim(
            "claim:email",
            "contact.email",
            Value::String("before@example.com".into()),
        )];
        let grant = authorize(
            "https://forms.example",
            vec!["claim:email".into()],
            100,
            1_000,
            &claims,
        )
        .unwrap();
        claims[0].value = Value::String("after@example.com".into());
        claims[0].revision += 1;
        assert!(prepare(&grant, request("https://forms.example"), &claims, 150).is_err());
    }

    #[test]
    fn backend_does_not_map_sensitive_or_duplicate_fields() {
        let claims = vec![claim(
            "claim:email",
            "contact.email",
            Value::String("a@example.com".into()),
        )];
        let grant = authorize(
            "https://forms.example",
            vec!["claim:email".into()],
            100,
            1_000,
            &claims,
        )
        .unwrap();
        let mut sensitive = request("https://forms.example");
        sensitive.fields[0].input_type = "password".into();
        assert!(prepare(&grant, sensitive, &claims, 150).is_err());
        let mut duplicate = request("https://forms.example");
        duplicate.fields.push(duplicate.fields[0].clone());
        assert!(prepare(&grant, duplicate, &claims, 150).is_err());
    }
}
