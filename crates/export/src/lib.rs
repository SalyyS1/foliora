//! Exact-preview JSON exports built only from reviewed, attributable claims.

mod archive;
mod clipboard;
mod markdown;
mod pdf;

pub use archive::{
    export_portable_archive, ArchiveEntry, ArchiveLocale, PortableArchiveExport,
    PortableArchiveManifest,
};
pub use clipboard::{export_redacted_clipboard, ClipboardExport, ClipboardLocale};
pub use markdown::{export_reviewed_markdown, MarkdownExport, MarkdownLocale};
pub use pdf::{export_reviewed_pdf, PdfExport, PdfLocale};

use foliora_domain::{
    detect_conflicts, validate_canonical_timestamp, BundleDraft, Claim, ClaimStatus, DomainError,
    Provenance, Sensitivity, Source, SourceLocator, SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const EXPORT_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportError {
    InvalidDomain(String),
    InvalidExportTime,
    ExpiredBundle,
    ExpiredSource(String),
    DuplicateClaimId(String),
    DuplicateClaimRecord(String),
    DuplicateSourceRecord(String),
    MissingClaim(String),
    UnconfirmedClaim(String),
    MissingSource(String),
    SensitiveClaimNotApproved(String),
    ConflictsRemain,
    Serialize(String),
    UnknownRedaction(String),
    AllClaimsRedacted,
    InvalidPdfFont,
    PdfSerialize(String),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDomain(error) => write!(f, "invalid domain value: {error}"),
            Self::InvalidExportTime => write!(f, "exported_at is not a canonical UTC timestamp"),
            Self::ExpiredBundle => write!(f, "bundle has expired"),
            Self::ExpiredSource(id) => write!(f, "source {id} has expired"),
            Self::DuplicateClaimId(id) => write!(f, "claim {id} is selected more than once"),
            Self::DuplicateClaimRecord(id) => write!(f, "claim input contains duplicate id {id}"),
            Self::DuplicateSourceRecord(id) => write!(f, "source input contains duplicate id {id}"),
            Self::MissingClaim(id) => write!(f, "claim {id} does not exist"),
            Self::UnconfirmedClaim(id) => write!(f, "claim {id} is not confirmed"),
            Self::MissingSource(id) => write!(f, "source {id} does not exist"),
            Self::SensitiveClaimNotApproved(id) => {
                write!(f, "sensitive claim {id} lacks explicit approval")
            }
            Self::ConflictsRemain => write!(f, "selected claims still conflict"),
            Self::Serialize(error) => write!(f, "export serialization failed: {error}"),
            Self::UnknownRedaction(id) => write!(f, "cannot redact unknown claim {id}"),
            Self::AllClaimsRedacted => write!(f, "clipboard export contains no claims"),
            Self::InvalidPdfFont => write!(
                f,
                "PDF export requires a valid Unicode TrueType/OpenType font"
            ),
            Self::PdfSerialize(error) => write!(f, "PDF serialization failed: {error}"),
        }
    }
}

impl std::error::Error for ExportError {}

impl From<DomainError> for ExportError {
    fn from(value: DomainError) -> Self {
        Self::InvalidDomain(value.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedProvenance {
    pub source_id: Option<String>,
    pub locator: Option<SourceLocator>,
    pub user_entered_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedClaim {
    pub id: String,
    pub claim_type: String,
    pub subject: String,
    pub value: Value,
    pub sensitivity: Sensitivity,
    pub provenance: ExportedProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSource {
    pub id: String,
    pub fingerprint: String,
    pub media_type: String,
    pub title: Option<String>,
    pub captured_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewedBundle {
    pub schema_version: u16,
    pub domain_schema_version: u16,
    pub id: String,
    pub purpose: String,
    pub exported_at: String,
    pub expires_at: Option<String>,
    pub claims: Vec<ExportedClaim>,
    pub evidence: Vec<EvidenceSource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportAuditEvent {
    pub event_type: String,
    pub bundle_id: String,
    pub exported_at: String,
    pub payload_sha256: String,
    pub claim_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonExport {
    pub preview: ReviewedBundle,
    pub bytes: Vec<u8>,
    pub audit_event: ExportAuditEvent,
}

pub fn export_reviewed_json(
    bundle: &BundleDraft,
    claims: &[Claim],
    sources: &[Source],
    approved_sensitive_claim_ids: &BTreeSet<String>,
    exported_at: &str,
) -> Result<JsonExport, ExportError> {
    bundle.validate()?;
    validate_canonical_timestamp(exported_at, "exported_at")
        .map_err(|_| ExportError::InvalidExportTime)?;
    if expired(bundle.expires_at.as_deref(), exported_at) {
        return Err(ExportError::ExpiredBundle);
    }

    let claims_by_id = index_claims(claims)?;
    let sources_by_id = index_sources(sources)?;
    let selected = select_claims(bundle, &claims_by_id, approved_sensitive_claim_ids)?;
    if !detect_conflicts(&selected).is_empty() {
        return Err(ExportError::ConflictsRemain);
    }

    let (exported_claims, evidence_ids) = export_claims(&selected);
    let evidence = collect_evidence(&evidence_ids, &sources_by_id, exported_at)?;
    let preview = ReviewedBundle {
        schema_version: EXPORT_SCHEMA_VERSION,
        domain_schema_version: SCHEMA_VERSION,
        id: bundle.id.clone(),
        purpose: bundle.purpose.clone(),
        exported_at: exported_at.to_owned(),
        expires_at: bundle.expires_at.clone(),
        claims: exported_claims,
        evidence,
    };
    let bytes = serde_json::to_vec_pretty(&preview)
        .map_err(|error| ExportError::Serialize(error.to_string()))?;
    let audit_event = ExportAuditEvent {
        event_type: "bundle.exported.json".to_owned(),
        bundle_id: bundle.id.clone(),
        exported_at: exported_at.to_owned(),
        payload_sha256: format!("sha256:{}", hex_digest(&bytes)),
        claim_ids: bundle.claim_ids.clone(),
    };
    Ok(JsonExport {
        preview,
        bytes,
        audit_event,
    })
}

fn index_claims(claims: &[Claim]) -> Result<BTreeMap<&String, &Claim>, ExportError> {
    let mut indexed = BTreeMap::new();
    for claim in claims {
        if indexed.insert(&claim.id, claim).is_some() {
            return Err(ExportError::DuplicateClaimRecord(claim.id.clone()));
        }
    }
    Ok(indexed)
}

fn index_sources(sources: &[Source]) -> Result<BTreeMap<&String, &Source>, ExportError> {
    let mut indexed = BTreeMap::new();
    for source in sources {
        if indexed.insert(&source.id, source).is_some() {
            return Err(ExportError::DuplicateSourceRecord(source.id.clone()));
        }
    }
    Ok(indexed)
}

fn select_claims(
    bundle: &BundleDraft,
    claims: &BTreeMap<&String, &Claim>,
    approvals: &BTreeSet<String>,
) -> Result<Vec<Claim>, ExportError> {
    let mut seen = BTreeSet::new();
    let mut selected = Vec::with_capacity(bundle.claim_ids.len());
    for id in &bundle.claim_ids {
        if !seen.insert(id.clone()) {
            return Err(ExportError::DuplicateClaimId(id.clone()));
        }
        let claim = claims
            .get(id)
            .ok_or_else(|| ExportError::MissingClaim(id.clone()))?;
        claim.validate()?;
        if claim.status != ClaimStatus::Confirmed {
            return Err(ExportError::UnconfirmedClaim(id.clone()));
        }
        if is_sensitive(claim.sensitivity) && !approvals.contains(id) {
            return Err(ExportError::SensitiveClaimNotApproved(id.clone()));
        }
        selected.push((*claim).clone());
    }
    Ok(selected)
}

fn export_claims(claims: &[Claim]) -> (Vec<ExportedClaim>, BTreeSet<String>) {
    let mut evidence_ids = BTreeSet::new();
    let values = claims
        .iter()
        .map(|claim| {
            let provenance = match &claim.provenance {
                Provenance::Source(value) => {
                    evidence_ids.insert(value.source_id.clone());
                    ExportedProvenance {
                        source_id: Some(value.source_id.clone()),
                        locator: Some(value.locator.clone()),
                        user_entered_at: None,
                    }
                }
                Provenance::UserEntered { entered_at } => ExportedProvenance {
                    source_id: None,
                    locator: None,
                    user_entered_at: Some(entered_at.clone()),
                },
            };
            ExportedClaim {
                id: claim.id.clone(),
                claim_type: claim.claim_type.clone(),
                subject: claim.subject.clone(),
                value: claim.value.clone(),
                sensitivity: claim.sensitivity,
                provenance,
            }
        })
        .collect();
    (values, evidence_ids)
}

fn collect_evidence(
    ids: &BTreeSet<String>,
    sources: &BTreeMap<&String, &Source>,
    exported_at: &str,
) -> Result<Vec<EvidenceSource>, ExportError> {
    ids.iter()
        .map(|id| {
            let source = sources
                .get(id)
                .ok_or_else(|| ExportError::MissingSource(id.clone()))?;
            source.validate()?;
            if expired(source.expires_at.as_deref(), exported_at) {
                return Err(ExportError::ExpiredSource(id.clone()));
            }
            Ok(EvidenceSource {
                id: source.id.clone(),
                fingerprint: source.fingerprint.clone(),
                media_type: source.media_type.clone(),
                title: source.title.clone(),
                captured_at: source.captured_at.clone(),
            })
        })
        .collect()
}

fn expired(expires_at: Option<&str>, exported_at: &str) -> bool {
    expires_at.is_some_and(|expiry| expiry <= exported_at)
}

fn is_sensitive(value: Sensitivity) -> bool {
    matches!(value, Sensitivity::Private | Sensitivity::HighlySensitive)
}

pub(crate) fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use foliora_domain::{SourceProvenance, ValidityWindow};

    const NOW: &str = "2026-09-11T00:00:00Z";

    fn source() -> Source {
        Source::new(
            "source:1".into(),
            format!("sha256:{}", "a".repeat(64)),
            "text/plain".into(),
            NOW.into(),
        )
        .unwrap()
    }

    fn claim(status: ClaimStatus, sensitivity: Sensitivity) -> Claim {
        Claim {
            schema_version: SCHEMA_VERSION,
            id: "claim:1".into(),
            claim_type: "project.goal".into(),
            subject: "project:1".into(),
            value: Value::String("Ship safely".into()),
            status,
            provenance: Provenance::Source(SourceProvenance {
                source_id: "source:1".into(),
                locator: SourceLocator::Span { start: 0, end: 11 },
                extractor: None,
            }),
            captured_at: NOW.into(),
            validity: ValidityWindow::default(),
            sensitivity,
            revision: 1,
        }
    }

    fn bundle() -> BundleDraft {
        BundleDraft {
            schema_version: SCHEMA_VERSION,
            id: "bundle:1".into(),
            purpose: "Project handoff".into(),
            claim_ids: vec!["claim:1".into()],
            expires_at: None,
        }
    }

    #[test]
    fn preview_is_exactly_the_serialized_payload() {
        let result = export_reviewed_json(
            &bundle(),
            &[claim(ClaimStatus::Confirmed, Sensitivity::Internal)],
            &[source()],
            &BTreeSet::new(),
            NOW,
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<ReviewedBundle>(&result.bytes).unwrap(),
            result.preview
        );
        assert_eq!(
            result.audit_event.payload_sha256,
            format!("sha256:{}", hex_digest(&result.bytes))
        );
    }

    #[test]
    fn unconfirmed_and_unapproved_sensitive_claims_fail_closed() {
        assert!(matches!(
            export_reviewed_json(
                &bundle(),
                &[claim(ClaimStatus::Candidate, Sensitivity::Internal)],
                &[source()],
                &BTreeSet::new(),
                NOW
            ),
            Err(ExportError::UnconfirmedClaim(_))
        ));
        assert!(matches!(
            export_reviewed_json(
                &bundle(),
                &[claim(ClaimStatus::Confirmed, Sensitivity::Private)],
                &[source()],
                &BTreeSet::new(),
                NOW
            ),
            Err(ExportError::SensitiveClaimNotApproved(_))
        ));
    }

    #[test]
    fn approved_sensitive_claim_exports_without_raw_source_content() {
        let approvals = BTreeSet::from(["claim:1".to_owned()]);
        let result = export_reviewed_json(
            &bundle(),
            &[claim(ClaimStatus::Confirmed, Sensitivity::Private)],
            &[source()],
            &approvals,
            NOW,
        )
        .unwrap();
        let text = String::from_utf8(result.bytes).unwrap();
        assert!(text.contains("Ship safely"));
        assert!(!text.contains("local_path"));
        assert!(!text.contains("source content"));
    }

    #[test]
    fn missing_or_expired_evidence_blocks_export() {
        assert!(matches!(
            export_reviewed_json(
                &bundle(),
                &[claim(ClaimStatus::Confirmed, Sensitivity::Internal)],
                &[],
                &BTreeSet::new(),
                NOW
            ),
            Err(ExportError::MissingSource(_))
        ));
        let mut expired = source();
        expired.expires_at = Some(NOW.into());
        assert!(matches!(
            export_reviewed_json(
                &bundle(),
                &[claim(ClaimStatus::Confirmed, Sensitivity::Internal)],
                &[expired],
                &BTreeSet::new(),
                NOW
            ),
            Err(ExportError::ExpiredSource(_))
        ));
    }

    #[test]
    fn duplicate_input_records_are_rejected() {
        let confirmed = claim(ClaimStatus::Confirmed, Sensitivity::Internal);
        assert!(matches!(
            export_reviewed_json(
                &bundle(),
                &[confirmed.clone(), confirmed.clone()],
                &[source()],
                &BTreeSet::new(),
                NOW
            ),
            Err(ExportError::DuplicateClaimRecord(_))
        ));
        let evidence = source();
        assert!(matches!(
            export_reviewed_json(
                &bundle(),
                &[confirmed],
                &[evidence.clone(), evidence],
                &BTreeSet::new(),
                NOW
            ),
            Err(ExportError::DuplicateSourceRecord(_))
        ));
    }
}
