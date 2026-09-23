//! Versioned, attributable contracts for Foliora's claim ledger and bundles.
//!
//! This crate intentionally contains no persistence, parsing, networking, or
//! cryptography. It validates values at boundaries for those layers.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub mod templates;

pub const SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    EmptyField(&'static str),
    InvalidRange(&'static str),
    InvalidClaimState,
    InvalidTimestamp(&'static str),
    RevisionOverflow,
    UnsupportedSchemaVersion(u16),
    InvalidFingerprint,
}
impl std::fmt::Display for DomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::InvalidRange(field) => write!(f, "invalid range for {field}"),
            Self::InvalidClaimState => write!(f, "claim state transition is not allowed"),
            Self::InvalidTimestamp(field) => write!(
                f,
                "{field} must use canonical UTC timestamp format YYYY-MM-DDTHH:MM:SSZ"
            ),
            Self::RevisionOverflow => write!(f, "claim revision overflow"),
            Self::UnsupportedSchemaVersion(version) => {
                write!(f, "unsupported domain schema version {version}")
            }
            Self::InvalidFingerprint => write!(
                f,
                "fingerprint must be sha256 plus 64 lowercase hex characters"
            ),
        }
    }
}
impl std::error::Error for DomainError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public,
    Internal,
    Private,
    HighlySensitive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Candidate,
    Confirmed,
    Rejected,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceLocator {
    Page {
        page: u32,
    },
    Span {
        start: u64,
        end: u64,
    },
    PageSpan {
        page: u32,
        start: u64,
        end: u64,
    },
    Region {
        page: u32,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
    },
}
impl SourceLocator {
    pub fn validate(&self) -> Result<(), DomainError> {
        match self {
            Self::Page { page } if *page == 0 => Err(DomainError::InvalidRange("page")),
            Self::Span { start, end } | Self::PageSpan { start, end, .. } if start >= end => {
                Err(DomainError::InvalidRange("span"))
            }
            Self::PageSpan { page, .. } | Self::Region { page, .. } if *page == 0 => {
                Err(DomainError::InvalidRange("page"))
            }
            Self::Region { width, height, .. } if *width == 0 || *height == 0 => {
                Err(DomainError::InvalidRange("region"))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceProvenance {
    pub source_id: String,
    pub locator: SourceLocator,
    pub extractor: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Provenance {
    Source(SourceProvenance),
    UserEntered { entered_at: String },
}
impl Provenance {
    pub fn validate(&self) -> Result<(), DomainError> {
        match self {
            Self::Source(p) => {
                nonempty(&p.source_id, "source_id")?;
                p.locator.validate()
            }
            Self::UserEntered { entered_at } => {
                nonempty(entered_at, "entered_at")?;
                validate_canonical_timestamp(entered_at, "entered_at")
            }
        }
    }
    pub fn source_id(&self) -> Option<&str> {
        match self {
            Self::Source(p) => Some(&p.source_id),
            Self::UserEntered { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    pub schema_version: u16,
    pub id: String,
    /// Content digest, rather than mutable path or filename.
    pub fingerprint: String,
    pub media_type: String,
    pub title: Option<String>,
    pub captured_at: String,
    pub sensitivity: Sensitivity,
    pub expires_at: Option<String>,
}
impl Source {
    pub fn new(
        id: String,
        fingerprint: String,
        media_type: String,
        captured_at: String,
    ) -> Result<Self, DomainError> {
        nonempty(&id, "id")?;
        nonempty(&fingerprint, "fingerprint")?;
        nonempty(&media_type, "media_type")?;
        nonempty(&captured_at, "captured_at")?;
        validate_canonical_timestamp(&captured_at, "captured_at")?;
        let source = Self {
            schema_version: SCHEMA_VERSION,
            id,
            fingerprint,
            media_type,
            title: None,
            captured_at,
            sensitivity: Sensitivity::Private,
            expires_at: None,
        };
        source.validate()?;
        Ok(source)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        validate_schema_version(self.schema_version)?;
        nonempty(&self.id, "id")?;
        nonempty(&self.fingerprint, "fingerprint")?;
        validate_fingerprint(&self.fingerprint)?;
        nonempty(&self.media_type, "media_type")?;
        nonempty(&self.captured_at, "captured_at")?;
        validate_canonical_timestamp(&self.captured_at, "captured_at")?;
        if let Some(expires_at) = &self.expires_at {
            validate_canonical_timestamp(expires_at, "expires_at")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ValidityWindow {
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
}
impl ValidityWindow {
    pub fn validate(&self) -> Result<(), DomainError> {
        if let Some(from) = &self.valid_from {
            validate_canonical_timestamp(from, "valid_from")?;
        }
        if let Some(until) = &self.valid_until {
            validate_canonical_timestamp(until, "valid_until")?;
        }
        if let (Some(from), Some(until)) = (&self.valid_from, &self.valid_until) {
            if from > until {
                return Err(DomainError::InvalidRange("validity"));
            }
        }
        Ok(())
    }
    pub fn overlaps(&self, other: &Self) -> bool {
        self.valid_until
            .as_ref()
            .is_none_or(|end| other.valid_from.as_ref().is_none_or(|start| end >= start))
            && other
                .valid_until
                .as_ref()
                .is_none_or(|end| self.valid_from.as_ref().is_none_or(|start| end >= start))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub schema_version: u16,
    pub id: String,
    pub claim_type: String,
    pub subject: String,
    pub value: Value,
    pub status: ClaimStatus,
    pub provenance: Provenance,
    pub captured_at: String,
    pub validity: ValidityWindow,
    pub sensitivity: Sensitivity,
    pub revision: u64,
}
impl Claim {
    pub fn validate(&self) -> Result<(), DomainError> {
        validate_schema_version(self.schema_version)?;
        nonempty(&self.id, "id")?;
        nonempty(&self.claim_type, "claim_type")?;
        nonempty(&self.subject, "subject")?;
        nonempty(&self.captured_at, "captured_at")?;
        validate_canonical_timestamp(&self.captured_at, "captured_at")?;
        self.provenance.validate()?;
        self.validity.validate()
    }
    pub fn attributable(&self) -> bool {
        self.provenance.validate().is_ok()
    }
    pub fn is_active(&self) -> bool {
        matches!(self.status, ClaimStatus::Candidate | ClaimStatus::Confirmed)
    }
    pub fn transition(&mut self, status: ClaimStatus) -> Result<(), DomainError> {
        // Candidate may be confirmed or rejected; confirmed may be superseded or rejected.
        let allowed = matches!(
            (self.status, status),
            (ClaimStatus::Candidate, ClaimStatus::Confirmed)
                | (ClaimStatus::Candidate, ClaimStatus::Rejected)
                | (ClaimStatus::Confirmed, ClaimStatus::Rejected)
                | (ClaimStatus::Confirmed, ClaimStatus::Superseded)
        );
        if !allowed {
            return Err(DomainError::InvalidClaimState);
        }
        let next_revision = self
            .revision
            .checked_add(1)
            .ok_or(DomainError::RevisionOverflow)?;
        let mut next = self.clone();
        next.status = status;
        next.revision = next_revision;
        next.validate()?;
        *self = next;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictSet {
    pub id: String,
    pub claim_ids: Vec<String>,
    pub claim_type: String,
    pub subject: String,
}

/// Detect active attributable claims for one field with differing values and
/// overlapping validity windows. No value is silently selected.
pub fn detect_conflicts(claims: &[Claim]) -> Vec<ConflictSet> {
    let mut groups: BTreeMap<(String, String), Vec<&Claim>> = BTreeMap::new();
    for claim in claims
        .iter()
        .filter(|claim| claim.is_active() && claim.attributable())
    {
        groups
            .entry((claim.claim_type.clone(), claim.subject.clone()))
            .or_default()
            .push(claim);
    }
    groups
        .into_iter()
        .filter_map(|((claim_type, subject), group)| {
            let mut ids = BTreeSet::new();
            let mut duplicate_id_conflict = false;
            for (index, left) in group.iter().enumerate() {
                for right in group.iter().skip(index + 1) {
                    if left.value != right.value && left.validity.overlaps(&right.validity) {
                        if left.id == right.id {
                            duplicate_id_conflict = true;
                        }
                        ids.insert(left.id.clone());
                        ids.insert(right.id.clone());
                    }
                }
            }
            if ids.len() > 1 || duplicate_id_conflict {
                let mut claim_ids: Vec<_> = ids.into_iter().collect();
                if duplicate_id_conflict {
                    // Preserve evidence that one identifier occurred in contradictory instances.
                    claim_ids.push(claim_ids[0].clone());
                    claim_ids.sort();
                }
                Some(ConflictSet {
                    id: format!("conflict:{claim_type}:{subject}"),
                    claim_ids,
                    claim_type,
                    subject,
                })
            } else {
                None
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequiredField {
    pub claim_type: String,
    pub subject: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletenessReport {
    pub complete: bool,
    pub missing: Vec<RequiredField>,
    pub conflicts: Vec<ConflictSet>,
}
pub fn assess_completeness(required: &[RequiredField], claims: &[Claim]) -> CompletenessReport {
    let conflicts = detect_conflicts(claims);
    let missing: Vec<RequiredField> = required
        .iter()
        .filter(|field| {
            !claims.iter().any(|claim| {
                claim.is_active()
                    && claim.status == ClaimStatus::Confirmed
                    && claim.claim_type == field.claim_type
                    && claim.subject == field.subject
                    && claim.attributable()
                    && !conflicts
                        .iter()
                        .any(|set| set.claim_ids.contains(&claim.id))
            })
        })
        .cloned()
        .collect();
    CompletenessReport {
        complete: missing.is_empty() && conflicts.is_empty(),
        missing,
        conflicts,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleDraft {
    pub schema_version: u16,
    pub id: String,
    pub purpose: String,
    pub claim_ids: Vec<String>,
    pub expires_at: Option<String>,
}
impl BundleDraft {
    pub fn validate(&self) -> Result<(), DomainError> {
        validate_schema_version(self.schema_version)?;
        nonempty(&self.id, "id")?;
        nonempty(&self.purpose, "purpose")?;
        if self.claim_ids.is_empty() {
            return Err(DomainError::EmptyField("claim_ids"));
        }
        if let Some(expires_at) = &self.expires_at {
            validate_canonical_timestamp(expires_at, "expires_at")?;
        }
        Ok(())
    }
}
pub fn validate_canonical_timestamp(value: &str, field: &'static str) -> Result<(), DomainError> {
    // Canonical timestamps are UTC, second precision, and have no offset/fraction.
    let bytes = value.as_bytes();
    let valid_shape = bytes.len() == 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        });
    if !valid_shape {
        return Err(DomainError::InvalidTimestamp(field));
    }
    let year = value[0..4].parse::<u32>().unwrap();
    let month = value[5..7].parse::<u32>().unwrap();
    let day = value[8..10].parse::<u32>().unwrap();
    let hour = value[11..13].parse::<u32>().unwrap();
    let minute = value[14..16].parse::<u32>().unwrap();
    let second = value[17..19].parse::<u32>().unwrap();
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > days || hour > 23 || minute > 59 || second > 59 {
        return Err(DomainError::InvalidTimestamp(field));
    }
    Ok(())
}

fn nonempty(value: &str, field: &'static str) -> Result<(), DomainError> {
    if value.trim().is_empty() {
        Err(DomainError::EmptyField(field))
    } else {
        Ok(())
    }
}

fn validate_schema_version(version: u16) -> Result<(), DomainError> {
    if version == SCHEMA_VERSION {
        Ok(())
    } else {
        Err(DomainError::UnsupportedSchemaVersion(version))
    }
}

fn validate_fingerprint(value: &str) -> Result<(), DomainError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(DomainError::InvalidFingerprint);
    };
    if hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(DomainError::InvalidFingerprint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn claim(id: &str, value: &str, status: ClaimStatus, source: &str) -> Claim {
        Claim {
            schema_version: SCHEMA_VERSION,
            id: id.into(),
            claim_type: "purchase.date".into(),
            subject: "device:1".into(),
            value: Value::String(value.into()),
            status,
            provenance: Provenance::Source(SourceProvenance {
                source_id: source.into(),
                locator: SourceLocator::Page { page: 1 },
                extractor: None,
            }),
            captured_at: "2026-01-01T00:00:00Z".into(),
            validity: ValidityWindow::default(),
            sensitivity: Sensitivity::Private,
            revision: 0,
        }
    }
    #[test]
    fn confirmed_claim_is_attributable() {
        assert!(claim("a", "2026-01-01", ClaimStatus::Confirmed, "doc")
            .validate()
            .is_ok());
    }
    #[test]
    fn conflicting_values_are_grouped() {
        let found = detect_conflicts(&[
            claim("a", "one", ClaimStatus::Confirmed, "a"),
            claim("b", "two", ClaimStatus::Candidate, "b"),
        ]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].claim_ids, vec!["a", "b"]);
    }
    #[test]
    fn rejected_values_do_not_conflict() {
        assert!(detect_conflicts(&[
            claim("a", "one", ClaimStatus::Rejected, "a"),
            claim("b", "two", ClaimStatus::Confirmed, "b")
        ])
        .is_empty());
    }
    #[test]
    fn missing_required_field_is_reported() {
        let report = assess_completeness(
            &[RequiredField {
                claim_type: "name".into(),
                subject: "x".into(),
            }],
            &[],
        );
        assert!(!report.complete);
        assert_eq!(report.missing.len(), 1);
    }
    #[test]
    fn invalid_locator_is_rejected() {
        let mut value = claim("a", "x", ClaimStatus::Confirmed, "doc");
        value.provenance = Provenance::Source(SourceProvenance {
            source_id: "doc".into(),
            locator: SourceLocator::Page { page: 0 },
            extractor: None,
        });
        assert!(value.validate().is_err());
    }
    #[test]
    fn terminal_status_cannot_be_reopened() {
        let mut value = claim("a", "x", ClaimStatus::Confirmed, "doc");
        value.transition(ClaimStatus::Rejected).unwrap();
        assert_eq!(
            value.transition(ClaimStatus::Confirmed),
            Err(DomainError::InvalidClaimState)
        );
    }
    #[test]
    fn duplicate_claim_ids_with_contradictory_values_conflict() {
        let found = detect_conflicts(&[
            claim("a", "one", ClaimStatus::Confirmed, "a"),
            claim("a", "two", ClaimStatus::Candidate, "b"),
        ]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].claim_ids, vec!["a", "a"]);
    }
    #[test]
    fn invalid_timestamps_are_rejected() {
        let mut value = claim("a", "x", ClaimStatus::Confirmed, "doc");
        value.captured_at = "2026-01-01".into();
        assert_eq!(
            value.validate(),
            Err(DomainError::InvalidTimestamp("captured_at"))
        );
        value.captured_at = "2026-01-01T00:00:00Z".into();
        value.validity.valid_from = Some("2026-02-30T00:00:00Z".into());
        assert_eq!(
            value.validate(),
            Err(DomainError::InvalidTimestamp("valid_from"))
        );
        assert_eq!(
            Provenance::UserEntered {
                entered_at: "2026-01-01T00:00:00+00:00".into()
            }
            .validate(),
            Err(DomainError::InvalidTimestamp("entered_at"))
        );
        assert!(Source::new(
            "s".into(),
            format!("sha256:{}", "a".repeat(64)),
            "text/plain".into(),
            "2026-01-01".into()
        )
        .is_err());
        let mut source = Source::new(
            "source".into(),
            format!("sha256:{}", "d".repeat(64)),
            "text/plain".into(),
            "2026-01-01T00:00:00Z".into(),
        )
        .unwrap();
        source.expires_at = Some("2026-99-01T00:00:00Z".into());
        assert_eq!(
            source.validate(),
            Err(DomainError::InvalidTimestamp("expires_at"))
        );
        let bundle = BundleDraft {
            schema_version: SCHEMA_VERSION,
            id: "bundle".into(),
            purpose: "test".into(),
            claim_ids: vec!["a".into()],
            expires_at: Some("2026-01-01".into()),
        };
        assert_eq!(
            bundle.validate(),
            Err(DomainError::InvalidTimestamp("expires_at"))
        );
    }
    #[test]
    fn illegal_transition_does_not_mutate_claim() {
        let mut value = claim("a", "x", ClaimStatus::Confirmed, "doc");
        assert_eq!(
            value.transition(ClaimStatus::Candidate),
            Err(DomainError::InvalidClaimState)
        );
        assert_eq!(value.status, ClaimStatus::Confirmed);
        assert_eq!(value.revision, 0);
    }
    #[test]
    fn revision_overflow_is_rejected_without_mutation() {
        let mut value = claim("a", "x", ClaimStatus::Candidate, "doc");
        value.revision = u64::MAX;
        assert_eq!(
            value.transition(ClaimStatus::Confirmed),
            Err(DomainError::RevisionOverflow)
        );
        assert_eq!(value.status, ClaimStatus::Candidate);
        assert_eq!(value.revision, u64::MAX);
    }
    #[test]
    fn source_json_round_trip_preserves_contract() {
        let source = Source::new(
            "s".into(),
            format!("sha256:{}", "a".repeat(64)),
            "text/plain".into(),
            "2026-01-01T00:00:00Z".into(),
        )
        .unwrap();
        let encoded = serde_json::to_string(&source).unwrap();
        assert_eq!(serde_json::from_str::<Source>(&encoded).unwrap(), source);
    }

    #[test]
    fn unknown_schema_versions_are_rejected() {
        let mut source = Source::new(
            "s".into(),
            format!("sha256:{}", "a".repeat(64)),
            "text/plain".into(),
            "2026-01-01T00:00:00Z".into(),
        )
        .unwrap();
        source.schema_version = 2;
        assert_eq!(
            source.validate(),
            Err(DomainError::UnsupportedSchemaVersion(2))
        );
        let mut claim = claim("a", "x", ClaimStatus::Confirmed, "doc");
        claim.schema_version = 2;
        assert_eq!(
            claim.validate(),
            Err(DomainError::UnsupportedSchemaVersion(2))
        );
        let bundle = BundleDraft {
            schema_version: 2,
            id: "bundle".into(),
            purpose: "test".into(),
            claim_ids: vec!["a".into()],
            expires_at: None,
        };
        assert_eq!(
            bundle.validate(),
            Err(DomainError::UnsupportedSchemaVersion(2))
        );
    }

    #[test]
    fn malformed_fingerprints_are_rejected() {
        assert_eq!(
            Source::new(
                "s".into(),
                "sha256:abc".into(),
                "text/plain".into(),
                "2026-01-01T00:00:00Z".into(),
            ),
            Err(DomainError::InvalidFingerprint)
        );
        assert_eq!(
            Source::new(
                "s".into(),
                format!("sha256:{}", "A".repeat(64)),
                "text/plain".into(),
                "2026-01-01T00:00:00Z".into(),
            ),
            Err(DomainError::InvalidFingerprint)
        );
    }
}
