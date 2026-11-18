//! Streaming context-pack diff engine comparing two bundles by SHA-256 payload,
//! claim lifecycle (added/removed/modified), and evidence citation overlap.

use crate::{hex_digest, EvidenceSource, ExportError, ExportedClaim, ReviewedBundle, StreamFrame};
use foliora_domain::Sensitivity;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::BufRead;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CitationOverlapMetrics {
    pub claim_jaccard: f64,
    pub evidence_jaccard: f64,
    pub shared_claims_count: usize,
    pub shared_evidence_count: usize,
    pub total_unique_claims: usize,
    pub total_unique_evidence: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimModification {
    pub id: String,
    pub before_value: Value,
    pub after_value: Value,
    pub before_sensitivity: Sensitivity,
    pub after_sensitivity: Sensitivity,
    pub provenance_changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceModification {
    pub id: String,
    pub before_fingerprint: String,
    pub after_fingerprint: String,
    pub media_type_changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimDiff {
    pub added: Vec<ExportedClaim>,
    pub removed: Vec<ExportedClaim>,
    pub modified: Vec<ClaimModification>,
    pub unchanged_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceDiff {
    pub added: Vec<EvidenceSource>,
    pub removed: Vec<EvidenceSource>,
    pub modified: Vec<EvidenceModification>,
    pub unchanged_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BundleDiffReport {
    pub bundle_a_id: String,
    pub bundle_b_id: String,
    pub payload_sha256_a: String,
    pub payload_sha256_b: String,
    pub identical_payload: bool,
    pub claims: ClaimDiff,
    pub evidence: EvidenceDiff,
    pub citation_overlap: CitationOverlapMetrics,
    pub summary: String,
}

/// Compares two reviewed bundles and computes exact SHA-256 digests, claim diffs,
/// evidence provenance shifts, and citation overlap metrics.
pub fn diff_reviewed_bundles(bundle_a: &ReviewedBundle, bundle_b: &ReviewedBundle) -> BundleDiffReport {
    let bytes_a = serde_json::to_vec(bundle_a).unwrap_or_default();
    let bytes_b = serde_json::to_vec(bundle_b).unwrap_or_default();
    let sha_a = format!("sha256:{}", hex_digest(&bytes_a));
    let sha_b = format!("sha256:{}", hex_digest(&bytes_b));
    let identical_payload = sha_a == sha_b;

    // Claims index
    let mut map_a: BTreeMap<&str, &ExportedClaim> = BTreeMap::new();
    for c in &bundle_a.claims {
        map_a.insert(&c.id, c);
    }
    let mut map_b: BTreeMap<&str, &ExportedClaim> = BTreeMap::new();
    for c in &bundle_b.claims {
        map_b.insert(&c.id, c);
    }

    let mut added_claims = Vec::new();
    let mut removed_claims = Vec::new();
    let mut modified_claims = Vec::new();
    let mut unchanged_claims_count = 0usize;

    let all_claim_keys: BTreeSet<&str> = map_a.keys().chain(map_b.keys()).copied().collect();
    for key in &all_claim_keys {
        match (map_a.get(key), map_b.get(key)) {
            (Some(a), None) => removed_claims.push((*a).clone()),
            (None, Some(b)) => added_claims.push((*b).clone()),
            (Some(a), Some(b)) => {
                let val_eq = a.value == b.value;
                let sens_eq = a.sensitivity == b.sensitivity;
                let prov_eq = a.provenance == b.provenance;
                if val_eq && sens_eq && prov_eq {
                    unchanged_claims_count += 1;
                } else {
                    modified_claims.push(ClaimModification {
                        id: (*key).to_owned(),
                        before_value: a.value.clone(),
                        after_value: b.value.clone(),
                        before_sensitivity: a.sensitivity,
                        after_sensitivity: b.sensitivity,
                        provenance_changed: !prov_eq,
                    });
                }
            }
            (None, None) => {}
        }
    }

    // Evidence index
    let mut ev_a: BTreeMap<&str, &EvidenceSource> = BTreeMap::new();
    for e in &bundle_a.evidence {
        ev_a.insert(&e.id, e);
    }
    let mut ev_b: BTreeMap<&str, &EvidenceSource> = BTreeMap::new();
    for e in &bundle_b.evidence {
        ev_b.insert(&e.id, e);
    }

    let mut added_ev = Vec::new();
    let mut removed_ev = Vec::new();
    let mut modified_ev = Vec::new();
    let mut unchanged_ev_count = 0usize;

    let all_ev_keys: BTreeSet<&str> = ev_a.keys().chain(ev_b.keys()).copied().collect();
    for key in &all_ev_keys {
        match (ev_a.get(key), ev_b.get(key)) {
            (Some(a), None) => removed_ev.push((*a).clone()),
            (None, Some(b)) => added_ev.push((*b).clone()),
            (Some(a), Some(b)) => {
                if a.fingerprint == b.fingerprint && a.media_type == b.media_type {
                    unchanged_ev_count += 1;
                } else {
                    modified_ev.push(EvidenceModification {
                        id: (*key).to_owned(),
                        before_fingerprint: a.fingerprint.clone(),
                        after_fingerprint: b.fingerprint.clone(),
                        media_type_changed: a.media_type != b.media_type,
                    });
                }
            }
            (None, None) => {}
        }
    }

    // Citation overlap calculations
    let shared_claims_count = unchanged_claims_count + modified_claims.len();
    let total_unique_claims = all_claim_keys.len();
    let claim_jaccard = if total_unique_claims > 0 {
        shared_claims_count as f64 / total_unique_claims as f64
    } else {
        1.0
    };

    let shared_evidence_count = unchanged_ev_count + modified_ev.len();
    let total_unique_evidence = all_ev_keys.len();
    let evidence_jaccard = if total_unique_evidence > 0 {
        shared_evidence_count as f64 / total_unique_evidence as f64
    } else {
        1.0
    };

    let summary = format!(
        "Diff between {} and {}: claims (+{}, -{}, ~{}, ={}), evidence (+{}, -{}, ~{}, ={}), claim overlap {:.1}%, evidence overlap {:.1}%",
        bundle_a.id,
        bundle_b.id,
        added_claims.len(),
        removed_claims.len(),
        modified_claims.len(),
        unchanged_claims_count,
        added_ev.len(),
        removed_ev.len(),
        modified_ev.len(),
        unchanged_ev_count,
        claim_jaccard * 100.0,
        evidence_jaccard * 100.0,
    );

    BundleDiffReport {
        bundle_a_id: bundle_a.id.clone(),
        bundle_b_id: bundle_b.id.clone(),
        payload_sha256_a: sha_a,
        payload_sha256_b: sha_b,
        identical_payload,
        claims: ClaimDiff {
            added: added_claims,
            removed: removed_claims,
            modified: modified_claims,
            unchanged_count: unchanged_claims_count,
        },
        evidence: EvidenceDiff {
            added: added_ev,
            removed: removed_ev,
            modified: modified_ev,
            unchanged_count: unchanged_ev_count,
        },
        citation_overlap: CitationOverlapMetrics {
            claim_jaccard,
            evidence_jaccard,
            shared_claims_count,
            shared_evidence_count,
            total_unique_claims,
            total_unique_evidence,
        },
        summary,
    }
}

/// Reconstructs a `ReviewedBundle` from a stream of JSONL frames.
pub fn read_bundle_from_jsonl<R: BufRead>(mut reader: R) -> Result<ReviewedBundle, ExportError> {
    let mut header: Option<(u16, u16, String, String, String, Option<String>)> = None;
    let mut evidence = Vec::new();
    let mut claims = Vec::new();

    let mut line = String::new();
    while reader.read_line(&mut line).map_err(|e| ExportError::Io(e.to_string()))? > 0 {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            if let Ok(frame) = serde_json::from_str::<StreamFrame>(trimmed) {
                match frame {
                    StreamFrame::Header {
                        schema_version,
                        domain_schema_version,
                        bundle_id,
                        purpose,
                        exported_at,
                        expires_at,
                        ..
                    } => {
                        header = Some((
                            schema_version,
                            domain_schema_version,
                            bundle_id,
                            purpose,
                            exported_at,
                            expires_at,
                        ));
                    }
                    StreamFrame::Evidence { source } => evidence.push(source),
                    StreamFrame::Claim { claim } => claims.push(claim),
                    StreamFrame::Audit { .. } => {}
                }
            }
        }
        line.clear();
    }

    let (schema_version, domain_schema_version, id, purpose, exported_at, expires_at) = header
        .ok_or_else(|| ExportError::Serialize("JSONL stream missing Header frame".into()))?;

    Ok(ReviewedBundle {
        schema_version,
        domain_schema_version,
        id,
        purpose,
        exported_at,
        expires_at,
        claims,
        evidence,
    })
}

/// Diff two streaming JSONL bundles directly from `BufRead` streams.
pub fn diff_jsonl_streams<R1: BufRead, R2: BufRead>(
    reader_a: R1,
    reader_b: R2,
) -> Result<BundleDiffReport, ExportError> {
    let bundle_a = read_bundle_from_jsonl(reader_a)?;
    let bundle_b = read_bundle_from_jsonl(reader_b)?;

    Ok(diff_reviewed_bundles(&bundle_a, &bundle_b))
}

/// Formats a clean Markdown summary table of the diff.
pub fn render_diff_markdown(report: &BundleDiffReport) -> String {
    let mut md = String::new();
    md.push_str(&format!("# Context Pack Diff: {} vs {}\n\n", report.bundle_a_id, report.bundle_b_id));
    md.push_str(&format!("**Summary**: {}\n\n", report.summary));
    md.push_str(&format!("- **SHA-256 A**: `{}`\n", report.payload_sha256_a));
    md.push_str(&format!("- **SHA-256 B**: `{}`\n", report.payload_sha256_b));
    md.push_str(&format!("- **Identical Payload**: {}\n\n", report.identical_payload));

    md.push_str("## Citation Overlap\n\n");
    md.push_str("| Metric | Value |\n| --- | --- |\n");
    md.push_str(&format!("| Claim Jaccard Similarity | {:.2}% |\n", report.citation_overlap.claim_jaccard * 100.0));
    md.push_str(&format!("| Evidence Jaccard Similarity | {:.2}% |\n", report.citation_overlap.evidence_jaccard * 100.0));
    md.push_str(&format!("| Shared Claims | {} / {} |\n", report.citation_overlap.shared_claims_count, report.citation_overlap.total_unique_claims));
    md.push_str(&format!("| Shared Evidence Sources | {} / {} |\n\n", report.citation_overlap.shared_evidence_count, report.citation_overlap.total_unique_evidence));

    if !report.claims.added.is_empty() {
        md.push_str("### Added Claims (+)\n\n");
        for c in &report.claims.added {
            md.push_str(&format!("- **{}** (`{}`): {:?}\n", c.id, c.claim_type, c.value));
        }
        md.push('\n');
    }

    if !report.claims.removed.is_empty() {
        md.push_str("### Removed Claims (-)\n\n");
        for c in &report.claims.removed {
            md.push_str(&format!("- **{}** (`{}`): {:?}\n", c.id, c.claim_type, c.value));
        }
        md.push('\n');
    }

    if !report.claims.modified.is_empty() {
        md.push_str("### Modified Claims (~)\n\n");
        for m in &report.claims.modified {
            md.push_str(&format!("- **{}**: {:?} -> {:?} (provenance changed: {})\n", m.id, m.before_value, m.after_value, m.provenance_changed));
        }
        md.push('\n');
    }

    md
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExportedProvenance, ReviewedBundle};
    use foliora_domain::SourceLocator;

    fn make_bundle(id: &str, claims: Vec<ExportedClaim>, evidence: Vec<EvidenceSource>) -> ReviewedBundle {
        ReviewedBundle {
            schema_version: 1,
            domain_schema_version: 1,
            id: id.into(),
            purpose: "Diff test".into(),
            exported_at: "2026-11-18T00:00:00Z".into(),
            expires_at: None,
            claims,
            evidence,
        }
    }

    fn sample_claim(id: &str, val: &str, src: Option<&str>) -> ExportedClaim {
        ExportedClaim {
            id: id.into(),
            claim_type: "policy".into(),
            subject: "target".into(),
            value: Value::String(val.into()),
            sensitivity: Sensitivity::Internal,
            provenance: ExportedProvenance {
                source_id: src.map(|s| s.to_owned()),
                locator: Some(SourceLocator::Span { start: 0, end: 10 }),
                user_entered_at: None,
            },
        }
    }

    fn sample_source(id: &str, fp: &str) -> EvidenceSource {
        EvidenceSource {
            id: id.into(),
            fingerprint: fp.into(),
            media_type: "text/plain".into(),
            title: Some(id.into()),
            captured_at: "2026-11-18T00:00:00Z".into(),
        }
    }

    #[test]
    fn diff_identical_bundles_reports_zero_changes_and_full_overlap() {
        let b1 = make_bundle(
            "b:1",
            vec![sample_claim("c:1", "val1", Some("s:1"))],
            vec![sample_source("s:1", "sha256:1111")],
        );
        let report = diff_reviewed_bundles(&b1, &b1);
        assert!(report.identical_payload);
        assert_eq!(report.claims.added.len(), 0);
        assert_eq!(report.claims.removed.len(), 0);
        assert_eq!(report.claims.modified.len(), 0);
        assert_eq!(report.claims.unchanged_count, 1);
        assert_eq!(report.citation_overlap.claim_jaccard, 1.0);
        assert_eq!(report.citation_overlap.evidence_jaccard, 1.0);
    }

    #[test]
    fn diff_detects_additions_removals_modifications_and_partial_overlap() {
        let b1 = make_bundle(
            "b:1",
            vec![
                sample_claim("c:keep", "same", Some("s:1")),
                sample_claim("c:change", "old", Some("s:1")),
                sample_claim("c:drop", "bye", Some("s:2")),
            ],
            vec![sample_source("s:1", "sha256:1111"), sample_source("s:2", "sha256:2222")],
        );

        let b2 = make_bundle(
            "b:2",
            vec![
                sample_claim("c:keep", "same", Some("s:1")),
                sample_claim("c:change", "new", Some("s:1")),
                sample_claim("c:add", "hello", Some("s:3")),
            ],
            vec![sample_source("s:1", "sha256:1111"), sample_source("s:3", "sha256:3333")],
        );

        let report = diff_reviewed_bundles(&b1, &b2);
        assert!(!report.identical_payload);
        assert_eq!(report.claims.unchanged_count, 1);
        assert_eq!(report.claims.added.len(), 1);
        assert_eq!(report.claims.added[0].id, "c:add");
        assert_eq!(report.claims.removed.len(), 1);
        assert_eq!(report.claims.removed[0].id, "c:drop");
        assert_eq!(report.claims.modified.len(), 1);
        assert_eq!(report.claims.modified[0].id, "c:change");
        assert_eq!(report.claims.modified[0].before_value, Value::String("old".into()));
        assert_eq!(report.claims.modified[0].after_value, Value::String("new".into()));

        // Evidence: s:1 kept, s:2 removed, s:3 added
        assert_eq!(report.evidence.unchanged_count, 1);
        assert_eq!(report.evidence.removed.len(), 1);
        assert_eq!(report.evidence.added.len(), 1);

        // 4 total unique claims (c:keep, c:change, c:drop, c:add). Shared = 2. Jaccard = 2/4 = 0.5
        assert_eq!(report.citation_overlap.claim_jaccard, 0.5);

        // Markdown rendering
        let md = render_diff_markdown(&report);
        assert!(md.contains("c:add"));
        assert!(md.contains("c:drop"));
        assert!(md.contains("c:change"));
    }
}
