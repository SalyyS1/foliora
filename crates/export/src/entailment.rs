//! Claim-to-evidence numerical and unit entailment verifier (`FP008`..`FP010`):
//! - `FP008`: Claim numerical quantity contradicts cited evidence source text
//! - `FP009`: Unit scale or order-of-magnitude mismatch between claim and evidence
//! - `FP010`: Directional trend or comparative polarity inversion between claim and evidence

use crate::verify::{HazardKind, PromptHazard};
use crate::{ExportedClaim, ReviewedBundle};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntailmentFinding {
    pub rule_id: String,
    pub kind: HazardKind,
    pub claim_id: String,
    pub source_id: String,
    pub field: String,
    pub detail: String,
}

impl EntailmentFinding {
    pub fn into_prompt_hazard(self) -> PromptHazard {
        PromptHazard {
            rule_id: self.rule_id,
            kind: self.kind,
            target_id: self.claim_id,
            related_target_id: Some(self.source_id),
            field: self.field,
            detail: self.detail,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitScale {
    Bytes(i32),          // power of 1024 or 1000: B=0, KB=1, MB=2, GB=3, TB=4
    DurationMillis(i32), // ms=0, sec=1, min=2, hr=3, day=4
    Percent,
    Currency(char), // '$', '€', '₫'
    Scalar,
}

#[derive(Debug, Clone)]
struct ParsedMetric {
    raw: String,
    number: f64,
    scale: UnitScale,
    anchors: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectionalTrend {
    Upward,   // increase, growth, exceed, gain, improve, higher, rise
    Downward, // decrease, drop, fall, lose, decline, lower, reduce
    Neutral,
}

#[derive(Debug, Clone)]
struct DirectionalAssertion {
    trend: DirectionalTrend,
    anchor: String,
    raw_phrase: String,
}

/// Scans a `ReviewedBundle` for claim-to-evidence entailment hazards.
/// If `source_texts` is provided, claims are verified against the full source text;
/// otherwise, claims citing an evidence entry are verified against the evidence title and metadata.
pub fn scan_bundle_entailment(
    bundle: &ReviewedBundle,
    source_texts: Option<&BTreeMap<String, String>>,
) -> Vec<EntailmentFinding> {
    let mut evidence_by_id = BTreeMap::new();
    for ev in &bundle.evidence {
        evidence_by_id.insert(&ev.id, ev);
    }

    let mut findings = Vec::new();

    for claim in &bundle.claims {
        let source_id = match &claim.provenance.source_id {
            Some(sid) => sid,
            None => continue, // User-entered claims without citations skip source entailment check
        };

        let mut claim_text = String::new();
        flatten_claim_value(&claim.value, &mut claim_text);
        if let Some(hint) = extract_claim_type_hint(&claim.claim_type) {
            claim_text.push(' ');
            claim_text.push_str(hint);
        }
        claim_text.push(' ');
        claim_text.push_str(&claim.subject);

        let evidence_text = if let Some(sources) = source_texts {
            sources.get(source_id).map(|s| s.as_str())
        } else {
            evidence_by_id
                .get(source_id)
                .and_then(|ev| ev.title.as_deref())
        };

        if let Some(ev_text) = evidence_text {
            findings.extend(verify_claim_against_evidence(
                claim,
                source_id,
                &claim_text,
                ev_text,
            ));
        }
    }

    findings
}

/// Verifies a single claim against evidence text.
pub fn verify_claim_against_evidence(
    claim: &ExportedClaim,
    source_id: &str,
    claim_text: &str,
    evidence_text: &str,
) -> Vec<EntailmentFinding> {
    let mut findings = Vec::new();

    let claim_metrics = extract_metrics(claim_text);
    let evidence_metrics = extract_metrics(evidence_text);

    // FP008 & FP009: Numerical and unit scale checks
    for cm in &claim_metrics {
        for em in &evidence_metrics {
            let shared_anchors: Vec<&String> = cm.anchors.intersection(&em.anchors).collect();
            if shared_anchors.is_empty() {
                continue;
            }
            let anchor_refs: Vec<&String> = shared_anchors.to_vec();
            let anchor = select_primary_anchor(&anchor_refs);

            // FP009: Unit scale mismatch (e.g. GB vs MB, seconds vs ms)
            if let Some(unit_err) = check_unit_scale_mismatch(cm, em, &anchor) {
                findings.push(EntailmentFinding {
                    rule_id: "FP009".to_string(),
                    kind: HazardKind::UnitScaleIncommensurability,
                    claim_id: claim.id.clone(),
                    source_id: source_id.to_string(),
                    field: "claim.value".to_string(),
                    detail: unit_err,
                });
                continue;
            }

            // FP008: Value mismatch within compatible unit scale
            if let Some(num_err) = check_numerical_mismatch(cm, em, &anchor) {
                findings.push(EntailmentFinding {
                    rule_id: "FP008".to_string(),
                    kind: HazardKind::ClaimToEvidenceNumericalMismatch,
                    claim_id: claim.id.clone(),
                    source_id: source_id.to_string(),
                    field: "claim.value".to_string(),
                    detail: num_err,
                });
            }
        }
    }

    // FP010: Directional entailment inversion
    let claim_directions = extract_directional_assertions(claim_text);
    let evidence_directions = extract_directional_assertions(evidence_text);

    for cd in &claim_directions {
        for ed in &evidence_directions {
            if cd.anchor == ed.anchor
                && cd.trend != DirectionalTrend::Neutral
                && ed.trend != DirectionalTrend::Neutral
                && cd.trend != ed.trend
            {
                let claim_trend_str = if cd.trend == DirectionalTrend::Upward {
                    "upward"
                } else {
                    "downward"
                };
                let ev_trend_str = if ed.trend == DirectionalTrend::Upward {
                    "upward"
                } else {
                    "downward"
                };
                findings.push(EntailmentFinding {
                    rule_id: "FP010".to_string(),
                    kind: HazardKind::DirectionalEntailmentInversion,
                    claim_id: claim.id.clone(),
                    source_id: source_id.to_string(),
                    field: "claim.value".to_string(),
                    detail: format!(
                        "directional entailment inversion for '{}': claim asserts {} trend ('{}') but evidence asserts {} trend ('{}')",
                        cd.anchor, claim_trend_str, cd.raw_phrase, ev_trend_str, ed.raw_phrase
                    ),
                });
            }
        }
    }

    findings
}

fn check_unit_scale_mismatch(
    claim_m: &ParsedMetric,
    ev_m: &ParsedMetric,
    anchor: &str,
) -> Option<String> {
    match (claim_m.scale, ev_m.scale) {
        (UnitScale::Bytes(c), UnitScale::Bytes(e)) if (c - e).abs() >= 1 => {
            Some(format!(
                "unit scale mismatch for '{}': claim specifies '{}' but evidence specifies '{}' (scale order divergence {})",
                anchor, claim_m.raw, ev_m.raw, (c - e).abs()
            ))
        }
        (UnitScale::DurationMillis(c), UnitScale::DurationMillis(e)) if (c - e).abs() >= 1 => {
            Some(format!(
                "unit scale mismatch for '{}': claim specifies '{}' but evidence specifies '{}' (duration scale divergence)",
                anchor, claim_m.raw, ev_m.raw
            ))
        }
        (UnitScale::Percent, UnitScale::Scalar) | (UnitScale::Scalar, UnitScale::Percent) => {
            Some(format!(
                "dimension mismatch for '{}': claim specifies '{}' while evidence specifies '{}'",
                anchor, claim_m.raw, ev_m.raw
            ))
        }
        (UnitScale::Currency(c), UnitScale::Currency(e)) if c != e => {
            Some(format!(
                "currency denomination mismatch for '{}': claim specifies '{}' while evidence specifies '{}'",
                anchor, claim_m.raw, ev_m.raw
            ))
        }
        _ => None,
    }
}

fn check_numerical_mismatch(
    claim_m: &ParsedMetric,
    ev_m: &ParsedMetric,
    anchor: &str,
) -> Option<String> {
    // Both must share the same scale family to compare normalized numeric magnitude
    let (c_norm, e_norm) = match (claim_m.scale, ev_m.scale) {
        (UnitScale::Bytes(c), UnitScale::Bytes(e)) => {
            let c_factor = 1024f64.powi(c);
            let e_factor = 1024f64.powi(e);
            (claim_m.number * c_factor, ev_m.number * e_factor)
        }
        (UnitScale::DurationMillis(c), UnitScale::DurationMillis(e)) => {
            let c_factor = match c {
                0 => 1.0,
                1 => 1000.0,
                2 => 60_000.0,
                3 => 3_600_000.0,
                _ => 86_400_000.0,
            };
            let e_factor = match e {
                0 => 1.0,
                1 => 1000.0,
                2 => 60_000.0,
                3 => 3_600_000.0,
                _ => 86_400_000.0,
            };
            (claim_m.number * c_factor, ev_m.number * e_factor)
        }
        (UnitScale::Percent, UnitScale::Percent) => (claim_m.number, ev_m.number),
        (UnitScale::Currency(c), UnitScale::Currency(e)) if c == e => (claim_m.number, ev_m.number),
        (UnitScale::Scalar, UnitScale::Scalar) => (claim_m.number, ev_m.number),
        _ => return None,
    };

    let denom = c_norm.abs().max(e_norm.abs()).max(1e-9);
    let rel_diff = (c_norm - e_norm).abs() / denom;
    if rel_diff > 1e-4 {
        Some(format!(
            "numerical quantity mismatch for '{}': claim asserts '{}' but cited evidence records '{}'",
            anchor, claim_m.raw, ev_m.raw
        ))
    } else {
        None
    }
}

fn extract_metrics(text: &str) -> Vec<ParsedMetric> {
    let mut metrics = Vec::new();
    let words: Vec<&str> = text.split_whitespace().collect();

    for (idx, &word) in words.iter().enumerate() {
        let cleaned = word.trim_matches(|c: char| {
            !c.is_alphanumeric() && c != '.' && c != '%' && c != '$' && c != '€'
        });
        if cleaned.is_empty() {
            continue;
        }

        // Try currency: $100, €50
        if cleaned.starts_with('$') || cleaned.starts_with('€') {
            let curr = cleaned.chars().next().unwrap();
            if let Ok(num) = cleaned[curr.len_utf8()..].parse::<f64>() {
                let anchors = collect_surrounding_anchors(&words, idx);
                metrics.push(ParsedMetric {
                    raw: cleaned.to_string(),
                    number: num,
                    scale: UnitScale::Currency(curr),
                    anchors,
                });
                continue;
            }
        }

        // Try percent: 99.95%
        if let Some(stripped) = cleaned.strip_suffix('%') {
            if let Ok(num) = stripped.parse::<f64>() {
                let anchors = collect_surrounding_anchors(&words, idx);
                metrics.push(ParsedMetric {
                    raw: cleaned.to_string(),
                    number: num,
                    scale: UnitScale::Percent,
                    anchors,
                });
                continue;
            }
        }

        // Check if pure number followed by unit word
        if let Ok(num) = cleaned.parse::<f64>() {
            let unit_word = words.get(idx + 1).map(|w| {
                w.trim_matches(|c: char| !c.is_alphanumeric())
                    .to_ascii_lowercase()
            });
            let (scale, raw_unit) = match unit_word.as_deref() {
                Some("b") | Some("bytes") | Some("byte") => (UnitScale::Bytes(0), "B"),
                Some("kb") | Some("kib") | Some("kilobytes") => (UnitScale::Bytes(1), "KB"),
                Some("mb") | Some("mib") | Some("megabytes") => (UnitScale::Bytes(2), "MB"),
                Some("gb") | Some("gib") | Some("gigabytes") => (UnitScale::Bytes(3), "GB"),
                Some("tb") | Some("tib") | Some("terabytes") => (UnitScale::Bytes(4), "TB"),
                Some("ms") | Some("millis") | Some("milliseconds") => {
                    (UnitScale::DurationMillis(0), "ms")
                }
                Some("s") | Some("sec") | Some("seconds") => (UnitScale::DurationMillis(1), "s"),
                Some("m") | Some("min") | Some("minutes") => (UnitScale::DurationMillis(2), "min"),
                Some("h") | Some("hr") | Some("hours") => (UnitScale::DurationMillis(3), "hr"),
                Some("d") | Some("days") => (UnitScale::DurationMillis(4), "days"),
                Some("%") | Some("percent") => (UnitScale::Percent, "%"),
                _ => (UnitScale::Scalar, ""),
            };

            let raw = if raw_unit.is_empty() {
                cleaned.to_string()
            } else {
                format!("{cleaned} {raw_unit}")
            };

            let anchors = collect_surrounding_anchors(&words, idx);
            metrics.push(ParsedMetric {
                raw,
                number: num,
                scale,
                anchors,
            });
        }
    }

    metrics
}

fn collect_surrounding_anchors(words: &[&str], target_idx: usize) -> BTreeSet<String> {
    let mut anchors = BTreeSet::new();
    let start = target_idx.saturating_sub(4);
    let end = (target_idx + 5).min(words.len());

    for &w in &words[start..end] {
        let clean = w
            .trim_matches(|c: char| !c.is_alphanumeric())
            .to_ascii_lowercase();
        if clean.len() >= 3 && !is_stopword(&clean) {
            anchors.insert(clean);
        }
    }
    anchors
}

fn select_primary_anchor(anchors: &[&String]) -> String {
    for key in &[
        "latency",
        "throughput",
        "uptime",
        "memory",
        "storage",
        "revenue",
        "cost",
        "error",
        "query",
        "speed",
    ] {
        if let Some(found) = anchors.iter().find(|a| a.as_str() == *key) {
            return (*found).clone();
        }
    }
    anchors
        .iter()
        .max_by_key(|a| a.len())
        .map(|s| (*s).clone())
        .unwrap_or_else(|| "metric".to_string())
}

fn extract_directional_assertions(text: &str) -> Vec<DirectionalAssertion> {
    let mut assertions = Vec::new();
    let words: Vec<&str> = text.split_whitespace().collect();

    for (idx, &w) in words.iter().enumerate() {
        let clean = w
            .trim_matches(|c: char| !c.is_alphanumeric())
            .to_ascii_lowercase();
        let trend = match clean.as_str() {
            "increase" | "increased" | "increasing" | "growth" | "grow" | "rose" | "rise"
            | "exceed" | "exceeded" | "higher" | "gain" | "gained" | "improved" | "positive" => {
                DirectionalTrend::Upward
            }
            "decrease" | "decreased" | "decreasing" | "drop" | "dropped" | "fall" | "fell"
            | "loss" | "lost" | "decline" | "declined" | "lower" | "reduced" | "reduce"
            | "negative" => DirectionalTrend::Downward,
            _ => DirectionalTrend::Neutral,
        };

        if trend != DirectionalTrend::Neutral {
            let anchors = collect_surrounding_anchors(&words, idx);
            if !anchors.is_empty() {
                let anchor_refs: Vec<&String> = anchors.iter().collect();
                let primary = select_primary_anchor(&anchor_refs);
                assertions.push(DirectionalAssertion {
                    trend,
                    anchor: primary,
                    raw_phrase: clean.clone(),
                });
            }
        }
    }

    assertions
}

fn is_stopword(word: &str) -> bool {
    matches!(
        word,
        "the"
            | "and"
            | "for"
            | "with"
            | "from"
            | "that"
            | "this"
            | "has"
            | "had"
            | "have"
            | "been"
            | "are"
            | "was"
            | "were"
            | "will"
            | "its"
            | "our"
            | "per"
    )
}

fn flatten_claim_value(value: &Value, out: &mut String) {
    match value {
        Value::String(s) => {
            out.push_str(s);
            out.push(' ');
        }
        Value::Number(n) => {
            out.push_str(&n.to_string());
            out.push(' ');
        }
        Value::Array(arr) => {
            for item in arr {
                flatten_claim_value(item, out);
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                out.push_str(k);
                out.push(' ');
                flatten_claim_value(v, out);
            }
        }
        _ => {}
    }
}

fn extract_claim_type_hint(claim_type: &str) -> Option<&'static str> {
    if claim_type.contains("uptime") || claim_type.contains("sla") {
        Some("uptime availability")
    } else if claim_type.contains("latency") || claim_type.contains("speed") {
        Some("latency response time")
    } else if claim_type.contains("memory") || claim_type.contains("ram") {
        Some("memory footprint capacity")
    } else if claim_type.contains("revenue") || claim_type.contains("cost") {
        Some("financial revenue cost")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foliora_domain::{Sensitivity, SourceLocator};

    fn make_test_claim(
        id: &str,
        subject: &str,
        claim_type: &str,
        text: &str,
        source_id: &str,
    ) -> ExportedClaim {
        ExportedClaim {
            id: id.to_string(),
            claim_type: claim_type.to_string(),
            subject: subject.to_string(),
            value: Value::String(text.to_string()),
            sensitivity: Sensitivity::Internal,
            provenance: crate::ExportedProvenance {
                source_id: Some(source_id.to_string()),
                locator: Some(SourceLocator::Span {
                    start: 0,
                    end: text.len() as u64,
                }),
                user_entered_at: None,
            },
        }
    }

    #[test]
    fn detects_numerical_mismatch_fp008() {
        let claim = make_test_claim(
            "claim:1",
            "database",
            "sla.latency",
            "average query latency is 45 ms",
            "src:db",
        );
        let evidence_text =
            "benchmark results confirm average query latency is 120 ms under normal load";
        let findings = verify_claim_against_evidence(
            &claim,
            "src:db",
            "average query latency is 45 ms database",
            evidence_text,
        );
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "FP008");
        assert_eq!(
            findings[0].kind,
            HazardKind::ClaimToEvidenceNumericalMismatch
        );
        assert!(findings[0].detail.contains("latency"));
    }

    #[test]
    fn detects_unit_scale_mismatch_fp009() {
        let claim = make_test_claim(
            "claim:2",
            "cache",
            "system.memory",
            "max heap memory footprint is 16 GB",
            "src:spec",
        );
        let evidence_text = "container configuration specifies max heap memory footprint is 16 MB";
        let findings = verify_claim_against_evidence(
            &claim,
            "src:spec",
            "max heap memory footprint is 16 GB cache",
            evidence_text,
        );
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "FP009");
        assert_eq!(findings[0].kind, HazardKind::UnitScaleIncommensurability);
        assert!(findings[0].detail.contains("scale order divergence"));
    }

    #[test]
    fn detects_directional_entailment_inversion_fp010() {
        let claim = make_test_claim(
            "claim:3",
            "performance",
            "metric.trend",
            "system throughput increased by 25 percent",
            "src:eval",
        );
        let evidence_text =
            "benchmark evaluation observed system throughput decreased by 25 percent";
        let findings = verify_claim_against_evidence(
            &claim,
            "src:eval",
            "system throughput increased by 25 percent performance",
            evidence_text,
        );
        let fp010 = findings.iter().find(|f| f.rule_id == "FP010");
        assert!(fp010.is_some());
        assert_eq!(
            fp010.unwrap().kind,
            HazardKind::DirectionalEntailmentInversion
        );
        assert!(fp010.unwrap().detail.contains("throughput"));
    }

    #[test]
    fn passes_when_claim_matches_evidence() {
        let claim = make_test_claim(
            "claim:4",
            "service",
            "sla.uptime",
            "monthly uptime is 99.95%",
            "src:sla",
        );
        let evidence_text =
            "vendor contract guarantees monthly uptime is 99.95% with 24/7 monitoring";
        let findings = verify_claim_against_evidence(
            &claim,
            "src:sla",
            "monthly uptime is 99.95% service",
            evidence_text,
        );
        assert!(findings.is_empty());
    }
}
