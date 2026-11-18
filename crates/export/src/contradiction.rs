//! Cross-chunk and cross-claim semantic contradiction detector (`FP005`..`FP007`):
//! - `FP005`: Unit-normalized numerical contradiction across shared entity/metric anchors
//! - `FP006`: Canonical calendar date mismatch or inverted start/expiry lifecycle window
//! - `FP007`: Opposing negation/modal polarity on high-overlap propositions

use crate::verify::{HazardKind, PromptHazard};
use crate::ReviewedBundle;
use foliora_ingestion::DocumentChunk;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContradictionSegment {
    pub id: String,
    pub subject: Option<String>,
    pub attribute_hint: Option<String>,
    pub source_id: Option<String>,
    pub field: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContradictionFinding {
    pub rule_id: String,
    pub kind: HazardKind,
    pub primary_id: String,
    pub peer_id: String,
    pub primary_source_id: Option<String>,
    pub peer_source_id: Option<String>,
    pub field: String,
    pub detail: String,
}

impl ContradictionFinding {
    pub fn into_prompt_hazard(self) -> PromptHazard {
        PromptHazard {
            rule_id: self.rule_id,
            kind: self.kind,
            target_id: self.primary_id,
            related_target_id: Some(self.peer_id),
            field: self.field,
            detail: self.detail,
        }
    }
}

/// Scans a `ReviewedBundle` for cross-claim numerical (`FP005`), temporal (`FP006`),
/// and polarity (`FP007`) contradictions.
pub fn scan_bundle_contradictions(bundle: &ReviewedBundle) -> Vec<ContradictionFinding> {
    if bundle.claims.len() < 2 {
        return Vec::new();
    }
    let mut segments = Vec::with_capacity(bundle.claims.len());
    for claim in &bundle.claims {
        let mut flat = String::new();
        flatten_value(&claim.value, &mut flat);
        let trimmed = flat.trim().to_owned();
        if trimmed.is_empty() {
            continue;
        }
        segments.push(ContradictionSegment {
            id: claim.id.clone(),
            subject: Some(claim.subject.trim().to_ascii_lowercase()),
            attribute_hint: extract_claim_type_hint(&claim.claim_type),
            source_id: claim.provenance.source_id.clone(),
            field: "claim.value".to_owned(),
            text: trimmed,
        });
    }
    scan_segments(&segments)
}

/// Scans ingested `DocumentChunk` slices across one or more documents for
/// cross-chunk numerical (`FP005`), temporal (`FP006`), and polarity (`FP007`) contradictions.
pub fn scan_chunk_contradictions(chunks: &[DocumentChunk]) -> Vec<ContradictionFinding> {
    if chunks.len() < 2 {
        return Vec::new();
    }
    let segments: Vec<ContradictionSegment> = chunks
        .iter()
        .map(|c| ContradictionSegment {
            id: c.id.clone(),
            subject: None,
            attribute_hint: None,
            source_id: Some(c.source_id.clone()),
            field: "chunk.text".to_owned(),
            text: c.text.clone(),
        })
        .collect();
    scan_segments(&segments)
}

/// Core pairwise analyzer over normalized `ContradictionSegment` records.
pub fn scan_segments(segments: &[ContradictionSegment]) -> Vec<ContradictionFinding> {
    if segments.len() < 2 {
        return Vec::new();
    }

    let analyzed: Vec<AnalyzedSegment<'_>> = segments.iter().map(analyze_segment).collect();
    let mut findings = Vec::new();
    let mut emitted_keys: BTreeSet<(String, String, &'static str)> = BTreeSet::new();

    for i in 0..analyzed.len() {
        for j in (i + 1)..analyzed.len() {
            let left = &analyzed[i];
            let right = &analyzed[j];
            if left.seg.id == right.seg.id {
                continue;
            }
            if !subjects_compatible(left, right) {
                continue;
            }
            if has_opposing_qualifiers(&left.qualifiers, &right.qualifiers) {
                continue;
            }

            if let Some(detail) = check_numerical_contradiction(left, right) {
                push_unique_finding(
                    &mut findings,
                    &mut emitted_keys,
                    HazardKind::NumericalContradiction,
                    left.seg,
                    right.seg,
                    detail,
                );
            }

            if let Some(detail) = check_temporal_contradiction(left, right) {
                push_unique_finding(
                    &mut findings,
                    &mut emitted_keys,
                    HazardKind::TemporalContradiction,
                    left.seg,
                    right.seg,
                    detail,
                );
            }

            if let Some(detail) = check_polarity_contradiction(left, right) {
                push_unique_finding(
                    &mut findings,
                    &mut emitted_keys,
                    HazardKind::PolarityContradiction,
                    left.seg,
                    right.seg,
                    detail,
                );
            }
        }
    }

    findings
}

fn push_unique_finding(
    findings: &mut Vec<ContradictionFinding>,
    emitted: &mut BTreeSet<(String, String, &'static str)>,
    kind: HazardKind,
    left: &ContradictionSegment,
    right: &ContradictionSegment,
    detail: String,
) {
    let (a, b) = if left.id <= right.id {
        (left.id.clone(), right.id.clone())
    } else {
        (right.id.clone(), left.id.clone())
    };
    let rule = kind.rule_id();
    if emitted.insert((a, b, rule)) {
        findings.push(ContradictionFinding {
            rule_id: rule.to_owned(),
            kind,
            primary_id: left.id.clone(),
            peer_id: right.id.clone(),
            primary_source_id: left.source_id.clone(),
            peer_source_id: right.source_id.clone(),
            field: left.field.clone(),
            detail,
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitFamily {
    Bytes,
    DurationSeconds,
    Percent,
    CurrencyUsd,
    CurrencyEur,
    CurrencyVnd,
    Scalar,
}

#[derive(Debug, Clone)]
struct ExtractedQuantity {
    family: UnitFamily,
    canonical_value: f64,
    raw_display: String,
    anchors: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TemporalRole {
    Start,
    End,
    Milestone,
}

#[derive(Debug, Clone)]
struct ExtractedDate {
    year: i32,
    month: u32,
    day: u32,
    ordinal_days: i64,
    iso_display: String,
    role: TemporalRole,
    anchors: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct PolarityProposition {
    predicate: &'static str,
    sign: i8,
    raw_phrase: String,
}

struct AnalyzedSegment<'a> {
    seg: &'a ContradictionSegment,
    content_tokens: BTreeSet<String>,
    qualifiers: BTreeSet<&'static str>,
    quantities: Vec<ExtractedQuantity>,
    dates: Vec<ExtractedDate>,
    propositions: Vec<PolarityProposition>,
}

fn analyze_segment(seg: &ContradictionSegment) -> AnalyzedSegment<'_> {
    let mut text_with_hint = String::new();
    if let Some(hint) = &seg.attribute_hint {
        text_with_hint.push_str(hint);
        text_with_hint.push(' ');
    }
    text_with_hint.push_str(&seg.text);

    let (dates, date_byte_ranges) =
        extract_dates_and_ranges(&seg.text, seg.attribute_hint.as_deref());
    let masked_for_numbers = mask_ranges(&seg.text, &date_byte_ranges);
    let quantities = extract_quantities(&masked_for_numbers, seg.attribute_hint.as_deref());
    let raw_words = extract_word_sequence(&text_with_hint);
    let qualifiers = collect_qualifiers(&raw_words);
    let content_tokens = collect_content_tokens(&raw_words);
    let propositions = extract_polarity_propositions(&raw_words);

    AnalyzedSegment {
        seg,
        content_tokens,
        qualifiers,
        quantities,
        dates,
        propositions,
    }
}

fn subjects_compatible(left: &AnalyzedSegment<'_>, right: &AnalyzedSegment<'_>) -> bool {
    match (&left.seg.subject, &right.seg.subject) {
        (Some(sa), Some(sb)) => sa == sb,
        _ => true,
    }
}

fn check_numerical_contradiction(
    left: &AnalyzedSegment<'_>,
    right: &AnalyzedSegment<'_>,
) -> Option<String> {
    if left.quantities.is_empty() || right.quantities.is_empty() {
        return None;
    }
    let explicit_same_subject = left.seg.subject.is_some() && left.seg.subject == right.seg.subject;
    let global_jaccard = token_jaccard(&left.content_tokens, &right.content_tokens);

    for qa in &left.quantities {
        for qb in &right.quantities {
            if qa.family != qb.family {
                continue;
            }
            let shared_anchors: Vec<&String> = qa.anchors.intersection(&qb.anchors).collect();
            if shared_anchors.is_empty() {
                continue;
            }
            // Scalar counts without explicit dimensional units require stronger lexical overlap.
            let min_jaccard = match (explicit_same_subject, qa.family) {
                (true, UnitFamily::Scalar) => 0.25,
                (true, _) => 0.10,
                (false, UnitFamily::Scalar) => 0.35,
                (false, _) => 0.20,
            };
            if global_jaccard < min_jaccard && shared_anchors.len() < 2 {
                continue;
            }

            let denom = qa
                .canonical_value
                .abs()
                .max(qb.canonical_value.abs())
                .max(1e-9);
            let rel_diff = (qa.canonical_value - qb.canonical_value).abs() / denom;
            if rel_diff > 1e-6 {
                let anchor_label = shared_anchors[0];
                return Some(format!(
                    "conflicting numerical values for '{}': '{}' ({}) vs '{}' ({})",
                    anchor_label, qa.raw_display, left.seg.id, qb.raw_display, right.seg.id
                ));
            }
        }
    }
    None
}

fn check_temporal_contradiction(
    left: &AnalyzedSegment<'_>,
    right: &AnalyzedSegment<'_>,
) -> Option<String> {
    if left.dates.is_empty() || right.dates.is_empty() {
        return None;
    }
    let explicit_same_subject = left.seg.subject.is_some() && left.seg.subject == right.seg.subject;
    let global_jaccard = token_jaccard(&left.content_tokens, &right.content_tokens);

    for da in &left.dates {
        for db in &right.dates {
            let shared_anchors: Vec<&String> = da.anchors.intersection(&db.anchors).collect();
            let context_aligned = explicit_same_subject
                || !shared_anchors.is_empty() && global_jaccard >= 0.20
                || shared_anchors.len() >= 2;
            if !context_aligned {
                continue;
            }

            match (da.role, db.role) {
                (TemporalRole::Start, TemporalRole::End) => {
                    if da.ordinal_days > db.ordinal_days {
                        return Some(format!(
                            "inverted lifecycle window: start date {} ({}) is after expiration/end date {} ({})",
                            da.iso_display, left.seg.id, db.iso_display, right.seg.id
                        ));
                    }
                }
                (TemporalRole::End, TemporalRole::Start) => {
                    if db.ordinal_days > da.ordinal_days {
                        return Some(format!(
                            "inverted lifecycle window: start date {} ({}) is after expiration/end date {} ({})",
                            db.iso_display, right.seg.id, da.iso_display, left.seg.id
                        ));
                    }
                }
                (role_a, role_b) if role_a == role_b => {
                    // For generic milestones without Start/End verbs, require shared event anchor.
                    if role_a == TemporalRole::Milestone && shared_anchors.is_empty() {
                        continue;
                    }
                    if (da.year, da.month, da.day) != (db.year, db.month, db.day) {
                        let label =
                            shared_anchors
                                .first()
                                .map(|s| s.as_str())
                                .unwrap_or(match role_a {
                                    TemporalRole::Start => "effective_date",
                                    TemporalRole::End => "expiration_date",
                                    TemporalRole::Milestone => "milestone_date",
                                });
                        return Some(format!(
                            "conflicting calendar dates for '{}': {} ({}) vs {} ({})",
                            label, da.iso_display, left.seg.id, db.iso_display, right.seg.id
                        ));
                    }
                }
                _ => {}
            }
        }
    }
    None
}

fn check_polarity_contradiction(
    left: &AnalyzedSegment<'_>,
    right: &AnalyzedSegment<'_>,
) -> Option<String> {
    if left.propositions.is_empty() || right.propositions.is_empty() {
        return None;
    }
    let shared_count = left
        .content_tokens
        .intersection(&right.content_tokens)
        .count();
    let jaccard = token_jaccard(&left.content_tokens, &right.content_tokens);
    let explicit_same_subject = left.seg.subject.is_some() && left.seg.subject == right.seg.subject;
    let min_jaccard = if explicit_same_subject { 0.30 } else { 0.40 };
    let min_shared = if explicit_same_subject { 1 } else { 2 };

    if shared_count < min_shared || jaccard < min_jaccard {
        return None;
    }

    for pa in &left.propositions {
        for pb in &right.propositions {
            if pa.predicate == pb.predicate && pa.sign != pb.sign {
                return Some(format!(
                    "opposing modal/boolean polarity on '{}': '{}' ({}) contradicts '{}' ({})",
                    pa.predicate, pa.raw_phrase, left.seg.id, pb.raw_phrase, right.seg.id
                ));
            }
        }
    }
    None
}

fn collect_qualifiers(words: &[String]) -> BTreeSet<&'static str> {
    let mut out = BTreeSet::new();
    for w in words {
        match w.as_str() {
            "min" | "minimum" | "floor" => {
                out.insert("bound:min");
            }
            "max" | "maximum" | "ceiling" => {
                out.insert("bound:max");
            }
            "p50" | "median" => {
                out.insert("pct:p50");
            }
            "p95" => {
                out.insert("pct:p95");
            }
            "p99" => {
                out.insert("pct:p99");
            }
            "soft" => {
                out.insert("tier:soft");
            }
            "hard" => {
                out.insert("tier:hard");
            }
            "inbound" | "ingress" => {
                out.insert("dir:in");
            }
            "outbound" | "egress" => {
                out.insert("dir:out");
            }
            "read" => {
                out.insert("io:read");
            }
            "write" => {
                out.insert("io:write");
            }
            "client" => {
                out.insert("side:client");
            }
            "server" => {
                out.insert("side:server");
            }
            _ => {}
        }
    }
    out
}

fn has_opposing_qualifiers(left: &BTreeSet<&'static str>, right: &BTreeSet<&'static str>) -> bool {
    const PAIRS: &[(&str, &str)] = &[
        ("bound:min", "bound:max"),
        ("pct:p50", "pct:p95"),
        ("pct:p50", "pct:p99"),
        ("pct:p95", "pct:p99"),
        ("tier:soft", "tier:hard"),
        ("dir:in", "dir:out"),
        ("io:read", "io:write"),
        ("side:client", "side:server"),
    ];
    for &(a, b) in PAIRS {
        if (left.contains(a) && right.contains(b)) || (left.contains(b) && right.contains(a)) {
            return true;
        }
    }
    false
}

fn extract_quantities(text: &str, hint: Option<&str>) -> Vec<ExtractedQuantity> {
    let tokens = tokenize_positioned(text);
    let mut out = Vec::new();
    let mut idx = 0usize;

    while idx < tokens.len() {
        let tok = &tokens[idx];
        // Check leading currency prefix like "$1,200" or "$49.99"
        if let Some(rest) = tok.raw.strip_prefix('$') {
            if let Some(val) = parse_standalone_number(rest) {
                let anchors = build_anchor_window(&tokens, idx, idx, hint);
                if !anchors.is_empty() {
                    out.push(ExtractedQuantity {
                        family: UnitFamily::CurrencyUsd,
                        canonical_value: val,
                        raw_display: tok.raw.clone(),
                        anchors,
                    });
                }
                idx += 1;
                continue;
            }
        }

        // Check "USD 1200" / "EUR 500"
        if let Some(curr_family) = currency_prefix_unit(&tok.lower) {
            if let Some(next_tok) = tokens.get(idx + 1) {
                if let Some(val) = parse_standalone_number(&next_tok.raw) {
                    let anchors = build_anchor_window(&tokens, idx, idx + 1, hint);
                    if !anchors.is_empty() {
                        out.push(ExtractedQuantity {
                            family: curr_family,
                            canonical_value: val,
                            raw_display: format!("{} {}", tok.raw, next_tok.raw),
                            anchors,
                        });
                    }
                    idx += 2;
                    continue;
                }
            }
        }

        // Check number with attached unit suffix (e.g. "99.95%", "500ms", "10GiB")
        if let Some((val, unit_str)) = split_number_and_unit(&tok.raw) {
            if let Some((family, scale)) = classify_unit(&unit_str.to_ascii_lowercase()) {
                let anchors = build_anchor_window(&tokens, idx, idx, hint);
                if !anchors.is_empty() {
                    out.push(ExtractedQuantity {
                        family,
                        canonical_value: val * scale,
                        raw_display: tok.raw.clone(),
                        anchors,
                    });
                }
                idx += 1;
                continue;
            }
        }

        // Check standalone number followed by separate unit token ("10 GiB", "2000 ms", "1200 USD")
        if let Some(val) = parse_standalone_number(&tok.raw) {
            if let Some(next_tok) = tokens.get(idx + 1) {
                if let Some((family, scale)) = classify_unit(&next_tok.lower) {
                    let anchors = build_anchor_window(&tokens, idx, idx + 1, hint);
                    if !anchors.is_empty() {
                        out.push(ExtractedQuantity {
                            family,
                            canonical_value: val * scale,
                            raw_display: format!("{} {}", tok.raw, next_tok.raw),
                            anchors,
                        });
                    }
                    idx += 2;
                    continue;
                }
            }

            let anchors = build_anchor_window(&tokens, idx, idx, hint);
            if !anchors.is_empty() {
                out.push(ExtractedQuantity {
                    family: UnitFamily::Scalar,
                    canonical_value: val,
                    raw_display: tok.raw.clone(),
                    anchors,
                });
            }
        }

        idx += 1;
    }

    out
}

fn currency_prefix_unit(lower: &str) -> Option<UnitFamily> {
    match lower {
        "usd" => Some(UnitFamily::CurrencyUsd),
        "eur" => Some(UnitFamily::CurrencyEur),
        "vnd" => Some(UnitFamily::CurrencyVnd),
        _ => None,
    }
}

fn classify_unit(unit_lower: &str) -> Option<(UnitFamily, f64)> {
    match unit_lower {
        "%" | "percent" | "pct" => Some((UnitFamily::Percent, 1.0)),
        "b" | "byte" | "bytes" => Some((UnitFamily::Bytes, 1.0)),
        "kb" => Some((UnitFamily::Bytes, 1_000.0)),
        "kib" => Some((UnitFamily::Bytes, 1_024.0)),
        "mb" => Some((UnitFamily::Bytes, 1_000_000.0)),
        "mib" => Some((UnitFamily::Bytes, 1_048_576.0)),
        "gb" => Some((UnitFamily::Bytes, 1_000_000_000.0)),
        "gib" => Some((UnitFamily::Bytes, 1_073_741_824.0)),
        "tb" => Some((UnitFamily::Bytes, 1_000_000_000_000.0)),
        "tib" => Some((UnitFamily::Bytes, 1_099_511_627_776.0)),
        "ms" | "millisecond" | "milliseconds" => Some((UnitFamily::DurationSeconds, 0.001)),
        "s" | "sec" | "secs" | "second" | "seconds" => Some((UnitFamily::DurationSeconds, 1.0)),
        "min" | "mins" | "minute" | "minutes" => Some((UnitFamily::DurationSeconds, 60.0)),
        "h" | "hr" | "hrs" | "hour" | "hours" => Some((UnitFamily::DurationSeconds, 3_600.0)),
        "d" | "day" | "days" => Some((UnitFamily::DurationSeconds, 86_400.0)),
        "usd" | "dollar" | "dollars" => Some((UnitFamily::CurrencyUsd, 1.0)),
        "eur" | "euro" | "euros" => Some((UnitFamily::CurrencyEur, 1.0)),
        "vnd" => Some((UnitFamily::CurrencyVnd, 1.0)),
        _ => None,
    }
}

fn parse_standalone_number(raw: &str) -> Option<f64> {
    let trimmed = raw.trim_matches(|c: char| matches!(c, '(' | ')' | ',' | '.' | ';' | ':'));
    if trimmed.is_empty() {
        return None;
    }
    // Reject technical identifiers containing hyphens, slashes, multiple dots, or letters
    if trimmed
        .chars()
        .any(|c| !c.is_ascii_digit() && c != ',' && c != '.')
    {
        return None;
    }
    if trimmed.matches('.').count() > 1 {
        return None;
    }
    let clean: String = trimmed.chars().filter(|&c| c != ',').collect();
    if clean.is_empty() || !clean.chars().any(|c| c.is_ascii_digit()) {
        return None;
    }
    let val = clean.parse::<f64>().ok()?;
    if val.is_finite() {
        Some(val)
    } else {
        None
    }
}

fn split_number_and_unit(raw: &str) -> Option<(f64, &str)> {
    let trimmed = raw.trim_matches(|c: char| matches!(c, '(' | ')' | ',' | ';' | ':'));
    if trimmed.is_empty() {
        return None;
    }
    // Must start with ASCII digit (prevents matching "sha256", "v2", "p99", "ap-southeast-1").
    if !trimmed.as_bytes()[0].is_ascii_digit() {
        return None;
    }
    let mut split_at = None;
    for (idx, ch) in trimmed.char_indices() {
        if !ch.is_ascii_digit() && ch != ',' && ch != '.' {
            split_at = Some(idx);
            break;
        }
    }
    let pos = split_at?;
    let num_part = &trimmed[..pos];
    let unit_part = &trimmed[pos..];
    if unit_part.is_empty() {
        return None;
    }
    let val = parse_standalone_number(num_part)?;
    Some((val, unit_part))
}

#[derive(Debug, Clone)]
struct PositionedToken {
    raw: String,
    lower: String,
}

fn tokenize_positioned(text: &str) -> Vec<PositionedToken> {
    text.split_whitespace()
        .filter_map(|raw| {
            let trimmed = raw.trim_matches(|c: char| {
                matches!(c, '"' | '\'' | '(' | ')' | '[' | ']' | ';' | ':')
            });
            if trimmed.is_empty() {
                None
            } else {
                Some(PositionedToken {
                    raw: trimmed.to_owned(),
                    lower: trimmed.to_ascii_lowercase(),
                })
            }
        })
        .collect()
}

fn build_anchor_window(
    tokens: &[PositionedToken],
    start_idx: usize,
    end_idx: usize,
    hint: Option<&str>,
) -> BTreeSet<String> {
    let mut anchors = BTreeSet::new();
    if let Some(h) = hint {
        for w in extract_word_sequence(h) {
            if is_meaningful_anchor(&w) {
                anchors.insert(normalize_stem(&w));
            }
        }
    }
    let lo = start_idx.saturating_sub(4);
    let hi = (end_idx + 5).min(tokens.len());
    for (idx, tok) in tokens.iter().enumerate().take(hi).skip(lo) {
        if idx >= start_idx && idx <= end_idx {
            continue;
        }
        for w in extract_word_sequence(&tok.lower) {
            if is_meaningful_anchor(&w) {
                anchors.insert(normalize_stem(&w));
            }
        }
    }
    anchors
}

fn is_meaningful_anchor(word: &str) -> bool {
    word.len() >= 3
        && word.chars().all(|c| c.is_alphabetic())
        && classify_unit(word).is_none()
        && !is_common_stopword(word)
}

fn extract_dates_and_ranges(
    text: &str,
    hint: Option<&str>,
) -> (Vec<ExtractedDate>, Vec<(usize, usize)>) {
    let mut dates = Vec::new();
    let mut ranges = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;

    // 1. Scan ISO-8601 YYYY-MM-DD (and optional THH:MM:SSZ suffix) or YYYY/MM/DD or DD/MM/YYYY
    while i + 10 <= bytes.len() {
        let prev_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        if prev_ok {
            if let Some((y, m, d, consumed)) = try_parse_numeric_date_at(&text[i..]) {
                let end = i + consumed;
                let next_ok = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
                if next_ok {
                    if let Some(ordinal) = checked_civil_days(y, m, d) {
                        let (role, anchors) = infer_temporal_context(text, i, end, hint);
                        dates.push(ExtractedDate {
                            year: y,
                            month: m,
                            day: d,
                            ordinal_days: ordinal,
                            iso_display: format!("{y:04}-{m:02}-{d:02}"),
                            role,
                            anchors,
                        });
                        ranges.push((i, end));
                        i = end;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }

    // 2. Scan English month-name dates: "December 31, 2027" or "31 December 2027"
    let word_spans = collect_word_byte_spans(text);
    let mut w_idx = 0usize;
    while w_idx + 2 < word_spans.len() {
        let (s0, _, w0) = &word_spans[w_idx];
        let (_, _, w1) = &word_spans[w_idx + 1];
        let (_, e2, w2) = &word_spans[w_idx + 2];

        // Avoid re-parsing ranges already covered
        if ranges.iter().any(|&(rs, re)| *s0 < re && *e2 > rs) {
            w_idx += 1;
            continue;
        }

        // Pattern A: Month DD, YYYY
        if let Some(month) = month_from_name(w0) {
            if let (Ok(day), Ok(year)) = (w1.parse::<u32>(), w2.parse::<i32>()) {
                // Check only whitespace/comma between w0..w1..w2
                if (1900..=2200).contains(&year) {
                    if let Some(ordinal) = checked_civil_days(year, month, day) {
                        let (role, anchors) = infer_temporal_context(text, *s0, *e2, hint);
                        dates.push(ExtractedDate {
                            year,
                            month,
                            day,
                            ordinal_days: ordinal,
                            iso_display: format!("{year:04}-{month:02}-{day:02}"),
                            role,
                            anchors,
                        });
                        ranges.push((*s0, *e2));
                        w_idx += 3;
                        continue;
                    }
                }
            }
        }

        // Pattern B: DD Month YYYY
        if let Some(month) = month_from_name(w1) {
            if let (Ok(day), Ok(year)) = (w0.parse::<u32>(), w2.parse::<i32>()) {
                if (1900..=2200).contains(&year) {
                    if let Some(ordinal) = checked_civil_days(year, month, day) {
                        let (role, anchors) = infer_temporal_context(text, *s0, *e2, hint);
                        dates.push(ExtractedDate {
                            year,
                            month,
                            day,
                            ordinal_days: ordinal,
                            iso_display: format!("{year:04}-{month:02}-{day:02}"),
                            role,
                            anchors,
                        });
                        ranges.push((*s0, *e2));
                        w_idx += 3;
                        continue;
                    }
                }
            }
        }

        w_idx += 1;
    }

    (dates, ranges)
}

fn try_parse_numeric_date_at(slice: &str) -> Option<(i32, u32, u32, usize)> {
    let b = slice.as_bytes();
    if b.len() < 10 {
        return None;
    }
    // YYYY-MM-DD or YYYY/MM/DD
    if b[0..4].iter().all(u8::is_ascii_digit)
        && (b[4] == b'-' || b[4] == b'/')
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b[4]
        && b[8..10].iter().all(u8::is_ascii_digit)
    {
        let year = slice[0..4].parse::<i32>().ok()?;
        let month = slice[5..7].parse::<u32>().ok()?;
        let day = slice[8..10].parse::<u32>().ok()?;
        if !(1900..=2200).contains(&year) {
            return None;
        }
        let mut consumed = 10usize;
        // Consume optional ISO timestamp suffix YYYY-MM-DDTHH:MM:SSZ
        if b.len() >= 20
            && b[10] == b'T'
            && b[11..13].iter().all(u8::is_ascii_digit)
            && b[13] == b':'
            && b[14..16].iter().all(u8::is_ascii_digit)
            && b[16] == b':'
            && b[17..19].iter().all(u8::is_ascii_digit)
            && b[19] == b'Z'
        {
            consumed = 20;
        }
        return Some((year, month, day, consumed));
    }

    // DD/MM/YYYY
    if b[0..2].iter().all(u8::is_ascii_digit)
        && b[2] == b'/'
        && b[3..5].iter().all(u8::is_ascii_digit)
        && b[5] == b'/'
        && b[6..10].iter().all(u8::is_ascii_digit)
    {
        let day = slice[0..2].parse::<u32>().ok()?;
        let month = slice[3..5].parse::<u32>().ok()?;
        let year = slice[6..10].parse::<i32>().ok()?;
        if (1900..=2200).contains(&year) {
            return Some((year, month, day, 10));
        }
    }

    None
}

fn month_from_name(lower: &str) -> Option<u32> {
    match lower {
        "january" | "jan" => Some(1),
        "february" | "feb" => Some(2),
        "march" | "mar" => Some(3),
        "april" | "apr" => Some(4),
        "may" => Some(5),
        "june" | "jun" => Some(6),
        "july" | "jul" => Some(7),
        "august" | "aug" => Some(8),
        "september" | "sep" | "sept" => Some(9),
        "october" | "oct" => Some(10),
        "november" | "nov" => Some(11),
        "december" | "dec" => Some(12),
        _ => None,
    }
}

fn checked_civil_days(year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || day < 1 {
        return None;
    }
    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap {
                29
            } else {
                28
            }
        }
        _ => return None,
    };
    if day > max_day {
        return None;
    }

    // Howard Hinnant civil-from-days proleptic Gregorian algorithm
    let y = (year as i64) - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = month as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + (day as u64) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + (doe as i64) - 719468)
}

fn infer_temporal_context(
    text: &str,
    byte_start: usize,
    byte_end: usize,
    hint: Option<&str>,
) -> (TemporalRole, BTreeSet<String>) {
    let prefix_lo = floor_char_boundary(text, byte_start.saturating_sub(64));
    let suffix_hi = ceil_char_boundary(text, (byte_end + 48).min(text.len()));
    let mut ctx_words = Vec::new();
    if let Some(h) = hint {
        ctx_words.extend(extract_word_sequence(h));
    }
    ctx_words.extend(extract_word_sequence(&text[prefix_lo..byte_start]));
    ctx_words.extend(extract_word_sequence(&text[byte_end..suffix_hi]));

    let mut role = TemporalRole::Milestone;
    for w in &ctx_words {
        match w.as_str() {
            "effective" | "start" | "starts" | "started" | "commence" | "commences" | "begin"
            | "begins" | "signed" | "issued" | "launch" | "launched" => {
                role = TemporalRole::Start;
                break;
            }
            "expire" | "expires" | "expired" | "expiry" | "expiration" | "end" | "ends"
            | "terminate" | "terminates" | "termination" | "until" | "through" | "deadline"
            | "due" => {
                role = TemporalRole::End;
                break;
            }
            _ => {}
        }
    }

    let mut anchors = BTreeSet::new();
    for w in ctx_words {
        if month_from_name(&w).is_some() {
            continue;
        }
        if is_meaningful_anchor(&w) && !is_temporal_role_verb(&w) {
            anchors.insert(normalize_stem(&w));
        }
    }
    (role, anchors)
}

fn is_temporal_role_verb(word: &str) -> bool {
    matches!(
        word,
        "effective"
            | "start"
            | "starts"
            | "started"
            | "begin"
            | "begins"
            | "expire"
            | "expires"
            | "expired"
            | "expiry"
            | "expiration"
            | "end"
            | "ends"
            | "until"
            | "through"
    )
}

fn mask_ranges(text: &str, ranges: &[(usize, usize)]) -> String {
    if ranges.is_empty() {
        return text.to_owned();
    }
    let mut bytes = text.as_bytes().to_vec();
    let len = bytes.len();
    for &(start, end) in ranges {
        for b in bytes.iter_mut().take(end.min(len)).skip(start) {
            *b = b' ';
        }
    }
    String::from_utf8(bytes).unwrap_or_else(|_| text.to_owned())
}

fn extract_polarity_propositions(words: &[String]) -> Vec<PolarityProposition> {
    let mut out = Vec::new();
    for (idx, w) in words.iter().enumerate() {
        let Some((predicate, base_sign)) = classify_polarity_word(w) else {
            continue;
        };
        let window_lo = idx.saturating_sub(3);
        let negated = words[window_lo..idx].iter().any(|prev| is_negator(prev));
        let sign = if negated { -base_sign } else { base_sign };
        let phrase = if negated {
            format!("not {w}")
        } else {
            w.clone()
        };
        out.push(PolarityProposition {
            predicate,
            sign,
            raw_phrase: phrase,
        });
    }
    out
}

fn classify_polarity_word(word: &str) -> Option<(&'static str, i8)> {
    match word {
        "enabled" | "enable" | "active" => Some(("enabled_state", 1)),
        "disabled" | "disable" | "inactive" => Some(("enabled_state", -1)),
        "required" | "mandatory" | "enforced" => Some(("requirement_state", 1)),
        "optional" | "unnecessary" => Some(("requirement_state", -1)),
        "allowed" | "permitted" | "authorized" => Some(("permission_state", 1)),
        "prohibited" | "forbidden" | "disallowed" | "blocked" => Some(("permission_state", -1)),
        "encrypted" => Some(("encryption_state", 1)),
        "unencrypted" | "plaintext" => Some(("encryption_state", -1)),
        "supported" => Some(("support_state", 1)),
        "unsupported" => Some(("support_state", -1)),
        _ => None,
    }
}

fn is_negator(word: &str) -> bool {
    matches!(
        word,
        "not" | "never" | "no" | "without" | "cannot" | "neither" | "non"
    )
}

fn collect_content_tokens(words: &[String]) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for w in words {
        if w.len() < 3
            || is_common_stopword(w)
            || is_negator(w)
            || classify_polarity_word(w).is_some()
            || classify_unit(w).is_some()
            || month_from_name(w).is_some()
            || w.chars().all(|c| c.is_ascii_digit())
        {
            continue;
        }
        set.insert(normalize_stem(w));
    }
    set
}

fn normalize_stem(word: &str) -> String {
    if word.len() > 5 {
        if let Some(stem) = word.strip_suffix("ies") {
            return format!("{stem}y");
        }
    }
    if word.len() > 4 && word.ends_with('s') && !word.ends_with("ss") {
        return word[..word.len() - 1].to_owned();
    }
    word.to_owned()
}

fn is_common_stopword(word: &str) -> bool {
    matches!(
        word,
        "the"
            | "and"
            | "for"
            | "with"
            | "that"
            | "this"
            | "from"
            | "into"
            | "onto"
            | "are"
            | "was"
            | "were"
            | "has"
            | "have"
            | "had"
            | "will"
            | "shall"
            | "all"
            | "any"
            | "per"
            | "must"
            | "may"
            | "can"
    )
}

fn token_jaccard(a: &BTreeSet<String>, b: &BTreeSet<String>) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let inter = a.intersection(b).count();
    let union = a.union(b).count();
    if union == 0 {
        0.0
    } else {
        (inter as f64) / (union as f64)
    }
}

fn extract_word_sequence(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        if ch.is_alphanumeric() {
            for lc in ch.to_lowercase() {
                cur.push(lc);
            }
        } else if !cur.is_empty() {
            words.push(cur.clone());
            cur.clear();
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

fn collect_word_byte_spans(text: &str) -> Vec<(usize, usize, String)> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    let mut buf = String::new();

    for (idx, ch) in text.char_indices() {
        if ch.is_ascii_alphanumeric() {
            if start.is_none() {
                start = Some(idx);
            }
            buf.push(ch.to_ascii_lowercase());
        } else if let Some(s) = start.take() {
            out.push((s, idx, buf.clone()));
            buf.clear();
        }
    }
    if let Some(s) = start {
        out.push((s, text.len(), buf));
    }
    out
}

fn floor_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn ceil_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

fn extract_claim_type_hint(claim_type: &str) -> Option<String> {
    let cleaned = claim_type.replace(['.', '_', '-', ':'], " ");
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn flatten_value(val: &Value, out: &mut String) {
    match val {
        Value::String(s) => {
            out.push_str(s);
            out.push(' ');
        }
        Value::Number(n) => {
            out.push_str(&n.to_string());
            out.push(' ');
        }
        Value::Bool(b) => {
            out.push_str(if *b { "true " } else { "false " });
        }
        Value::Array(items) => {
            for item in items {
                flatten_value(item, out);
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                out.push_str(k);
                out.push(' ');
                flatten_value(v, out);
            }
        }
        Value::Null => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(id: &str, subject: Option<&str>, text: &str) -> ContradictionSegment {
        ContradictionSegment {
            id: id.into(),
            subject: subject.map(str::to_owned),
            attribute_hint: None,
            source_id: Some("src:1".into()),
            field: "chunk.text".into(),
            text: text.into(),
        }
    }

    #[test]
    fn fp005_detects_unit_normalized_mismatch_but_accepts_unit_equivalent_values() {
        // 2 GiB == 2048 MiB -> identical canonical byte count, zero contradictions
        let consistent = vec![
            seg("chunk:1", Some("vault"), "Maximum vault quota is 2 GiB"),
            seg("chunk:2", Some("vault"), "Maximum vault quota is 2048 MiB"),
        ];
        assert!(scan_segments(&consistent).is_empty());

        // 2 GiB != 4096 MiB -> FP005
        let conflicting = vec![
            seg("chunk:1", Some("vault"), "Maximum vault quota is 2 GiB"),
            seg("chunk:2", Some("vault"), "Maximum vault quota is 4096 MiB"),
        ];
        let res = scan_segments(&conflicting);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].rule_id, "FP005");
        assert_eq!(res[0].kind, HazardKind::NumericalContradiction);

        // Min vs Max qualifiers do NOT false-positive
        let min_max = vec![
            seg("chunk:min", Some("sync"), "Minimum retry delay is 200 ms"),
            seg("chunk:max", Some("sync"), "Maximum retry delay is 5000 ms"),
        ];
        assert!(scan_segments(&min_max).is_empty());
    }

    #[test]
    fn fp006_detects_cross_format_date_mismatch_and_inverted_lifecycle_windows() {
        // ISO 2027-12-31 == December 31, 2027 -> zero contradictions
        let same_date = vec![
            seg("chunk:a", Some("sla"), "Warranty SLA expires on 2027-12-31"),
            seg(
                "chunk:b",
                Some("sla"),
                "Warranty SLA expires on December 31, 2027",
            ),
        ];
        assert!(scan_segments(&same_date).is_empty());

        // Conflicting expiry dates across formats -> FP006
        let diff_expiry = vec![
            seg("chunk:a", Some("sla"), "Warranty SLA expires on 2027-12-31"),
            seg(
                "chunk:b",
                Some("sla"),
                "Warranty SLA expires on June 30, 2026",
            ),
        ];
        let findings = scan_segments(&diff_expiry);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FP006");

        // Inverted start vs expiration window -> FP006
        let inverted = vec![
            seg(
                "chunk:start",
                Some("contract"),
                "Enterprise agreement effective 2027-06-01",
            ),
            seg(
                "chunk:end",
                Some("contract"),
                "Enterprise agreement expires 2026-12-31",
            ),
        ];
        let inv_findings = scan_segments(&inverted);
        assert_eq!(inv_findings.len(), 1);
        assert_eq!(inv_findings[0].rule_id, "FP006");
        assert!(inv_findings[0].detail.contains("inverted lifecycle window"));
    }

    #[test]
    fn fp007_detects_negation_and_antonym_polarity_contradictions() {
        // "optional" (-1) and "not required" (-1) agree in polarity -> zero contradictions
        let consistent = vec![
            seg(
                "chunk:1",
                Some("auth"),
                "Hardware MFA token is optional for local vault unlock",
            ),
            seg(
                "chunk:2",
                Some("auth"),
                "Hardware MFA token is not required for local vault unlock",
            ),
        ];
        assert!(scan_segments(&consistent).is_empty());

        // "required" (+1) vs "not required" (-1) -> FP007
        let opposing = vec![
            seg(
                "chunk:1",
                Some("auth"),
                "Hardware MFA token is required for local vault unlock",
            ),
            seg(
                "chunk:2",
                Some("auth"),
                "Hardware MFA token is not required for local vault unlock",
            ),
        ];
        let findings = scan_segments(&opposing);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FP007");
        assert_eq!(findings[0].kind, HazardKind::PolarityContradiction);
    }
}
