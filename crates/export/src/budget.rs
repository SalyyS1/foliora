//! Token-budget context-pack allocator with shared-evidence cost amortization
//! and transitive evidence pruning.

use crate::{
    export_reviewed_markdown, ExportError, MarkdownExport, MarkdownLocale, ReviewedBundle,
};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenBudgetPolicy {
    pub max_tokens: usize,
    pub pinned_claim_ids: BTreeSet<String>,
    pub excluded_claim_ids: BTreeSet<String>,
    pub locale: MarkdownLocale,
}

impl TokenBudgetPolicy {
    pub fn new(max_tokens: usize, locale: MarkdownLocale) -> Self {
        Self {
            max_tokens,
            pinned_claim_ids: BTreeSet::new(),
            excluded_claim_ids: BTreeSet::new(),
            locale,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetedMarkdownExport {
    pub export: MarkdownExport,
    pub used_tokens: usize,
    pub max_tokens: usize,
    pub included_claim_ids: Vec<String>,
    pub dropped_claim_ids: Vec<String>,
    pub pruned_evidence_ids: Vec<String>,
}

/// Deterministic offline BPE-calibrated token estimator for rendered context packs.
pub fn estimate_pack_tokens(text: &str) -> usize {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return 0;
    }

    let mut tokens = 0usize;
    let mut ascii_word_len = 0usize;
    let mut punct_run_len = 0usize;
    let mut non_ascii_bytes = 0usize;

    let flush = |tokens: &mut usize,
                 ascii_word_len: &mut usize,
                 punct_run_len: &mut usize,
                 non_ascii_bytes: &mut usize| {
        if *ascii_word_len > 0 {
            *tokens += (*ascii_word_len).div_ceil(4);
            *ascii_word_len = 0;
        }
        if *punct_run_len > 0 {
            *tokens += (*punct_run_len).div_ceil(2);
            *punct_run_len = 0;
        }
        if *non_ascii_bytes > 0 {
            *tokens += (*non_ascii_bytes).div_ceil(2);
            *non_ascii_bytes = 0;
        }
    };

    for ch in trimmed.chars() {
        if ch.is_whitespace() {
            flush(
                &mut tokens,
                &mut ascii_word_len,
                &mut punct_run_len,
                &mut non_ascii_bytes,
            );
        } else if ch.is_ascii_alphanumeric() {
            if punct_run_len > 0 || non_ascii_bytes > 0 {
                flush(
                    &mut tokens,
                    &mut ascii_word_len,
                    &mut punct_run_len,
                    &mut non_ascii_bytes,
                );
            }
            ascii_word_len += 1;
        } else if ch.is_ascii() {
            if ascii_word_len > 0 || non_ascii_bytes > 0 {
                flush(
                    &mut tokens,
                    &mut ascii_word_len,
                    &mut punct_run_len,
                    &mut non_ascii_bytes,
                );
            }
            punct_run_len += 1;
        } else {
            if ascii_word_len > 0 || punct_run_len > 0 {
                flush(
                    &mut tokens,
                    &mut ascii_word_len,
                    &mut punct_run_len,
                    &mut non_ascii_bytes,
                );
            }
            non_ascii_bytes += ch.len_utf8();
        }
    }
    flush(
        &mut tokens,
        &mut ascii_word_len,
        &mut punct_run_len,
        &mut non_ascii_bytes,
    );
    tokens.max(1)
}

/// Allocates a citation-grounded Markdown context pack guaranteed to fit within
/// `policy.max_tokens` (including safety framing and the `Evidence Index` table).
///
/// Admits `pinned_claim_ids` first (failing closed if pinned claims exceed the
/// budget), then greedily selects remaining claims by minimal marginal rendered
/// token cost so claims sharing already-included `EvidenceSource` records
/// amortize citation-index overhead.
pub fn export_budgeted_markdown(
    reviewed: &ReviewedBundle,
    policy: &TokenBudgetPolicy,
) -> Result<BudgetedMarkdownExport, ExportError> {
    if policy.max_tokens == 0 {
        return Err(ExportError::InvalidTokenBudget(
            "max_tokens must be greater than zero".into(),
        ));
    }

    let all_ids: Vec<String> = reviewed.claims.iter().map(|c| c.id.clone()).collect();
    let available: BTreeSet<String> = all_ids.iter().cloned().collect();

    if let Some(unknown) = policy
        .excluded_claim_ids
        .iter()
        .find(|id| !available.contains(*id))
    {
        return Err(ExportError::UnknownRedaction(unknown.clone()));
    }
    if let Some(unknown) = policy
        .pinned_claim_ids
        .iter()
        .find(|id| !available.contains(*id))
    {
        return Err(ExportError::UnknownRedaction(unknown.clone()));
    }
    if policy
        .pinned_claim_ids
        .intersection(&policy.excluded_claim_ids)
        .next()
        .is_some()
    {
        return Err(ExportError::InvalidTokenBudget(
            "a claim cannot be both pinned and excluded".into(),
        ));
    }

    let eligible_indices: Vec<usize> = all_ids
        .iter()
        .enumerate()
        .filter(|(_, id)| !policy.excluded_claim_ids.contains(*id))
        .map(|(idx, _)| idx)
        .collect();
    if eligible_indices.is_empty() {
        return Err(ExportError::AllClaimsRedacted);
    }

    let render_subset =
        |selected_indices: &BTreeSet<usize>| -> Result<(MarkdownExport, usize), ExportError> {
            let excluded: BTreeSet<String> = all_ids
                .iter()
                .enumerate()
                .filter(|(idx, _)| !selected_indices.contains(idx))
                .map(|(_, id)| id.clone())
                .collect();
            let exported = export_reviewed_markdown(reviewed, &excluded, policy.locale)?;
            let tok = estimate_pack_tokens(&exported.markdown);
            Ok((exported, tok))
        };

    let mut selected = BTreeSet::new();
    for &idx in &eligible_indices {
        if policy.pinned_claim_ids.contains(&all_ids[idx]) {
            selected.insert(idx);
        }
    }

    if !selected.is_empty() {
        let (_, pinned_tokens) = render_subset(&selected)?;
        if pinned_tokens > policy.max_tokens {
            return Err(ExportError::TokenBudgetExceeded {
                required_min_tokens: pinned_tokens,
                max_tokens: policy.max_tokens,
            });
        }
    }

    // Greedily admit remaining eligible claims by lowest marginal rendered token delta,
    // breaking ties by original bundle order.
    let mut min_single_tokens: Option<usize> = None;
    loop {
        let mut best_candidate: Option<(usize, usize)> = None;
        let current_tokens = if selected.is_empty() {
            0
        } else {
            render_subset(&selected)?.1
        };

        for &idx in &eligible_indices {
            if selected.contains(&idx) {
                continue;
            }
            let mut trial = selected.clone();
            trial.insert(idx);
            let (_, candidate_tokens) = render_subset(&trial)?;
            if selected.is_empty() {
                min_single_tokens =
                    Some(min_single_tokens.map_or(candidate_tokens, |m| m.min(candidate_tokens)));
            }
            if candidate_tokens <= policy.max_tokens {
                let delta = candidate_tokens.saturating_sub(current_tokens);
                match best_candidate {
                    None => best_candidate = Some((idx, delta)),
                    Some((_, best_delta)) if delta < best_delta => {
                        best_candidate = Some((idx, delta));
                    }
                    _ => {}
                }
            }
        }

        if let Some((chosen_idx, _)) = best_candidate {
            selected.insert(chosen_idx);
        } else {
            break;
        }
    }

    if selected.is_empty() {
        return Err(ExportError::TokenBudgetExceeded {
            required_min_tokens: min_single_tokens.unwrap_or(policy.max_tokens + 1),
            max_tokens: policy.max_tokens,
        });
    }

    let (export, used_tokens) = render_subset(&selected)?;
    let included_claim_ids: Vec<String> =
        export.preview.claims.iter().map(|c| c.id.clone()).collect();
    let included_set: BTreeSet<&str> = included_claim_ids.iter().map(String::as_str).collect();
    let dropped_claim_ids: Vec<String> = all_ids
        .iter()
        .filter(|id| {
            !policy.excluded_claim_ids.contains(*id) && !included_set.contains(id.as_str())
        })
        .cloned()
        .collect();

    let kept_sources: BTreeSet<&str> = export
        .preview
        .evidence
        .iter()
        .map(|s| s.id.as_str())
        .collect();
    let pruned_evidence_ids: Vec<String> = reviewed
        .evidence
        .iter()
        .filter(|s| !kept_sources.contains(s.id.as_str()))
        .map(|s| s.id.clone())
        .collect();

    Ok(BudgetedMarkdownExport {
        export,
        used_tokens,
        max_tokens: policy.max_tokens,
        included_claim_ids,
        dropped_claim_ids,
        pruned_evidence_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EvidenceSource, ExportedClaim, ExportedProvenance, EXPORT_SCHEMA_VERSION};
    use foliora_domain::{Sensitivity, SourceLocator};
    use serde_json::Value;

    fn multi_source_bundle() -> ReviewedBundle {
        ReviewedBundle {
            schema_version: EXPORT_SCHEMA_VERSION,
            domain_schema_version: 1,
            id: "bundle:budget-1".into(),
            purpose: "Token budget allocation test".into(),
            exported_at: "2026-11-15T00:00:00Z".into(),
            expires_at: None,
            claims: vec![
                ExportedClaim {
                    id: "c1".into(),
                    claim_type: "project.goal".into(),
                    subject: "core".into(),
                    value: Value::String("Offline verification".into()),
                    sensitivity: Sensitivity::Public,
                    provenance: ExportedProvenance {
                        source_id: Some("src:shared".into()),
                        locator: Some(SourceLocator::Span { start: 0, end: 20 }),
                        user_entered_at: None,
                    },
                },
                ExportedClaim {
                    id: "c2".into(),
                    claim_type: "project.appendix".into(),
                    subject: "core".into(),
                    value: Value::String(
                        "Long narrative clause requiring a separate heavy source citation row and many extra subword tokens in the output context window".into(),
                    ),
                    sensitivity: Sensitivity::Internal,
                    provenance: ExportedProvenance {
                        source_id: Some("src:heavy".into()),
                        locator: Some(SourceLocator::PageSpan {
                            page: 4,
                            start: 10,
                            end: 140,
                        }),
                        user_entered_at: None,
                    },
                },
                ExportedClaim {
                    id: "c3".into(),
                    claim_type: "project.owner".into(),
                    subject: "core".into(),
                    value: Value::String("ops@foliora.local".into()),
                    sensitivity: Sensitivity::Internal,
                    provenance: ExportedProvenance {
                        source_id: Some("src:shared".into()),
                        locator: Some(SourceLocator::Span { start: 25, end: 42 }),
                        user_entered_at: None,
                    },
                },
            ],
            evidence: vec![
                EvidenceSource {
                    id: "src:shared".into(),
                    fingerprint: format!("sha256:{}", "a".repeat(64)),
                    media_type: "text/plain".into(),
                    title: Some("brief.txt".into()),
                    captured_at: "2026-11-15T00:00:00Z".into(),
                },
                EvidenceSource {
                    id: "src:heavy".into(),
                    fingerprint: format!("sha256:{}", "b".repeat(64)),
                    media_type: "application/pdf".into(),
                    title: Some("Comprehensive-Enterprise-Appendix-2026.pdf".into()),
                    captured_at: "2026-11-15T00:00:00Z".into(),
                },
            ],
        }
    }

    #[test]
    fn allocator_enforces_token_ceiling_amortizes_shared_evidence_and_prunes_dropped_sources() {
        let bundle = multi_source_bundle();
        let full =
            export_reviewed_markdown(&bundle, &BTreeSet::new(), MarkdownLocale::English).unwrap();
        let full_tokens = estimate_pack_tokens(&full.markdown);

        let mut policy = TokenBudgetPolicy::new(full_tokens - 25, MarkdownLocale::English);
        policy.pinned_claim_ids.insert("c1".into());

        let budgeted = export_budgeted_markdown(&bundle, &policy).unwrap();
        assert!(budgeted.used_tokens <= policy.max_tokens);
        assert_eq!(budgeted.included_claim_ids, vec!["c1", "c3"]);
        assert_eq!(budgeted.dropped_claim_ids, vec!["c2"]);
        assert_eq!(budgeted.pruned_evidence_ids, vec!["src:heavy"]);
        assert!(!budgeted.export.markdown.contains("src:heavy"));
    }

    #[test]
    fn allocator_fails_closed_when_budget_is_too_small_or_policy_is_invalid() {
        let bundle = multi_source_bundle();
        assert!(matches!(
            export_budgeted_markdown(&bundle, &TokenBudgetPolicy::new(0, MarkdownLocale::English)),
            Err(ExportError::InvalidTokenBudget(_))
        ));
        assert!(matches!(
            export_budgeted_markdown(
                &bundle,
                &TokenBudgetPolicy::new(15, MarkdownLocale::English)
            ),
            Err(ExportError::TokenBudgetExceeded { .. })
        ));
    }
}
