//! Structured citation graph export (DOT and Mermaid) tracing evidence chains
//! across reviewed context packs.

use crate::{hex_digest, ExportError, ReviewedBundle};
use foliora_domain::{Sensitivity, SourceLocator};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CitationNodeKind {
    Bundle,
    Source,
    Claim,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CitationGraphNode {
    pub id: String,
    pub kind: CitationNodeKind,
    pub label: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CitationGraphEdge {
    pub from: String,
    pub to: String,
    pub relationship: String,
    pub locator_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CitationGraphExport {
    pub bundle_id: String,
    pub dot: String,
    pub mermaid: String,
    pub node_count: usize,
    pub edge_count: usize,
    pub evidence_chain_count: usize,
    pub audit_sha256: String,
}

fn sanitize_dot_label(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            '\t' => out.push(' '),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn sanitize_mermaid_label(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("#quot;"),
            '[' => out.push('('),
            ']' => out.push(')'),
            '{' => out.push('('),
            '}' => out.push(')'),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\n' => out.push_str("<br/>"),
            '\r' => {}
            '\\' => out.push('/'),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn format_locator(locator: &SourceLocator) -> String {
    match locator {
        SourceLocator::Page { page } => format!("p.{page}"),
        SourceLocator::Span { start, end } => format!("bytes {start}..{end}"),
        SourceLocator::PageSpan { page, start, end } => format!("p.{page} bytes {start}..{end}"),
        SourceLocator::Region { page, x, y, width, height } => {
            format!("p.{page} ({x},{y} {width}x{height})")
        }
    }
}

fn format_value_preview(val: &Value, max_len: usize) -> String {
    let raw = match val {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    if raw.chars().count() <= max_len {
        raw
    } else {
        let truncated: String = raw.chars().take(max_len.saturating_sub(3)).collect();
        format!("{truncated}...")
    }
}

fn format_sensitivity(s: Sensitivity) -> &'static str {
    match s {
        Sensitivity::Public => "public",
        Sensitivity::Internal => "internal",
        Sensitivity::Private => "private",
        Sensitivity::HighlySensitive => "highly_sensitive",
    }
}

/// Renders a deterministic Graphviz DOT citation graph tracing evidence chains.
pub fn render_dot(bundle: &ReviewedBundle) -> String {
    let mut dot = String::new();
    dot.push_str("digraph CitationGraph {\n");
    dot.push_str("  rankdir=LR;\n");
    dot.push_str("  node [shape=box, fontname=\"Helvetica,Arial,sans-serif\", fontsize=10];\n");
    dot.push_str("  edge [fontname=\"Helvetica,Arial,sans-serif\", fontsize=9];\n\n");

    // Bundle root
    let bundle_label = format!(
        "Bundle: {}\\n{}",
        sanitize_dot_label(&bundle.id),
        sanitize_dot_label(&bundle.purpose)
    );
    dot.push_str(&format!(
        "  \"bundle_{}\" [label=\"{}\", shape=doubleoctagon, style=\"filled,rounded\", fillcolor=\"#e3f2fd\", color=\"#1565c0\"];\n",
        sanitize_dot_label(&bundle.id),
        bundle_label
    ));

    // Sources (subgraph)
    if !bundle.evidence.is_empty() {
        dot.push_str("\n  subgraph cluster_sources {\n");
        dot.push_str("    label=\"Evidence Sources\";\n");
        dot.push_str("    style=\"rounded,dashed\";\n");
        dot.push_str("    color=\"#2e7d32\";\n");
        for source in &bundle.evidence {
            let short_fp = if source.fingerprint.len() > 16 {
                &source.fingerprint[..16]
            } else {
                &source.fingerprint
            };
            let title_line = source
                .title
                .as_deref()
                .map(|t| format!("\\n{}", sanitize_dot_label(t)))
                .unwrap_or_default();
            let label = format!(
                "Source: {}\\n[{}]{}\\n{}",
                sanitize_dot_label(&source.id),
                sanitize_dot_label(&source.media_type),
                title_line,
                sanitize_dot_label(short_fp)
            );
            dot.push_str(&format!(
                "    \"source_{}\" [label=\"{}\", shape=cylinder, style=filled, fillcolor=\"#e8f5e9\", color=\"#2e7d32\"];\n",
                sanitize_dot_label(&source.id),
                label
            ));
        }
        dot.push_str("  }\n\n");
    }

    // Claims (subgraph)
    if !bundle.claims.is_empty() {
        dot.push_str("  subgraph cluster_claims {\n");
        dot.push_str("    label=\"Reviewed Claims\";\n");
        dot.push_str("    style=\"rounded,dashed\";\n");
        dot.push_str("    color=\"#e65100\";\n");
        for claim in &bundle.claims {
            let preview = format_value_preview(&claim.value, 40);
            let label = format!(
                "Claim: {}\\n[{}] {}\\n{}",
                sanitize_dot_label(&claim.id),
                format_sensitivity(claim.sensitivity),
                sanitize_dot_label(&claim.claim_type),
                sanitize_dot_label(&preview)
            );
            dot.push_str(&format!(
                "    \"claim_{}\" [label=\"{}\", style=\"filled,rounded\", fillcolor=\"#fff8e1\", color=\"#f57f17\"];\n",
                sanitize_dot_label(&claim.id),
                label
            ));
        }
        dot.push_str("  }\n\n");
    }

    // Edges
    dot.push_str("  // Containment & Evidence Edges\n");
    for claim in &bundle.claims {
        dot.push_str(&format!(
            "  \"bundle_{}\" -> \"claim_{}\" [color=\"#90caf9\", style=solid];\n",
            sanitize_dot_label(&bundle.id),
            sanitize_dot_label(&claim.id)
        ));

        if let Some(src_id) = &claim.provenance.source_id {
            let loc_str = claim
                .provenance
                .locator
                .as_ref()
                .map(format_locator)
                .unwrap_or_else(|| "attributable".to_owned());
            dot.push_str(&format!(
                "  \"source_{}\" -> \"claim_{}\" [label=\"{}\", color=\"#388e3c\", fontcolor=\"#1b5e20\", weight=2];\n",
                sanitize_dot_label(src_id),
                sanitize_dot_label(&claim.id),
                sanitize_dot_label(&loc_str)
            ));
        } else if let Some(entered) = &claim.provenance.user_entered_at {
            dot.push_str(&format!(
                "  \"bundle_{}\" -> \"claim_{}\" [label=\"user-entered {}\", style=dotted, color=\"#78909c\"];\n",
                sanitize_dot_label(&bundle.id),
                sanitize_dot_label(&claim.id),
                sanitize_dot_label(entered)
            ));
        }
    }

    dot.push_str("}\n");
    dot
}

/// Renders a Mermaid flowchart tracing evidence chains across the context pack.
pub fn render_mermaid(bundle: &ReviewedBundle) -> String {
    let mut mm = String::new();
    mm.push_str("flowchart LR\n");

    let b_label = format!(
        "Bundle: {}<br/>{}",
        sanitize_mermaid_label(&bundle.id),
        sanitize_mermaid_label(&bundle.purpose)
    );
    mm.push_str(&format!("  b_root[\"{}\"]:::bundleNode\n", b_label));

    // Sources
    for (i, source) in bundle.evidence.iter().enumerate() {
        let short_fp = if source.fingerprint.len() > 12 {
            &source.fingerprint[..12]
        } else {
            &source.fingerprint
        };
        let title_line = source
            .title
            .as_deref()
            .map(|t| format!("<br/>{}", sanitize_mermaid_label(t)))
            .unwrap_or_default();
        let s_label = format!(
            "Source: {} ({}){}<br/><code>{}</code>",
            sanitize_mermaid_label(&source.id),
            sanitize_mermaid_label(&source.media_type),
            title_line,
            sanitize_mermaid_label(short_fp)
        );
        mm.push_str(&format!("  s_{}[(\"{}\")]:::sourceNode\n", i, s_label));
    }

    // Source id to index lookup
    let src_indices: BTreeMap<&str, usize> = bundle
        .evidence
        .iter()
        .enumerate()
        .map(|(i, s)| (s.id.as_str(), i))
        .collect();

    // Claims
    for (j, claim) in bundle.claims.iter().enumerate() {
        let preview = format_value_preview(&claim.value, 36);
        let c_label = format!(
            "Claim: {} ({})<br/><b>{}</b><br/>{}",
            sanitize_mermaid_label(&claim.id),
            format_sensitivity(claim.sensitivity),
            sanitize_mermaid_label(&claim.claim_type),
            sanitize_mermaid_label(&preview)
        );
        mm.push_str(&format!("  c_{}[\"{}\"]:::claimNode\n", j, c_label));

        // Edge from bundle
        mm.push_str(&format!("  b_root -.-> c_{}\n", j));

        // Edge from source
        if let Some(src_id) = &claim.provenance.source_id {
            if let Some(&src_idx) = src_indices.get(src_id.as_str()) {
                let loc_str = claim
                    .provenance
                    .locator
                    .as_ref()
                    .map(format_locator)
                    .unwrap_or_else(|| "evidence".to_owned());
                mm.push_str(&format!(
                    "  s_{} ==>|\"{}\"| c_{}\n",
                    src_idx,
                    sanitize_mermaid_label(&loc_str),
                    j
                ));
            }
        }
    }

    // Styles
    mm.push_str("  classDef bundleNode fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#0d47a1;\n");
    mm.push_str("  classDef sourceNode fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#1b5e20;\n");
    mm.push_str("  classDef claimNode fill:#fff8e1,stroke:#f57f17,stroke-width:2px,color:#e65100;\n");

    mm
}

/// Exports a complete structured citation graph with DOT and Mermaid formats
/// along with an audit SHA-256 fingerprint binding both representations.
pub fn export_citation_graph(bundle: &ReviewedBundle) -> Result<CitationGraphExport, ExportError> {
    let dot = render_dot(bundle);
    let mermaid = render_mermaid(bundle);

    let mut hasher = Sha256::new();
    hasher.update(dot.as_bytes());
    hasher.update(b"\n---\n");
    hasher.update(mermaid.as_bytes());
    let digest = format!("sha256:{}", hex_digest(&hasher.finalize()));

    let mut evidence_chain_count = 0usize;
    for claim in &bundle.claims {
        if claim.provenance.source_id.is_some() {
            evidence_chain_count += 1;
        }
    }

    let node_count = 1 + bundle.evidence.len() + bundle.claims.len();
    let edge_count = bundle.claims.len() + evidence_chain_count;

    Ok(CitationGraphExport {
        bundle_id: bundle.id.clone(),
        dot,
        mermaid,
        node_count,
        edge_count,
        evidence_chain_count,
        audit_sha256: digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EvidenceSource, ExportedClaim, ExportedProvenance};
    use foliora_domain::SourceLocator;

    fn sample_bundle() -> ReviewedBundle {
        ReviewedBundle {
            schema_version: 1,
            domain_schema_version: 1,
            id: "bundle:audit-1".into(),
            purpose: "Q3 SOC2 Security Assessment".into(),
            exported_at: "2026-11-18T00:00:00Z".into(),
            expires_at: Some("2026-12-31T23:59:59Z".into()),
            claims: vec![
                ExportedClaim {
                    id: "claim:mfa".into(),
                    claim_type: "auth.mfa_enforced".into(),
                    subject: "auth:policy".into(),
                    value: Value::Bool(true),
                    sensitivity: Sensitivity::Internal,
                    provenance: ExportedProvenance {
                        source_id: Some("source:iam_spec".into()),
                        locator: Some(SourceLocator::PageSpan {
                            page: 3,
                            start: 120,
                            end: 450,
                        }),
                        user_entered_at: None,
                    },
                },
                ExportedClaim {
                    id: "claim:custody".into(),
                    claim_type: "compliance.custody".into(),
                    subject: "custody:root".into(),
                    value: Value::String("Zero unencrypted keys at rest".into()),
                    sensitivity: Sensitivity::Private,
                    provenance: ExportedProvenance {
                        source_id: Some("source:iam_spec".into()),
                        locator: Some(SourceLocator::Span {
                            start: 500,
                            end: 800,
                        }),
                        user_entered_at: None,
                    },
                },
                ExportedClaim {
                    id: "claim:attestation".into(),
                    claim_type: "auditor.statement".into(),
                    subject: "auditor:lead".into(),
                    value: Value::String("Manual audit confirmed clean".into()),
                    sensitivity: Sensitivity::Public,
                    provenance: ExportedProvenance {
                        source_id: None,
                        locator: None,
                        user_entered_at: Some("2026-11-17T20:00:00Z".into()),
                    },
                },
            ],
            evidence: vec![EvidenceSource {
                id: "source:iam_spec".into(),
                fingerprint: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                media_type: "application/pdf".into(),
                title: Some("IAM Security Specification v2.pdf".into()),
                captured_at: "2026-11-15T10:00:00Z".into(),
            }],
        }
    }

    #[test]
    fn graph_export_produces_valid_dot_and_mermaid_with_correct_counts() {
        let bundle = sample_bundle();
        let export = export_citation_graph(&bundle).unwrap();

        assert_eq!(export.bundle_id, "bundle:audit-1");
        // 1 bundle + 1 source + 3 claims = 5 nodes
        assert_eq!(export.node_count, 5);
        // 3 bundle->claim containment edges + 2 evidence source->claim edges = 5 edges
        assert_eq!(export.edge_count, 5);
        assert_eq!(export.evidence_chain_count, 2);
        assert!(export.audit_sha256.starts_with("sha256:"));

        // Verify DOT contents
        assert!(export.dot.contains("digraph CitationGraph {"));
        assert!(export.dot.contains("bundle_bundle:audit-1"));
        assert!(export.dot.contains("Q3 SOC2 Security Assessment"));
        assert!(export.dot.contains("source_source:iam_spec"));
        assert!(export.dot.contains("claim_claim:mfa"));
        assert!(export.dot.contains("p.3 bytes 120..450"));
        assert!(export.dot.contains("bytes 500..800"));
        assert!(export.dot.contains("user-entered 2026-11-17T20:00:00Z"));

        // Verify Mermaid contents
        assert!(export.mermaid.contains("flowchart LR"));
        assert!(export.mermaid.contains("b_root"));
        assert!(export.mermaid.contains("s_0"));
        assert!(export.mermaid.contains("c_0"));
        assert!(export.mermaid.contains("p.3 bytes 120..450"));
        assert!(export.mermaid.contains("classDef bundleNode"));
    }

    #[test]
    fn special_characters_and_quotes_are_safely_escaped() {
        let mut bundle = sample_bundle();
        bundle.purpose = "Quotes: \"hello\" & <script>alert(1)</script> \n newline".into();
        bundle.claims[0].value = Value::String("Special [brackets] and {braces} and \"quotes\"".into());

        let export = export_citation_graph(&bundle).unwrap();
        // DOT should have escaped quotes
        assert!(export.dot.contains("\\\"hello\\\""));
        assert!(!export.dot.contains("<script>"));

        // Mermaid should have escaped quotes and brackets
        assert!(export.mermaid.contains("#quot;hello#quot;"));
        assert!(!export.mermaid.contains("<script>"));
    }
}
