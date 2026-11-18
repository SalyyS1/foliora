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
    pub svg: String,
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
        SourceLocator::Region {
            page,
            x,
            y,
            width,
            height,
        } => {
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
    mm.push_str(
        "  classDef bundleNode fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#0d47a1;\n",
    );
    mm.push_str(
        "  classDef sourceNode fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#1b5e20;\n",
    );
    mm.push_str(
        "  classDef claimNode fill:#fff8e1,stroke:#f57f17,stroke-width:2px,color:#e65100;\n",
    );

    mm
}

fn sanitize_xml(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\n' | '\r' | '\t' => out.push(' '),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn safe_json_for_html_script(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for ch in json.chars() {
        match ch {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out
}

fn truncate_chars(text: &str, max_len: usize) -> String {
    if text.chars().count() <= max_len {
        text.to_owned()
    } else {
        let head: String = text.chars().take(max_len.saturating_sub(3)).collect();
        format!("{head}...")
    }
}

/// Renders a standalone deterministic SVG citation graph tracing sources, claims, and bundle root.
pub fn render_svg(bundle: &ReviewedBundle) -> String {
    let col_source_x = 36u32;
    let col_source_w = 276u32;
    let col_claim_x = 408u32;
    let col_claim_w = 304u32;
    let col_bundle_x = 808u32;
    let col_bundle_w = 268u32;

    let card_h = 74u32;
    let row_step = 94u32;
    let top_y = 78u32;

    let max_rows = bundle.evidence.len().max(bundle.claims.len()).max(1) as u32;
    let svg_width = 1112u32;
    let svg_height = (top_y + max_rows * row_step + 44).max(320);

    let bundle_y = top_y + ((max_rows.saturating_sub(1)) * row_step) / 2;

    let mut source_positions: BTreeMap<&str, (u32, u32)> = BTreeMap::new();
    for (idx, src) in bundle.evidence.iter().enumerate() {
        let y = top_y + (idx as u32) * row_step;
        source_positions.insert(src.id.as_str(), (col_source_x, y));
    }

    let mut claim_positions: Vec<(u32, u32)> = Vec::with_capacity(bundle.claims.len());
    for idx in 0..bundle.claims.len() {
        claim_positions.push((col_claim_x, top_y + (idx as u32) * row_step));
    }

    let mut svg = String::with_capacity(4096);
    svg.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {svg_width} {svg_height}\" width=\"{svg_width}\" height=\"{svg_height}\" role=\"img\" aria-label=\"Citation graph for {}\">\n",
        sanitize_xml(&bundle.id)
    ));
    svg.push_str("  <defs>\n");
    svg.push_str("    <marker id=\"arrow-evidence\" viewBox=\"0 0 10 10\" refX=\"9\" refY=\"5\" markerWidth=\"7\" markerHeight=\"7\" orient=\"auto-start-reverse\">\n");
    svg.push_str("      <path d=\"M 0 1 L 10 5 L 0 9 z\" fill=\"#2e7d32\"/>\n");
    svg.push_str("    </marker>\n");
    svg.push_str("    <marker id=\"arrow-bundle\" viewBox=\"0 0 10 10\" refX=\"9\" refY=\"5\" markerWidth=\"7\" markerHeight=\"7\" orient=\"auto-start-reverse\">\n");
    svg.push_str("      <path d=\"M 0 1 L 10 5 L 0 9 z\" fill=\"#1565c0\"/>\n");
    svg.push_str("    </marker>\n");
    svg.push_str("  </defs>\n");

    // Background & column lane labels
    svg.push_str(&format!(
        "  <rect x=\"0\" y=\"0\" width=\"{svg_width}\" height=\"{svg_height}\" fill=\"#f8fafc\" rx=\"12\"/>\n"
    ));
    svg.push_str(&format!(
        "  <text x=\"{col_source_x}\" y=\"42\" font-family=\"system-ui,-apple-system,Segoe UI,sans-serif\" font-size=\"12\" font-weight=\"700\" fill=\"#1b5e20\">EVIDENCE SOURCES ({})</text>\n",
        bundle.evidence.len()
    ));
    svg.push_str(&format!(
        "  <text x=\"{col_claim_x}\" y=\"42\" font-family=\"system-ui,-apple-system,Segoe UI,sans-serif\" font-size=\"12\" font-weight=\"700\" fill=\"#e65100\">REVIEWED CLAIMS ({})</text>\n",
        bundle.claims.len()
    ));
    svg.push_str(&format!(
        "  <text x=\"{col_bundle_x}\" y=\"42\" font-family=\"system-ui,-apple-system,Segoe UI,sans-serif\" font-size=\"12\" font-weight=\"700\" fill=\"#0d47a1\">CONTEXT PACK BUNDLE</text>\n"
    ));

    // Edges first so nodes render cleanly on top
    svg.push_str("  <g class=\"cg-edges\">\n");
    let bundle_node_id = format!("bundle:{}", bundle.id);
    for (idx, claim) in bundle.claims.iter().enumerate() {
        let (cx, cy) = claim_positions[idx];
        let claim_mid_y = cy + card_h / 2;
        let claim_node_id = format!("claim:{}", claim.id);

        if let Some(src_id) = &claim.provenance.source_id {
            if let Some(&(sx, sy)) = source_positions.get(src_id.as_str()) {
                let x1 = sx + col_source_w;
                let y1 = sy + card_h / 2;
                let x2 = cx;
                let y2 = claim_mid_y;
                let ctrl = (x2 - x1) / 2;
                let from_id = format!("source:{src_id}");
                let loc = claim
                    .provenance
                    .locator
                    .as_ref()
                    .map(format_locator)
                    .unwrap_or_else(|| "evidence".to_owned());
                svg.push_str(&format!(
                    "    <path class=\"cg-edge cg-edge-evidence\" data-from=\"{}\" data-to=\"{}\" d=\"M {x1} {y1} C {} {y1}, {} {y2}, {x2} {y2}\" fill=\"none\" stroke=\"#2e7d32\" stroke-width=\"2\" marker-end=\"url(#arrow-evidence)\"/>\n",
                    sanitize_xml(&from_id),
                    sanitize_xml(&claim_node_id),
                    x1 + ctrl,
                    x2 - ctrl
                ));
                let lx = (x1 + x2) / 2;
                let ly = (y1 + y2) / 2;
                svg.push_str(&format!(
                    "    <text class=\"cg-edge-label\" data-from=\"{}\" data-to=\"{}\" x=\"{lx}\" y=\"{}\" text-anchor=\"middle\" font-family=\"ui-monospace,SFMono-Regular,Consolas,monospace\" font-size=\"10\" fill=\"#1b5e20\">{}</text>\n",
                    sanitize_xml(&from_id),
                    sanitize_xml(&claim_node_id),
                    ly.saturating_sub(5),
                    sanitize_xml(&truncate_chars(&loc, 26))
                ));
            }
        }

        // Claim -> Bundle edge
        let bx1 = cx + col_claim_w;
        let by1 = claim_mid_y;
        let bx2 = col_bundle_x;
        let by2 = bundle_y + card_h / 2;
        let bctrl = (bx2 - bx1) / 2;
        svg.push_str(&format!(
            "    <path class=\"cg-edge cg-edge-bundle\" data-from=\"{}\" data-to=\"{}\" d=\"M {bx1} {by1} C {} {by1}, {} {by2}, {bx2} {by2}\" fill=\"none\" stroke=\"#1565c0\" stroke-width=\"1.6\" stroke-dasharray=\"5,4\" marker-end=\"url(#arrow-bundle)\"/>\n",
            sanitize_xml(&claim_node_id),
            sanitize_xml(&bundle_node_id),
            bx1 + bctrl,
            bx2 - bctrl
        ));
    }
    svg.push_str("  </g>\n");

    // Source nodes
    svg.push_str("  <g class=\"cg-nodes\">\n");
    for src in &bundle.evidence {
        let Some(&(sx, sy)) = source_positions.get(src.id.as_str()) else {
            continue;
        };
        let node_id = format!("source:{}", src.id);
        let title = src.title.as_deref().unwrap_or(&src.media_type);
        let short_fp = truncate_chars(&src.fingerprint, 23);
        svg.push_str(&format!(
            "    <g class=\"cg-node\" tabindex=\"0\" data-node-id=\"{}\" data-node-kind=\"source\" data-search=\"{}\">\n",
            sanitize_xml(&node_id),
            sanitize_xml(&format!("{} {} {} {}", src.id, title, src.media_type, src.fingerprint).to_lowercase())
        ));
        svg.push_str(&format!(
            "      <rect x=\"{sx}\" y=\"{sy}\" width=\"{col_source_w}\" height=\"{card_h}\" rx=\"8\" fill=\"#e8f5e9\" stroke=\"#2e7d32\" stroke-width=\"1.8\"/>\n"
        ));
        svg.push_str(&format!(
            "      <text x=\"{}\" y=\"{}\" font-family=\"system-ui,-apple-system,Segoe UI,sans-serif\" font-size=\"12\" font-weight=\"700\" fill=\"#1b5e20\">{}</text>\n",
            sx + 12,
            sy + 22,
            sanitize_xml(&truncate_chars(&src.id, 32))
        ));
        svg.push_str(&format!(
            "      <text x=\"{}\" y=\"{}\" font-family=\"system-ui,-apple-system,Segoe UI,sans-serif\" font-size=\"11\" fill=\"#2e7d32\">{}</text>\n",
            sx + 12,
            sy + 41,
            sanitize_xml(&truncate_chars(title, 36))
        ));
        svg.push_str(&format!(
            "      <text x=\"{}\" y=\"{}\" font-family=\"ui-monospace,SFMono-Regular,Consolas,monospace\" font-size=\"10\" fill=\"#33691e\">{}</text>\n",
            sx + 12,
            sy + 59,
            sanitize_xml(&short_fp)
        ));
        svg.push_str("    </g>\n");
    }

    // Claim nodes
    for (idx, claim) in bundle.claims.iter().enumerate() {
        let (cx, cy) = claim_positions[idx];
        let node_id = format!("claim:{}", claim.id);
        let sens = format_sensitivity(claim.sensitivity);
        let preview = format_value_preview(&claim.value, 38);
        let (fill, stroke, badge_fill) = match claim.sensitivity {
            Sensitivity::Public => ("#fffde7", "#f9a825", "#f57f17"),
            Sensitivity::Internal => ("#fff8e1", "#ef6c00", "#e65100"),
            Sensitivity::Private => ("#fbe9e7", "#d84315", "#bf360c"),
            Sensitivity::HighlySensitive => ("#ffebee", "#c62828", "#b71c1c"),
        };
        svg.push_str(&format!(
            "    <g class=\"cg-node\" tabindex=\"0\" data-node-id=\"{}\" data-node-kind=\"claim\" data-sensitivity=\"{sens}\" data-search=\"{}\">\n",
            sanitize_xml(&node_id),
            sanitize_xml(&format!("{} {} {} {} {}", claim.id, claim.claim_type, claim.subject, preview, sens).to_lowercase())
        ));
        svg.push_str(&format!(
            "      <rect x=\"{cx}\" y=\"{cy}\" width=\"{col_claim_w}\" height=\"{card_h}\" rx=\"8\" fill=\"{fill}\" stroke=\"{stroke}\" stroke-width=\"1.8\"/>\n"
        ));
        svg.push_str(&format!(
            "      <text x=\"{}\" y=\"{}\" font-family=\"system-ui,-apple-system,Segoe UI,sans-serif\" font-size=\"12\" font-weight=\"700\" fill=\"{badge_fill}\">{} [{}]</text>\n",
            cx + 12,
            cy + 22,
            sanitize_xml(&truncate_chars(&claim.claim_type, 24)),
            sanitize_xml(sens)
        ));
        svg.push_str(&format!(
            "      <text x=\"{}\" y=\"{}\" font-family=\"system-ui,-apple-system,Segoe UI,sans-serif\" font-size=\"11\" fill=\"#37474f\">{}: {}</text>\n",
            cx + 12,
            cy + 41,
            sanitize_xml(&truncate_chars(&claim.subject, 14)),
            sanitize_xml(&truncate_chars(&preview, 26))
        ));
        svg.push_str(&format!(
            "      <text x=\"{}\" y=\"{}\" font-family=\"ui-monospace,SFMono-Regular,Consolas,monospace\" font-size=\"10\" fill=\"#546e7a\">{}</text>\n",
            cx + 12,
            cy + 59,
            sanitize_xml(&truncate_chars(&claim.id, 38))
        ));
        svg.push_str("    </g>\n");
    }

    // Bundle node
    svg.push_str(&format!(
        "    <g class=\"cg-node\" tabindex=\"0\" data-node-id=\"{}\" data-node-kind=\"bundle\" data-search=\"{}\">\n",
        sanitize_xml(&bundle_node_id),
        sanitize_xml(&format!("{} {}", bundle.id, bundle.purpose).to_lowercase())
    ));
    svg.push_str(&format!(
        "      <rect x=\"{col_bundle_x}\" y=\"{bundle_y}\" width=\"{col_bundle_w}\" height=\"{card_h}\" rx=\"10\" fill=\"#e3f2fd\" stroke=\"#1565c0\" stroke-width=\"2.2\"/>\n"
    ));
    svg.push_str(&format!(
        "      <text x=\"{}\" y=\"{}\" font-family=\"system-ui,-apple-system,Segoe UI,sans-serif\" font-size=\"12\" font-weight=\"700\" fill=\"#0d47a1\">{}</text>\n",
        col_bundle_x + 12,
        bundle_y + 23,
        sanitize_xml(&truncate_chars(&bundle.id, 30))
    ));
    svg.push_str(&format!(
        "      <text x=\"{}\" y=\"{}\" font-family=\"system-ui,-apple-system,Segoe UI,sans-serif\" font-size=\"11\" fill=\"#1565c0\">{}</text>\n",
        col_bundle_x + 12,
        bundle_y + 42,
        sanitize_xml(&truncate_chars(&bundle.purpose, 34))
    ));
    svg.push_str(&format!(
        "      <text x=\"{}\" y=\"{}\" font-family=\"ui-monospace,SFMono-Regular,Consolas,monospace\" font-size=\"10\" fill=\"#1e88e5\">{}</text>\n",
        col_bundle_x + 12,
        bundle_y + 60,
        sanitize_xml(&bundle.exported_at)
    ));
    svg.push_str("    </g>\n");
    svg.push_str("  </g>\n");
    svg.push_str("</svg>\n");
    svg
}

/// Renders a self-contained offline interactive HTML/SVG citation graph explorer.
pub fn render_html(bundle: &ReviewedBundle) -> Result<String, ExportError> {
    let graph = export_citation_graph(bundle)?;
    let mut node_details: BTreeMap<String, Value> = BTreeMap::new();

    node_details.insert(
        format!("bundle:{}", bundle.id),
        serde_json::json!({
            "kind": "bundle",
            "id": bundle.id,
            "purpose": bundle.purpose,
            "exported_at": bundle.exported_at,
            "expires_at": bundle.expires_at,
            "audit_sha256": graph.audit_sha256,
        }),
    );

    for src in &bundle.evidence {
        node_details.insert(
            format!("source:{}", src.id),
            serde_json::json!({
                "kind": "source",
                "id": src.id,
                "title": src.title,
                "media_type": src.media_type,
                "fingerprint": src.fingerprint,
                "captured_at": src.captured_at,
            }),
        );
    }

    for claim in &bundle.claims {
        let loc_str = claim.provenance.locator.as_ref().map(format_locator);
        node_details.insert(
            format!("claim:{}", claim.id),
            serde_json::json!({
                "kind": "claim",
                "id": claim.id,
                "claim_type": claim.claim_type,
                "subject": claim.subject,
                "sensitivity": format_sensitivity(claim.sensitivity),
                "value": claim.value,
                "source_id": claim.provenance.source_id,
                "locator": loc_str,
                "user_entered_at": claim.provenance.user_entered_at,
            }),
        );
    }

    let payload_json = serde_json::to_string(&serde_json::json!({
        "bundle_id": graph.bundle_id,
        "node_count": graph.node_count,
        "edge_count": graph.edge_count,
        "evidence_chain_count": graph.evidence_chain_count,
        "audit_sha256": graph.audit_sha256,
        "nodes": node_details,
    }))
    .map_err(|e| ExportError::Serialize(e.to_string()))?;

    let export_json_pretty =
        serde_json::to_string_pretty(&graph).map_err(|e| ExportError::Serialize(e.to_string()))?;

    let safe_script_payload = safe_json_for_html_script(&payload_json);
    let escaped_id = sanitize_xml(&bundle.id);
    let escaped_purpose = sanitize_xml(&bundle.purpose);
    let escaped_audit = sanitize_xml(&graph.audit_sha256);
    let escaped_dot = sanitize_xml(&graph.dot);
    let escaped_mermaid = sanitize_xml(&graph.mermaid);
    let escaped_json = sanitize_xml(&export_json_pretty);

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:;">
  <title>Foliora Citation Graph - {escaped_id}</title>
  <style>
    :root {{ color-scheme: light; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: #f1f5f9; color: #0f172a; }}
    header {{ background: #ffffff; border-bottom: 1px solid #cbd5e1; padding: 16px 24px; display: flex; flex-wrap: wrap; gap: 12px; justify-content: space-between; align-items: center; }}
    .title-group h1 {{ margin: 0; font-size: 18px; color: #0f172a; }}
    .title-group p {{ margin: 4px 0 0; font-size: 13px; color: #475569; }}
    .metrics {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }}
    .badge {{ background: #e2e8f0; color: #1e293b; border-radius: 6px; padding: 4px 10px; font-size: 12px; font-weight: 600; }}
    .badge.sha {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; background: #dbeafe; color: #1e40af; }}
    .toolbar {{ background: #ffffff; border-bottom: 1px solid #e2e8f0; padding: 10px 24px; display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }}
    .toolbar input[type="search"] {{ padding: 6px 10px; border: 1px solid #cbd5e1; border-radius: 6px; min-width: 240px; font-size: 13px; }}
    .toolbar select, .toolbar button {{ padding: 6px 12px; border: 1px solid #cbd5e1; border-radius: 6px; background: #f8fafc; color: #0f172a; font-size: 13px; cursor: pointer; }}
    .toolbar button.active {{ background: #0f172a; color: #ffffff; border-color: #0f172a; }}
    main {{ display: grid; grid-template-columns: 1fr 340px; gap: 16px; padding: 16px 24px; min-height: calc(100vh - 130px); }}
    @media (max-width: 960px) {{ main {{ grid-template-columns: 1fr; }} }}
    .panel {{ background: #ffffff; border: 1px solid #cbd5e1; border-radius: 10px; overflow: hidden; display: flex; flex-direction: column; }}
    .canvas-wrap {{ overflow: auto; padding: 12px; flex: 1; }}
    .code-view {{ display: none; margin: 0; padding: 16px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; overflow: auto; white-space: pre; flex: 1; background: #0f172a; color: #e2e8f0; }}
    .inspector {{ padding: 16px; font-size: 13px; overflow: auto; }}
    .inspector h2 {{ margin: 0 0 10px; font-size: 15px; }}
    .inspector pre {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px; overflow: auto; font-size: 12px; white-space: pre-wrap; word-break: break-word; }}
    .cg-node {{ cursor: pointer; transition: opacity 0.15s ease; }}
    .cg-edge, .cg-edge-label {{ transition: opacity 0.15s ease; }}
    .dimmed {{ opacity: 0.18; }}
    .selected rect {{ stroke-width: 3.2px; }}
  </style>
</head>
<body>
  <header>
    <div class="title-group">
      <h1>Foliora Citation Graph: {escaped_id}</h1>
      <p>{escaped_purpose}</p>
    </div>
    <div class="metrics">
      <span class="badge">Nodes: {node_count}</span>
      <span class="badge">Edges: {edge_count}</span>
      <span class="badge">Evidence Chains: {chain_count}</span>
      <span class="badge sha" title="{escaped_audit}">{short_audit}</span>
    </div>
  </header>
  <div class="toolbar" role="toolbar" aria-label="Citation graph controls">
    <input id="cg-search" type="search" placeholder="Filter claims, subjects, or SHA-256...">
    <select id="cg-sensitivity" aria-label="Filter by sensitivity">
      <option value="all">All sensitivities</option>
      <option value="public">Public</option>
      <option value="internal">Internal</option>
      <option value="private">Private</option>
      <option value="highly_sensitive">Highly sensitive</option>
    </select>
    <button type="button" id="cg-zoom-in">Zoom +</button>
    <button type="button" id="cg-zoom-out">Zoom -</button>
    <button type="button" id="cg-reset">Reset</button>
    <button type="button" class="tab-btn active" data-tab="svg">Interactive SVG</button>
    <button type="button" class="tab-btn" data-tab="dot">DOT</button>
    <button type="button" class="tab-btn" data-tab="mermaid">Mermaid</button>
    <button type="button" class="tab-btn" data-tab="json">JSON</button>
  </div>
  <main>
    <section class="panel" aria-label="Graph viewport">
      <div id="view-svg" class="canvas-wrap">
        {svg}
      </div>
      <pre id="view-dot" class="code-view">{escaped_dot}</pre>
      <pre id="view-mermaid" class="code-view">{escaped_mermaid}</pre>
      <pre id="view-json" class="code-view">{escaped_json}</pre>
    </section>
    <aside class="panel inspector" aria-label="Provenance inspector">
      <h2>Provenance Inspector</h2>
      <p id="inspector-hint">Select any source, claim, or bundle node in the graph to inspect its full provenance record and highlight connected lineage.</p>
      <pre id="inspector-content">Click a node to inspect details.</pre>
    </aside>
  </main>
  <script id="foliora-graph-data" type="application/json">{safe_script_payload}</script>
  <script>
    (function () {{
      const payload = JSON.parse(document.getElementById('foliora-graph-data').textContent);
      const svgEl = document.querySelector('#view-svg svg');
      const nodes = Array.from(document.querySelectorAll('.cg-node'));
      const edges = Array.from(document.querySelectorAll('.cg-edge, .cg-edge-label'));
      const inspector = document.getElementById('inspector-content');
      const searchInput = document.getElementById('cg-search');
      const sensSelect = document.getElementById('cg-sensitivity');
      let scale = 1.0;

      function applyZoom() {{
        if (svgEl) {{
          svgEl.style.transformOrigin = '0 0';
          svgEl.style.transform = 'scale(' + scale.toFixed(2) + ')';
        }}
      }}

      function clearSelection() {{
        nodes.forEach((n) => n.classList.remove('dimmed', 'selected'));
        edges.forEach((e) => e.classList.remove('dimmed'));
      }}

      function selectNode(nodeId) {{
        const connected = new Set([nodeId]);
        edges.forEach((edge) => {{
          const from = edge.getAttribute('data-from');
          const to = edge.getAttribute('data-to');
          if (from === nodeId || to === nodeId) {{
            connected.add(from);
            connected.add(to);
          }}
        }});
        nodes.forEach((n) => {{
          const id = n.getAttribute('data-node-id');
          n.classList.toggle('selected', id === nodeId);
          n.classList.toggle('dimmed', !connected.has(id));
        }});
        edges.forEach((e) => {{
          const active = e.getAttribute('data-from') === nodeId || e.getAttribute('data-to') === nodeId;
          e.classList.toggle('dimmed', !active);
        }});
        const detail = payload.nodes[nodeId] || {{ id: nodeId }};
        inspector.textContent = JSON.stringify(detail, null, 2);
      }}

      function applyFilter() {{
        const q = searchInput.value.trim().toLowerCase();
        const sens = sensSelect.value;
        const matched = new Set();
        nodes.forEach((n) => {{
          const id = n.getAttribute('data-node-id');
          const kind = n.getAttribute('data-node-kind');
          const nodeSens = n.getAttribute('data-sensitivity') || 'all';
          const text = n.getAttribute('data-search') || '';
          const sensOk = sens === 'all' || kind !== 'claim' || nodeSens === sens;
          const textOk = !q || text.includes(q);
          if (sensOk && textOk) {{
            matched.add(id);
          }}
        }});
        nodes.forEach((n) => {{
          const id = n.getAttribute('data-node-id');
          n.classList.toggle('dimmed', !matched.has(id));
        }});
        edges.forEach((e) => {{
          const visible = matched.has(e.getAttribute('data-from')) && matched.has(e.getAttribute('data-to'));
          e.classList.toggle('dimmed', !visible);
        }});
      }}

      nodes.forEach((n) => {{
        n.addEventListener('click', () => selectNode(n.getAttribute('data-node-id')));
        n.addEventListener('keydown', (ev) => {{
          if (ev.key === 'Enter' || ev.key === ' ') {{
            ev.preventDefault();
            selectNode(n.getAttribute('data-node-id'));
          }}
        }});
      }});
      searchInput.addEventListener('input', applyFilter);
      sensSelect.addEventListener('change', applyFilter);
      document.getElementById('cg-zoom-in').addEventListener('click', () => {{ scale = Math.min(2.4, scale + 0.15); applyZoom(); }});
      document.getElementById('cg-zoom-out').addEventListener('click', () => {{ scale = Math.max(0.45, scale - 0.15); applyZoom(); }});
      document.getElementById('cg-reset').addEventListener('click', () => {{
        scale = 1.0;
        searchInput.value = '';
        sensSelect.value = 'all';
        applyZoom();
        clearSelection();
      }});

      const tabs = Array.from(document.querySelectorAll('.tab-btn'));
      tabs.forEach((btn) => {{
        btn.addEventListener('click', () => {{
          const target = btn.getAttribute('data-tab');
          tabs.forEach((b) => b.classList.toggle('active', b === btn));
          ['svg', 'dot', 'mermaid', 'json'].forEach((name) => {{
            const el = document.getElementById('view-' + name);
            if (el) {{
              el.style.display = name === target ? 'block' : 'none';
            }}
          }});
        }});
      }});
    }})();
  </script>
</body>
</html>
"#,
        node_count = graph.node_count,
        edge_count = graph.edge_count,
        chain_count = graph.evidence_chain_count,
        short_audit = sanitize_xml(&truncate_chars(&graph.audit_sha256, 24)),
        svg = graph.svg,
    );

    Ok(html)
}

/// Exports a complete structured citation graph with DOT, Mermaid, and SVG formats
/// along with an audit SHA-256 fingerprint binding the graph representations.
pub fn export_citation_graph(bundle: &ReviewedBundle) -> Result<CitationGraphExport, ExportError> {
    let dot = render_dot(bundle);
    let mermaid = render_mermaid(bundle);
    let svg = render_svg(bundle);

    let mut hasher = Sha256::new();
    hasher.update(dot.as_bytes());
    hasher.update(b"\n---\n");
    hasher.update(mermaid.as_bytes());
    hasher.update(b"\n---\n");
    hasher.update(svg.as_bytes());
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
        svg,
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
                fingerprint:
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
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
        bundle.claims[0].value =
            Value::String("Special [brackets] and {braces} and \"quotes\"".into());

        let export = export_citation_graph(&bundle).unwrap();
        // DOT should have escaped quotes
        assert!(export.dot.contains("\\\"hello\\\""));
        assert!(!export.dot.contains("<script>"));

        // Mermaid should have escaped quotes and brackets
        assert!(export.mermaid.contains("#quot;hello#quot;"));
        assert!(!export.mermaid.contains("<script>"));
    }

    #[test]
    fn svg_and_html_bundle_generator_render_lineage_and_neutralize_script_breakouts() {
        let mut bundle = sample_bundle();
        bundle.purpose = "Audit </script><script>alert(1)</script> & lineage".into();
        bundle.claims[0].value =
            Value::String("Payload </script><img src=x onerror=alert(1)>".into());

        let svg = render_svg(&bundle);
        assert!(svg.starts_with("<svg xmlns=\"http://www.w3.org/2000/svg\""));
        assert!(svg.contains("data-node-id=\"source:source:iam_spec\""));
        assert!(svg.contains("data-node-id=\"claim:claim:mfa\""));
        assert!(svg.contains("data-node-id=\"bundle:bundle:audit-1\""));
        assert!(svg.contains("p.3 bytes 120..450"));
        assert!(!svg.contains("<script>alert(1)</script>"));

        let html = render_html(&bundle).unwrap();
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("Content-Security-Policy"));
        assert!(html.contains("id=\"foliora-graph-data\""));
        assert!(!html.contains("</script><script>alert(1)</script>"));
        assert!(!html.contains("<img src=x onerror=alert(1)>"));
        assert!(html.contains("\\u003c/script\\u003e"));
    }
}
