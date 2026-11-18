//! Coordinate-aware native PDF table extraction pipeline built on `lopdf`.
//!
//! Decodes bounded PDF page content streams (`BT`/`ET`, `Tm`, `Td`, `TD`, `T*`,
//! `TL`, `Tf`, `Tj`, `TJ`, `'`, `"`, `cm`, `q`/`Q`) into user-space `(x, y)`
//! text spans, segments multi-column tabular regions away from prose lines,
//! clusters row baselines and column x-anchors, and emits attributable cells
//! backed by `SourceLocator::Region`.

use crate::{hex_digest, IngestionError, PdfImportLimits};
use foliora_domain::{
    Claim, ClaimStatus, Provenance, Sensitivity, Source, SourceLocator, SourceProvenance,
    ValidityWindow, SCHEMA_VERSION,
};
use lopdf::content::Content;
use lopdf::{Document, Encoding, LoadOptions, Object};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Configuration governing coordinate clustering and grid segmentation for PDF tables.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PdfTableConfig {
    /// Maximum vertical baseline difference (in PDF points) to group spans into one row.
    pub row_tolerance_pt: f64,
    /// Maximum horizontal left-edge drift (in PDF points) to cluster column anchors.
    pub col_tolerance_pt: f64,
    /// Maximum vertical distance (in PDF points) between consecutive rows in the same table.
    pub max_row_gap_pt: f64,
    /// Minimum number of rows required to emit a structured table.
    pub min_rows: usize,
    /// Minimum number of distinct columns required to emit a structured table.
    pub min_cols: usize,
    /// Negative `TJ` kerning adjustment threshold (in thousandths of text space)
    /// at or below which a `TJ` array splits into separate horizontal spans.
    pub tj_column_split_threshold: f64,
}

impl Default for PdfTableConfig {
    fn default() -> Self {
        Self {
            row_tolerance_pt: 4.0,
            col_tolerance_pt: 24.0,
            max_row_gap_pt: 42.0,
            min_rows: 2,
            min_cols: 2,
            tj_column_split_threshold: -800.0,
        }
    }
}

/// Integer user-space bounding box (in PDF points, rounded to non-zero `u32` bounds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdfTableBBox {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// Positioned cell inside an extracted PDF table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdfTableCell {
    pub row: usize,
    pub col: usize,
    pub text: String,
    pub bbox: PdfTableBBox,
}

/// One structured table reconstructed from a PDF page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedPdfTable {
    pub table_index: usize,
    pub page: u32,
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub cells: Vec<Vec<Option<PdfTableCell>>>,
    pub bbox: PdfTableBBox,
    pub sha256: String,
}

impl ExtractedPdfTable {
    /// Returns the non-header data rows (`rows[1..]`).
    pub fn data_rows(&self) -> &[Vec<String>] {
        if self.rows.len() > 1 {
            &self.rows[1..]
        } else {
            &[]
        }
    }

    /// Renders this table as a deterministic GitHub-flavored Markdown pipe table.
    pub fn to_markdown(&self) -> String {
        if self.rows.is_empty() {
            return String::new();
        }
        let col_count = self.headers.len();
        let mut out = String::new();

        out.push('|');
        for header in &self.headers {
            out.push(' ');
            out.push_str(&escape_markdown_cell(header));
            out.push_str(" |");
        }
        out.push('\n');

        out.push('|');
        for _ in 0..col_count {
            out.push_str(" --- |");
        }
        out.push('\n');

        for row in self.data_rows() {
            out.push('|');
            for col_idx in 0..col_count {
                let cell = row.get(col_idx).map_or("", String::as_str);
                out.push(' ');
                out.push_str(&escape_markdown_cell(cell));
                out.push_str(" |");
            }
            out.push('\n');
        }
        out
    }

    /// Renders this table as RFC 4180 CSV.
    pub fn to_csv(&self) -> String {
        let mut out = String::new();
        for row in &self.rows {
            for (idx, cell) in row.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(&escape_csv_cell(cell));
            }
            out.push('\n');
        }
        out
    }
}

/// Complete extraction report for all structured tables discovered in a PDF source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdfTableExtractionReport {
    pub source: Source,
    pub page_count: usize,
    pub tables: Vec<ExtractedPdfTable>,
}

#[derive(Debug, Clone)]
struct PositionedSpan {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
    font_size: f64,
    text: String,
}

#[derive(Debug, Clone, Copy)]
struct GraphicsState {
    ctm: [f64; 6],
    font_size: f64,
    char_spacing: f64,
    word_spacing: f64,
    horiz_scale: f64,
    leading: f64,
}

impl Default for GraphicsState {
    fn default() -> Self {
        Self {
            ctm: IDENTITY_MATRIX,
            font_size: 12.0,
            char_spacing: 0.0,
            word_spacing: 0.0,
            horiz_scale: 1.0,
            leading: 14.0,
        }
    }
}

const IDENTITY_MATRIX: [f64; 6] = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0];

fn mul_matrix(lhs: [f64; 6], rhs: [f64; 6]) -> [f64; 6] {
    [
        lhs[0] * rhs[0] + lhs[1] * rhs[2],
        lhs[0] * rhs[1] + lhs[1] * rhs[3],
        lhs[2] * rhs[0] + lhs[3] * rhs[2],
        lhs[2] * rhs[1] + lhs[3] * rhs[3],
        lhs[4] * rhs[0] + lhs[5] * rhs[2] + rhs[4],
        lhs[4] * rhs[1] + lhs[5] * rhs[3] + rhs[5],
    ]
}

fn obj_to_f64(obj: &Object) -> Option<f64> {
    match obj {
        Object::Real(v) => Some(f64::from(*v)),
        Object::Integer(v) => Some(*v as f64),
        _ => None,
    }
}

fn parse_matrix6(operands: &[Object]) -> Option<[f64; 6]> {
    if operands.len() < 6 {
        return None;
    }
    Some([
        obj_to_f64(&operands[0])?,
        obj_to_f64(&operands[1])?,
        obj_to_f64(&operands[2])?,
        obj_to_f64(&operands[3])?,
        obj_to_f64(&operands[4])?,
        obj_to_f64(&operands[5])?,
    ])
}

fn decode_pdf_bytes(encoding: Option<&Encoding<'_>>, raw: &[u8]) -> String {
    if raw.len() >= 2 && raw[0] == 0xFE && raw[1] == 0xFF {
        let mut units = Vec::with_capacity((raw.len() - 2) / 2);
        let mut idx = 2;
        while idx + 1 < raw.len() {
            units.push(u16::from_be_bytes([raw[idx], raw[idx + 1]]));
            idx += 2;
        }
        return String::from_utf16_lossy(&units);
    }
    if let Some(enc) = encoding {
        if let Ok(decoded) = Document::decode_text(enc, raw) {
            return decoded;
        }
    }
    match std::str::from_utf8(raw) {
        Ok(utf8) => utf8.to_owned(),
        Err(_) => raw.iter().map(|&b| char::from(b)).collect(),
    }
}

fn estimate_text_advance(text: &str, gs: &GraphicsState) -> f64 {
    let mut advance = 0.0;
    for ch in text.chars() {
        let glyph_em = if ch == ' ' { 0.28 } else { 0.52 };
        let extra = if ch == ' ' {
            gs.char_spacing + gs.word_spacing
        } else {
            gs.char_spacing
        };
        advance += (glyph_em * gs.font_size + extra) * gs.horiz_scale;
    }
    advance.max(1.0)
}

fn emit_span_with_tabs(
    spans: &mut Vec<PositionedSpan>,
    raw_text: &str,
    tm: &mut [f64; 6],
    gs: &GraphicsState,
    total_text_bytes: &mut usize,
    max_total_text_bytes: usize,
) -> Result<(), IngestionError> {
    let parts: Vec<&str> = raw_text.split('\t').collect();
    for (idx, part) in parts.iter().enumerate() {
        if idx > 0 {
            let tab_advance = (2.2 * gs.font_size).max(18.0) * gs.horiz_scale;
            *tm = mul_matrix([1.0, 0.0, 0.0, 1.0, tab_advance, 0.0], *tm);
        }
        let advance_text = estimate_text_advance(part, gs);
        let cleaned = normalize_inline_whitespace(part);
        if !cleaned.is_empty() {
            *total_text_bytes = total_text_bytes.checked_add(cleaned.len()).ok_or(
                IngestionError::PdfTextTooLarge {
                    actual: usize::MAX,
                    limit: max_total_text_bytes,
                },
            )?;
            if *total_text_bytes > max_total_text_bytes {
                return Err(IngestionError::PdfTextTooLarge {
                    actual: *total_text_bytes,
                    limit: max_total_text_bytes,
                });
            }

            let composite = mul_matrix(*tm, gs.ctm);
            let scale_x = composite[0].hypot(composite[1]).max(0.1);
            let scale_y = composite[2].hypot(composite[3]).max(0.1);
            let eff_font = (gs.font_size.abs() * scale_y).max(6.0);
            let width = (advance_text * scale_x).max(4.0);
            let x = composite[4];
            let y = composite[5];
            if x.is_finite() && y.is_finite() {
                spans.push(PositionedSpan {
                    x,
                    y,
                    width,
                    height: eff_font,
                    font_size: eff_font,
                    text: cleaned,
                });
            }
        }
        *tm = mul_matrix([1.0, 0.0, 0.0, 1.0, advance_text, 0.0], *tm);
    }
    Ok(())
}

fn normalize_inline_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = false;
    for ch in s.chars() {
        if ch.is_control() && ch != ' ' {
            continue;
        }
        if ch.is_whitespace() {
            if !prev_space && !out.is_empty() {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

/// Extracts structured tables from native PDF content streams with bounded decompression.
pub fn extract_pdf_tables(
    bytes: &[u8],
    title: Option<String>,
    captured_at: String,
    limits: PdfImportLimits,
    config: PdfTableConfig,
) -> Result<PdfTableExtractionReport, IngestionError> {
    extract_pdf_tables_with_password(bytes, title, captured_at, None, limits, config)
}

/// Extracts structured tables from native or password-protected PDF content streams.
pub fn extract_pdf_tables_with_password(
    bytes: &[u8],
    title: Option<String>,
    captured_at: String,
    password: Option<&str>,
    limits: PdfImportLimits,
    config: PdfTableConfig,
) -> Result<PdfTableExtractionReport, IngestionError> {
    if limits.max_file_bytes == 0
        || limits.max_pages == 0
        || limits.max_page_decompressed_bytes == 0
        || limits.max_total_text_bytes == 0
    {
        return Err(IngestionError::InvalidPdfLimits);
    }
    if config.min_rows < 2
        || config.min_cols < 2
        || !config.row_tolerance_pt.is_finite()
        || config.row_tolerance_pt <= 0.0
        || !config.col_tolerance_pt.is_finite()
        || config.col_tolerance_pt <= 0.0
        || !config.max_row_gap_pt.is_finite()
        || config.max_row_gap_pt <= 0.0
    {
        return Err(IngestionError::InvalidPdfLimits);
    }
    if bytes.is_empty() {
        return Err(IngestionError::Empty);
    }
    if bytes.len() > limits.max_file_bytes {
        return Err(IngestionError::TooLarge {
            actual: bytes.len(),
            limit: limits.max_file_bytes,
        });
    }
    if !bytes
        .get(..bytes.len().min(1_024))
        .is_some_and(|prefix| prefix.windows(5).any(|window| window == b"%PDF-"))
    {
        return Err(IngestionError::InvalidPdf);
    }
    if password.is_some_and(str::is_empty) {
        return Err(IngestionError::EncryptedPdf);
    }

    let document = match password {
        Some(pw) => Document::load_mem_with_options(bytes, LoadOptions::with_password(pw)),
        None => Document::load_mem(bytes),
    }
    .map_err(|err| match err {
        lopdf::Error::Decryption(_) | lopdf::Error::InvalidPassword => IngestionError::EncryptedPdf,
        _ => IngestionError::InvalidPdf,
    })?;

    if document.is_encrypted() {
        return Err(IngestionError::EncryptedPdf);
    }

    let pages = document.get_pages();
    if pages.is_empty() {
        return Err(IngestionError::InvalidPdf);
    }
    if pages.len() > limits.max_pages {
        return Err(IngestionError::TooManyPdfPages {
            actual: pages.len(),
            limit: limits.max_pages,
        });
    }

    let mut total_text_bytes = 0usize;
    let mut tables = Vec::new();

    for (&page_num, &page_id) in &pages {
        let spans = extract_page_positioned_spans(
            &document,
            page_num,
            page_id,
            limits.max_page_decompressed_bytes,
            limits.max_total_text_bytes,
            &mut total_text_bytes,
            &config,
        )?;
        let mut page_tables = reconstruct_page_tables(page_num, &spans, &config, tables.len());
        tables.append(&mut page_tables);
    }

    if total_text_bytes == 0 {
        return Err(IngestionError::PdfHasNoExtractableText);
    }

    let fingerprint = format!("sha256:{}", hex_digest(bytes));
    let id = format!("source:{}", &fingerprint[7..]);
    let mut source = Source::new(id, fingerprint, "application/pdf".to_owned(), captured_at)?;
    source.title = title.filter(|v| !v.trim().is_empty());
    source.validate()?;

    Ok(PdfTableExtractionReport {
        source,
        page_count: pages.len(),
        tables,
    })
}

fn extract_page_positioned_spans(
    document: &Document,
    page_num: u32,
    page_id: (u32, u16),
    max_page_bytes: usize,
    max_total_text_bytes: usize,
    total_text_bytes: &mut usize,
    config: &PdfTableConfig,
) -> Result<Vec<PositionedSpan>, IngestionError> {
    let fonts = document.get_page_fonts(page_id).unwrap_or_default();
    let mut encodings: BTreeMap<Vec<u8>, Encoding<'_>> = BTreeMap::new();
    for (name, font) in fonts {
        if let Ok(enc) = font.get_font_encoding_with_limit(document, max_page_bytes) {
            encodings.insert(name, enc);
        }
    }

    let content_bytes = document
        .get_page_content_with_limit(page_id, max_page_bytes)
        .map_err(|err| match err {
            lopdf::Error::Decompress(lopdf::DecompressError::MemoryLimitExceeded { .. }) => {
                IngestionError::PdfPageTooLarge {
                    page: page_num,
                    limit: max_page_bytes,
                }
            }
            _ => IngestionError::InvalidPdf,
        })?;

    if content_bytes.is_empty() {
        return Ok(Vec::new());
    }

    let content = Content::decode(&content_bytes).map_err(|_| IngestionError::InvalidPdf)?;
    let mut spans = Vec::new();
    let mut gs = GraphicsState::default();
    let mut gs_stack: Vec<GraphicsState> = Vec::new();
    let mut tm = IDENTITY_MATRIX;
    let mut tlm = IDENTITY_MATRIX;
    let mut current_font: Option<Vec<u8>> = None;

    for op in &content.operations {
        let encoding = current_font.as_deref().and_then(|name| encodings.get(name));
        match op.operator.as_str() {
            "q" => gs_stack.push(gs),
            "Q" => {
                if let Some(saved) = gs_stack.pop() {
                    gs = saved;
                }
            }
            "cm" => {
                if let Some(m) = parse_matrix6(&op.operands) {
                    gs.ctm = mul_matrix(m, gs.ctm);
                }
            }
            "BT" => {
                tm = IDENTITY_MATRIX;
                tlm = IDENTITY_MATRIX;
            }
            "ET" => {}
            "Tf" => {
                if let Some(font_name) = op.operands.first().and_then(|o| o.as_name().ok()) {
                    current_font = Some(font_name.to_vec());
                }
                if let Some(sz) = op.operands.get(1).and_then(obj_to_f64) {
                    if sz.abs() > 0.0 {
                        gs.font_size = sz.abs();
                    }
                }
            }
            "TL" => {
                if let Some(tl) = op.operands.first().and_then(obj_to_f64) {
                    gs.leading = tl;
                }
            }
            "Tc" => {
                if let Some(tc) = op.operands.first().and_then(obj_to_f64) {
                    gs.char_spacing = tc;
                }
            }
            "Tw" => {
                if let Some(tw) = op.operands.first().and_then(obj_to_f64) {
                    gs.word_spacing = tw;
                }
            }
            "Tz" => {
                if let Some(tz) = op.operands.first().and_then(obj_to_f64) {
                    if tz > 0.0 {
                        gs.horiz_scale = tz / 100.0;
                    }
                }
            }
            "Tm" => {
                if let Some(m) = parse_matrix6(&op.operands) {
                    tm = m;
                    tlm = m;
                }
            }
            "Td" => {
                if let (Some(tx), Some(ty)) = (
                    op.operands.first().and_then(obj_to_f64),
                    op.operands.get(1).and_then(obj_to_f64),
                ) {
                    tlm = mul_matrix([1.0, 0.0, 0.0, 1.0, tx, ty], tlm);
                    tm = tlm;
                }
            }
            "TD" => {
                if let (Some(tx), Some(ty)) = (
                    op.operands.first().and_then(obj_to_f64),
                    op.operands.get(1).and_then(obj_to_f64),
                ) {
                    gs.leading = -ty;
                    tlm = mul_matrix([1.0, 0.0, 0.0, 1.0, tx, ty], tlm);
                    tm = tlm;
                }
            }
            "T*" => {
                tlm = mul_matrix([1.0, 0.0, 0.0, 1.0, 0.0, -gs.leading], tlm);
                tm = tlm;
            }
            "Tj" => {
                if let Some(raw) = op.operands.first().and_then(|o| o.as_str().ok()) {
                    let decoded = decode_pdf_bytes(encoding, raw);
                    emit_span_with_tabs(
                        &mut spans,
                        &decoded,
                        &mut tm,
                        &gs,
                        total_text_bytes,
                        max_total_text_bytes,
                    )?;
                }
            }
            "'" => {
                tlm = mul_matrix([1.0, 0.0, 0.0, 1.0, 0.0, -gs.leading], tlm);
                tm = tlm;
                if let Some(raw) = op.operands.first().and_then(|o| o.as_str().ok()) {
                    let decoded = decode_pdf_bytes(encoding, raw);
                    emit_span_with_tabs(
                        &mut spans,
                        &decoded,
                        &mut tm,
                        &gs,
                        total_text_bytes,
                        max_total_text_bytes,
                    )?;
                }
            }
            "\"" => {
                if let (Some(aw), Some(ac)) = (
                    op.operands.first().and_then(obj_to_f64),
                    op.operands.get(1).and_then(obj_to_f64),
                ) {
                    gs.word_spacing = aw;
                    gs.char_spacing = ac;
                }
                tlm = mul_matrix([1.0, 0.0, 0.0, 1.0, 0.0, -gs.leading], tlm);
                tm = tlm;
                if let Some(raw) = op.operands.get(2).and_then(|o| o.as_str().ok()) {
                    let decoded = decode_pdf_bytes(encoding, raw);
                    emit_span_with_tabs(
                        &mut spans,
                        &decoded,
                        &mut tm,
                        &gs,
                        total_text_bytes,
                        max_total_text_bytes,
                    )?;
                }
            }
            "TJ" => {
                if let Some(items) = op.operands.first().and_then(|o| o.as_array().ok()) {
                    let mut accum = String::new();
                    let mut accum_tm = tm;
                    for item in items {
                        if let Ok(raw) = item.as_str() {
                            if accum.is_empty() {
                                accum_tm = tm;
                            }
                            let decoded = decode_pdf_bytes(encoding, raw);
                            accum.push_str(&decoded);
                            let adv = estimate_text_advance(&decoded, &gs);
                            tm = mul_matrix([1.0, 0.0, 0.0, 1.0, adv, 0.0], tm);
                        } else if let Some(kern) = obj_to_f64(item) {
                            let shift = (-kern / 1000.0) * gs.font_size * gs.horiz_scale;
                            if kern <= config.tj_column_split_threshold {
                                if !accum.is_empty() {
                                    let mut start_tm = accum_tm;
                                    emit_span_with_tabs(
                                        &mut spans,
                                        &accum,
                                        &mut start_tm,
                                        &gs,
                                        total_text_bytes,
                                        max_total_text_bytes,
                                    )?;
                                    accum.clear();
                                }
                                tm = mul_matrix([1.0, 0.0, 0.0, 1.0, shift, 0.0], tm);
                                accum_tm = tm;
                            } else {
                                if kern <= -180.0 && !accum.is_empty() && !accum.ends_with(' ') {
                                    accum.push(' ');
                                }
                                tm = mul_matrix([1.0, 0.0, 0.0, 1.0, shift, 0.0], tm);
                            }
                        }
                    }
                    if !accum.is_empty() {
                        let mut start_tm = accum_tm;
                        emit_span_with_tabs(
                            &mut spans,
                            &accum,
                            &mut start_tm,
                            &gs,
                            total_text_bytes,
                            max_total_text_bytes,
                        )?;
                    }
                }
            }
            _ => {}
        }
    }

    Ok(spans)
}

#[derive(Debug, Clone)]
struct ClusteredRow {
    mean_y: f64,
    spans: Vec<PositionedSpan>,
}

fn cluster_rows(spans: &[PositionedSpan], row_tolerance_pt: f64) -> Vec<ClusteredRow> {
    if spans.is_empty() {
        return Vec::new();
    }
    let mut sorted = spans.to_vec();
    sorted.sort_by(|a, b| b.y.total_cmp(&a.y).then_with(|| a.x.total_cmp(&b.x)));

    let mut rows: Vec<ClusteredRow> = Vec::new();
    for span in sorted {
        if let Some(last) = rows.last_mut() {
            let tol = row_tolerance_pt.max(0.42 * span.font_size.min(last.spans[0].font_size));
            if (span.y - last.mean_y).abs() <= tol {
                let count = last.spans.len() as f64;
                last.mean_y = (last.mean_y * count + span.y) / (count + 1.0);
                last.spans.push(span);
                continue;
            }
        }
        rows.push(ClusteredRow {
            mean_y: span.y,
            spans: vec![span],
        });
    }

    for row in &mut rows {
        row.spans.sort_by(|a, b| a.x.total_cmp(&b.x));
        let mut merged: Vec<PositionedSpan> = Vec::with_capacity(row.spans.len());
        for span in row.spans.drain(..) {
            if let Some(prev) = merged.last_mut() {
                let prev_right = prev.x + prev.width;
                let gap = span.x - prev_right;
                let join_limit = (0.38 * prev.font_size).max(2.5);
                if gap <= join_limit {
                    if gap > 0.5 && !prev.text.ends_with(' ') && !span.text.starts_with(' ') {
                        prev.text.push(' ');
                    }
                    prev.text.push_str(&span.text);
                    let new_right = prev_right.max(span.x + span.width);
                    prev.width = (new_right - prev.x).max(4.0);
                    prev.height = prev.height.max(span.height);
                    continue;
                }
            }
            merged.push(span);
        }
        row.spans = merged;
    }

    rows
}

fn reconstruct_page_tables(
    page: u32,
    spans: &[PositionedSpan],
    config: &PdfTableConfig,
    starting_index: usize,
) -> Vec<ExtractedPdfTable> {
    let rows = cluster_rows(spans, config.row_tolerance_pt);
    if rows.len() < config.min_rows {
        return Vec::new();
    }

    // Segment contiguous multi-column row blocks bounded by vertical rhythm.
    let mut segments: Vec<Vec<ClusteredRow>> = Vec::new();
    let mut current: Vec<ClusteredRow> = Vec::new();

    for idx in 0..rows.len() {
        let row = &rows[idx];
        let vertical_ok = current
            .last()
            .is_none_or(|prev| (prev.mean_y - row.mean_y).abs() <= config.max_row_gap_pt);

        if row.spans.len() >= config.min_cols {
            if !vertical_ok && !current.is_empty() {
                segments.push(std::mem::take(&mut current));
            }
            current.push(row.clone());
        } else if !current.is_empty() && vertical_ok {
            // Allow a single sparse row only when immediately followed by another multi-column row
            // within the same vertical table rhythm.
            let next_continues = rows.get(idx + 1).is_some_and(|next| {
                next.spans.len() >= config.min_cols
                    && (row.mean_y - next.mean_y).abs() <= config.max_row_gap_pt
            });
            if next_continues && !row.spans.is_empty() {
                current.push(row.clone());
            } else {
                segments.push(std::mem::take(&mut current));
            }
        } else if !current.is_empty() {
            segments.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        segments.push(current);
    }

    let mut extracted = Vec::new();
    for segment in segments {
        if segment.len() < config.min_rows {
            continue;
        }
        if let Some(table) =
            build_table_from_segment(page, starting_index + extracted.len(), &segment, config)
        {
            extracted.push(table);
        }
    }
    extracted
}

fn cluster_column_anchors(segment: &[ClusteredRow], col_tolerance_pt: f64) -> Vec<f64> {
    let mut xs: Vec<f64> = segment
        .iter()
        .flat_map(|r| r.spans.iter().map(|s| s.x))
        .collect();
    xs.sort_by(f64::total_cmp);

    let mut clusters: Vec<(f64, usize)> = Vec::new();
    for x in xs {
        if let Some((mean, count)) = clusters.last_mut() {
            if (x - *mean).abs() <= col_tolerance_pt {
                let n = *count as f64;
                *mean = (*mean * n + x) / (n + 1.0);
                *count += 1;
                continue;
            }
        }
        clusters.push((x, 1));
    }
    clusters.into_iter().map(|(mean, _)| mean).collect()
}

fn span_to_bbox(x_min: f64, y_min: f64, x_max: f64, y_max: f64) -> PdfTableBBox {
    let x = x_min.max(0.0).floor() as u32;
    let y = y_min.max(0.0).floor() as u32;
    let right = x_max.max(x_min + 1.0).ceil() as u32;
    let top = y_max.max(y_min + 1.0).ceil() as u32;
    PdfTableBBox {
        x,
        y,
        width: right.saturating_sub(x).max(1),
        height: top.saturating_sub(y).max(1),
    }
}

#[derive(Debug, Clone)]
struct AccumCell {
    text: String,
    x0: f64,
    y0: f64,
    x1: f64,
    y1: f64,
}

fn build_table_from_segment(
    page: u32,
    table_index: usize,
    segment: &[ClusteredRow],
    config: &PdfTableConfig,
) -> Option<ExtractedPdfTable> {
    let anchors = cluster_column_anchors(segment, config.col_tolerance_pt);
    let col_count = anchors.len();
    if col_count < config.min_cols {
        return None;
    }

    let mut rows_text: Vec<Vec<String>> = Vec::with_capacity(segment.len());
    let mut cells_grid: Vec<Vec<Option<PdfTableCell>>> = Vec::with_capacity(segment.len());

    let mut table_x_min = f64::INFINITY;
    let mut table_y_min = f64::INFINITY;
    let mut table_x_max = f64::NEG_INFINITY;
    let mut table_y_max = f64::NEG_INFINITY;

    for (row_idx, row) in segment.iter().enumerate() {
        let mut cell_accum: Vec<Option<AccumCell>> = vec![None; col_count];
        for span in &row.spans {
            let best_col = anchors
                .iter()
                .enumerate()
                .min_by(|(_, a), (_, b)| (span.x - **a).abs().total_cmp(&(span.x - **b).abs()))
                .map(|(idx, _)| idx)?;

            let sx0 = span.x;
            let sy0 = span.y;
            let sx1 = span.x + span.width;
            let sy1 = span.y + span.height;

            table_x_min = table_x_min.min(sx0);
            table_y_min = table_y_min.min(sy0);
            table_x_max = table_x_max.max(sx1);
            table_y_max = table_y_max.max(sy1);

            match &mut cell_accum[best_col] {
                Some(acc) => {
                    if !acc.text.is_empty() && !span.text.is_empty() {
                        acc.text.push(' ');
                    }
                    acc.text.push_str(&span.text);
                    acc.x0 = acc.x0.min(sx0);
                    acc.y0 = acc.y0.min(sy0);
                    acc.x1 = acc.x1.max(sx1);
                    acc.y1 = acc.y1.max(sy1);
                }
                slot @ None => {
                    *slot = Some(AccumCell {
                        text: span.text.clone(),
                        x0: sx0,
                        y0: sy0,
                        x1: sx1,
                        y1: sy1,
                    });
                }
            }
        }

        let mut row_strings = Vec::with_capacity(col_count);
        let mut row_cells = Vec::with_capacity(col_count);
        for (col_idx, entry) in cell_accum.into_iter().enumerate() {
            match entry {
                Some(acc) => {
                    row_strings.push(acc.text.clone());
                    row_cells.push(Some(PdfTableCell {
                        row: row_idx,
                        col: col_idx,
                        text: acc.text,
                        bbox: span_to_bbox(acc.x0, acc.y0, acc.x1, acc.y1),
                    }));
                }
                None => {
                    row_strings.push(String::new());
                    row_cells.push(None);
                }
            }
        }
        rows_text.push(row_strings);
        cells_grid.push(row_cells);
    }

    if !table_x_min.is_finite() || rows_text.len() < config.min_rows {
        return None;
    }

    let headers = rows_text.first()?.clone();
    let mut canonical = format!("page:{page}\0cols:{col_count}\n");
    for row in &rows_text {
        for (idx, cell) in row.iter().enumerate() {
            if idx > 0 {
                canonical.push('\t');
            }
            canonical.push_str(cell);
        }
        canonical.push('\n');
    }
    let sha256 = format!("sha256:{}", hex_digest(canonical.as_bytes()));

    Some(ExtractedPdfTable {
        table_index,
        page,
        headers,
        rows: rows_text,
        cells: cells_grid,
        bbox: span_to_bbox(table_x_min, table_y_min, table_x_max, table_y_max),
        sha256,
    })
}

/// Creates a candidate `Claim` anchored to an exact extracted PDF table cell via `SourceLocator::Region`.
pub fn candidate_from_pdf_table_cell(
    report: &PdfTableExtractionReport,
    table_index: usize,
    row: usize,
    col: usize,
    claim_type: String,
    subject: String,
) -> Result<Claim, IngestionError> {
    let table = report
        .tables
        .get(table_index)
        .ok_or(IngestionError::InvalidSpan)?;
    let cell = table
        .cells
        .get(row)
        .and_then(|r| r.get(col))
        .and_then(Option::as_ref)
        .ok_or(IngestionError::InvalidSpan)?;

    if cell.text.trim().is_empty() {
        return Err(IngestionError::ValueDoesNotMatchSource);
    }

    let identity = format!(
        "{}\0{}\0{}\0{}\0{}\0{}\0{}",
        report.source.id, table.page, table_index, row, col, claim_type, subject
    );
    let claim = Claim {
        schema_version: SCHEMA_VERSION,
        id: format!("claim:{}", hex_digest(identity.as_bytes())),
        claim_type,
        subject,
        value: Value::String(cell.text.clone()),
        status: ClaimStatus::Candidate,
        provenance: Provenance::Source(SourceProvenance {
            source_id: report.source.id.clone(),
            locator: SourceLocator::Region {
                page: table.page,
                x: cell.bbox.x,
                y: cell.bbox.y,
                width: cell.bbox.width,
                height: cell.bbox.height,
            },
            extractor: Some("foliora:pdf-table-grid:lopdf-0.44:v1".to_owned()),
        }),
        captured_at: report.source.captured_at.clone(),
        validity: ValidityWindow::default(),
        sensitivity: Sensitivity::Private,
        revision: 0,
    };
    claim.validate()?;
    Ok(claim)
}

fn escape_markdown_cell(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '|' => out.push_str("\\|"),
            '\n' | '\r' | '\t' => out.push(' '),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn escape_csv_cell(text: &str) -> String {
    if text.contains([',', '"', '\n', '\r']) {
        let mut out = String::with_capacity(text.len() + 2);
        out.push('"');
        for ch in text.chars() {
            if ch == '"' {
                out.push_str("\"\"");
            } else if !ch.is_control() || ch == '\n' {
                out.push(ch);
            }
        }
        out.push('"');
        out
    } else {
        text.chars().filter(|c| !c.is_control()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::content::Operation;
    use lopdf::{dictionary, Stream};

    const CAPTURED: &str = "2026-11-18T00:00:00Z";

    fn build_pdf_from_ops(pages_ops: Vec<Vec<Operation>>) -> Vec<u8> {
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Helvetica",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });

        let mut page_ids = Vec::new();
        for ops in pages_ops {
            let content = Content { operations: ops };
            let content_id = doc.add_object(Stream::new(
                dictionary! {},
                content.encode().expect("content encodes"),
            ));
            let page_id = doc.add_object(dictionary! {
                "Type" => "Page",
                "Parent" => pages_id,
                "Contents" => content_id,
                "Resources" => resources_id,
                "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
            });
            page_ids.push(page_id.into());
        }

        let page_count = page_ids.len() as i64;
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => page_ids,
                "Count" => page_count,
            }),
        );
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        doc.trailer.set("Root", catalog_id);
        doc.compress();
        let mut out = Vec::new();
        doc.save_to(&mut out).expect("pdf saves");
        out
    }

    #[test]
    fn extracts_multicolumn_pdf_table_ignoring_surrounding_prose() {
        let ops = vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 14.into()]),
            Operation::new(
                "Tm",
                vec![
                    1.into(),
                    0.into(),
                    0.into(),
                    1.into(),
                    50.into(),
                    780.into(),
                ],
            ),
            Operation::new(
                "Tj",
                vec![Object::string_literal("Quarterly Vendor SLA Audit Report")],
            ),
            Operation::new("Tf", vec!["F1".into(), 11.into()]),
            Operation::new(
                "Tm",
                vec![
                    1.into(),
                    0.into(),
                    0.into(),
                    1.into(),
                    50.into(),
                    750.into(),
                ],
            ),
            Operation::new(
                "Tj",
                vec![Object::string_literal(
                    "Executive summary paragraph precedes the table.",
                )],
            ),
            // Row 0 (Headers at y=700)
            Operation::new(
                "Tm",
                vec![
                    1.into(),
                    0.into(),
                    0.into(),
                    1.into(),
                    50.into(),
                    700.into(),
                ],
            ),
            Operation::new("Tj", vec![Object::string_literal("Service")]),
            Operation::new(
                "Tm",
                vec![
                    1.into(),
                    0.into(),
                    0.into(),
                    1.into(),
                    220.into(),
                    700.into(),
                ],
            ),
            Operation::new("Tj", vec![Object::string_literal("Region")]),
            Operation::new(
                "Tm",
                vec![
                    1.into(),
                    0.into(),
                    0.into(),
                    1.into(),
                    380.into(),
                    700.into(),
                ],
            ),
            Operation::new("Tj", vec![Object::string_literal("Monthly SLA")]),
            // Row 1 (Data at y=680)
            Operation::new(
                "Tm",
                vec![
                    1.into(),
                    0.into(),
                    0.into(),
                    1.into(),
                    52.into(),
                    680.into(),
                ],
            ),
            Operation::new("Tj", vec![Object::string_literal("Vault Sync")]),
            Operation::new(
                "Tm",
                vec![
                    1.into(),
                    0.into(),
                    0.into(),
                    1.into(),
                    218.into(),
                    680.into(),
                ],
            ),
            Operation::new("Tj", vec![Object::string_literal("ap-southeast-1")]),
            Operation::new(
                "Tm",
                vec![
                    1.into(),
                    0.into(),
                    0.into(),
                    1.into(),
                    381.into(),
                    680.into(),
                ],
            ),
            Operation::new("Tj", vec![Object::string_literal("99.95%")]),
            // Row 2 (Data at y=660)
            Operation::new(
                "Tm",
                vec![
                    1.into(),
                    0.into(),
                    0.into(),
                    1.into(),
                    51.into(),
                    660.into(),
                ],
            ),
            Operation::new("Tj", vec![Object::string_literal("Object Store")]),
            Operation::new(
                "Tm",
                vec![
                    1.into(),
                    0.into(),
                    0.into(),
                    1.into(),
                    221.into(),
                    660.into(),
                ],
            ),
            Operation::new("Tj", vec![Object::string_literal("eu-central-1")]),
            Operation::new(
                "Tm",
                vec![
                    1.into(),
                    0.into(),
                    0.into(),
                    1.into(),
                    379.into(),
                    660.into(),
                ],
            ),
            Operation::new("Tj", vec![Object::string_literal("99.99%")]),
            // Footer prose at y=580
            Operation::new(
                "Tm",
                vec![
                    1.into(),
                    0.into(),
                    0.into(),
                    1.into(),
                    50.into(),
                    580.into(),
                ],
            ),
            Operation::new(
                "Tj",
                vec![Object::string_literal(
                    "Confidential internal assessment footer.",
                )],
            ),
            Operation::new("ET", vec![]),
        ];

        let pdf_bytes = build_pdf_from_ops(vec![ops]);
        let report = extract_pdf_tables(
            &pdf_bytes,
            Some("sla-audit.pdf".into()),
            CAPTURED.into(),
            PdfImportLimits::default(),
            PdfTableConfig::default(),
        )
        .unwrap();

        assert_eq!(report.page_count, 1);
        assert_eq!(report.tables.len(), 1);
        let tbl = &report.tables[0];
        assert_eq!(tbl.page, 1);
        assert_eq!(tbl.headers, vec!["Service", "Region", "Monthly SLA"]);
        assert_eq!(tbl.data_rows().len(), 2);
        assert_eq!(
            tbl.data_rows()[0],
            vec!["Vault Sync", "ap-southeast-1", "99.95%"]
        );
        assert_eq!(
            tbl.data_rows()[1],
            vec!["Object Store", "eu-central-1", "99.99%"]
        );
        assert!(tbl.sha256.starts_with("sha256:"));

        let md = tbl.to_markdown();
        assert!(md.contains("| Service | Region | Monthly SLA |"));
        assert!(md.contains("| Vault Sync | ap-southeast-1 | 99.95% |"));

        let csv = tbl.to_csv();
        assert!(csv.contains("Service,Region,Monthly SLA\n"));
        assert!(csv.contains("Vault Sync,ap-southeast-1,99.95%\n"));

        // Candidate provenance check
        let claim = candidate_from_pdf_table_cell(
            &report,
            0,
            1,
            2,
            "sla.uptime".into(),
            "service:vault-sync".into(),
        )
        .unwrap();
        assert_eq!(claim.value, Value::String("99.95%".into()));
        assert!(claim.attributable());
        match &claim.provenance {
            Provenance::Source(sp) => match &sp.locator {
                SourceLocator::Region {
                    page,
                    x,
                    y,
                    width,
                    height,
                } => {
                    assert_eq!(*page, 1);
                    assert_eq!(*x, 381);
                    assert_eq!(*y, 680);
                    assert!(*width > 0);
                    assert!(*height > 0);
                }
                other => panic!("expected SourceLocator::Region, got {other:?}"),
            },
            other => panic!("expected source provenance, got {other:?}"),
        }
    }

    #[test]
    fn extracts_tj_kerned_array_table_and_escapes_pipe_and_comma_cells() {
        let ops = vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 10.into()]),
            Operation::new("Td", vec![40.into(), 720.into()]),
            Operation::new(
                "TJ",
                vec![Object::Array(vec![
                    Object::string_literal("Control"),
                    (-4500).into(),
                    Object::string_literal("Expression"),
                    (-4500).into(),
                    Object::string_literal("Notes"),
                ])],
            ),
            Operation::new("Td", vec![0.into(), (-18).into()]),
            Operation::new(
                "TJ",
                vec![Object::Array(vec![
                    Object::string_literal("AC-1"),
                    (-5800).into(),
                    Object::string_literal("a | b"),
                    (-5600).into(),
                    Object::string_literal("Strict, \"verified\""),
                ])],
            ),
            Operation::new("ET", vec![]),
        ];

        let pdf_bytes = build_pdf_from_ops(vec![ops]);
        let report = extract_pdf_tables(
            &pdf_bytes,
            None,
            CAPTURED.into(),
            PdfImportLimits::default(),
            PdfTableConfig::default(),
        )
        .unwrap();

        assert_eq!(report.tables.len(), 1);
        let tbl = &report.tables[0];
        assert_eq!(tbl.headers, vec!["Control", "Expression", "Notes"]);
        assert_eq!(tbl.data_rows()[0][1], "a | b");
        assert!(tbl.to_markdown().contains("a \\| b"));
        assert!(tbl.to_csv().contains("\"Strict, \"\"verified\"\"\""));
    }

    #[test]
    fn rejects_invalid_or_oversized_pdf_inputs_fail_closed() {
        assert_eq!(
            extract_pdf_tables(
                b"",
                None,
                CAPTURED.into(),
                PdfImportLimits::default(),
                PdfTableConfig::default()
            ),
            Err(IngestionError::Empty)
        );
        assert_eq!(
            extract_pdf_tables(
                b"not a pdf",
                None,
                CAPTURED.into(),
                PdfImportLimits::default(),
                PdfTableConfig::default()
            ),
            Err(IngestionError::InvalidPdf)
        );
    }
}
