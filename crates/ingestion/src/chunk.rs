//! Multi-modal document chunking with exact UTF-8 byte/page provenance and
//! SHA-256 content-addressed chunk deduplication across TXT, Markdown, PDF, and DOCX.

use crate::{hex_digest, ImportedDocx, ImportedPdf, ImportedText, IngestionError};
use foliora_domain::{SourceLocator, SourceProvenance};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const DEFAULT_MAX_CHUNK_TOKENS: usize = 256;
pub const DEFAULT_OVERLAP_TOKENS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkingConfig {
    pub max_chunk_tokens: usize,
    pub overlap_tokens: usize,
}

impl Default for ChunkingConfig {
    fn default() -> Self {
        Self {
            max_chunk_tokens: DEFAULT_MAX_CHUNK_TOKENS,
            overlap_tokens: DEFAULT_OVERLAP_TOKENS,
        }
    }
}

impl ChunkingConfig {
    pub fn validate(self) -> Result<Self, IngestionError> {
        if self.max_chunk_tokens == 0 || self.overlap_tokens >= self.max_chunk_tokens {
            return Err(IngestionError::InvalidChunkingConfig);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentChunk {
    pub id: String,
    pub source_id: String,
    pub media_type: String,
    pub text: String,
    pub estimated_tokens: usize,
    pub raw_sha256: String,
    pub canonical_sha256: String,
    pub primary_provenance: SourceProvenance,
    pub duplicate_provenances: Vec<SourceProvenance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkBatchReport {
    pub chunks: Vec<DocumentChunk>,
    pub total_input_chunks: usize,
    pub deduplicated_count: usize,
    pub total_tokens: usize,
    pub saved_tokens: usize,
}

/// Deterministic offline BPE-calibrated token estimator supporting English,
/// Vietnamese, CJK, and structured punctuation without external model downloads.
pub fn estimate_tokens(text: &str) -> usize {
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

/// Computes a whitespace-normalized SHA-256 digest (`sha256:<64-hex>`) so
/// identical clauses across PDF line-wraps, DOCX paragraphs, and plain text
/// deduplicate deterministically.
pub fn canonical_chunk_sha256(text: &str) -> String {
    let mut normalized = String::with_capacity(text.len());
    for word in text.split_whitespace() {
        if !normalized.is_empty() {
            normalized.push(' ');
        }
        normalized.push_str(word);
    }
    format!("sha256:{}", hex_digest(normalized.as_bytes()))
}

pub fn chunk_text(
    imported: &ImportedText,
    config: ChunkingConfig,
) -> Result<Vec<DocumentChunk>, IngestionError> {
    let config = config.validate()?;
    Ok(chunk_str_into_spans(
        &imported.text,
        &imported.source.id,
        &imported.source.media_type,
        None,
        "foliora:chunker-text:v1",
        config,
    ))
}

pub fn chunk_docx(
    imported: &ImportedDocx,
    config: ChunkingConfig,
) -> Result<Vec<DocumentChunk>, IngestionError> {
    let config = config.validate()?;
    Ok(chunk_str_into_spans(
        &imported.text,
        &imported.source.id,
        &imported.source.media_type,
        None,
        "foliora:chunker-docx:v1",
        config,
    ))
}

pub fn chunk_pdf(
    imported: &ImportedPdf,
    config: ChunkingConfig,
) -> Result<Vec<DocumentChunk>, IngestionError> {
    let config = config.validate()?;
    let mut out = Vec::new();
    for page in &imported.pages {
        if page.text.trim().is_empty() {
            continue;
        }
        out.extend(chunk_str_into_spans(
            &page.text,
            &imported.source.id,
            &imported.source.media_type,
            Some(page.page),
            "foliora:chunker-pdf:v1",
            config,
        ));
    }
    Ok(out)
}

/// Multi-document SHA-256 chunk deduplicator preserving cross-source provenance.
#[derive(Debug, Default)]
pub struct ChunkDeduplicator {
    ordered_keys: Vec<String>,
    by_canonical: BTreeMap<String, DocumentChunk>,
    total_input_chunks: usize,
    deduplicated_count: usize,
    saved_tokens: usize,
}

impl ChunkDeduplicator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ingest_text(
        &mut self,
        imported: &ImportedText,
        config: ChunkingConfig,
    ) -> Result<usize, IngestionError> {
        let chunks = chunk_text(imported, config)?;
        Ok(self.ingest_chunks(chunks))
    }

    pub fn ingest_docx(
        &mut self,
        imported: &ImportedDocx,
        config: ChunkingConfig,
    ) -> Result<usize, IngestionError> {
        let chunks = chunk_docx(imported, config)?;
        Ok(self.ingest_chunks(chunks))
    }

    pub fn ingest_pdf(
        &mut self,
        imported: &ImportedPdf,
        config: ChunkingConfig,
    ) -> Result<usize, IngestionError> {
        let chunks = chunk_pdf(imported, config)?;
        Ok(self.ingest_chunks(chunks))
    }

    /// Inserts chunks and returns the number of newly added unique chunks.
    pub fn ingest_chunks(&mut self, chunks: Vec<DocumentChunk>) -> usize {
        let mut added = 0usize;
        for chunk in chunks {
            self.total_input_chunks += 1;
            if let Some(existing) = self.by_canonical.get_mut(&chunk.canonical_sha256) {
                self.deduplicated_count += 1;
                self.saved_tokens += chunk.estimated_tokens;
                if existing.primary_provenance != chunk.primary_provenance
                    && !existing
                        .duplicate_provenances
                        .contains(&chunk.primary_provenance)
                {
                    existing
                        .duplicate_provenances
                        .push(chunk.primary_provenance);
                }
                for extra in chunk.duplicate_provenances {
                    if existing.primary_provenance != extra
                        && !existing.duplicate_provenances.contains(&extra)
                    {
                        existing.duplicate_provenances.push(extra);
                    }
                }
            } else {
                self.ordered_keys.push(chunk.canonical_sha256.clone());
                self.by_canonical
                    .insert(chunk.canonical_sha256.clone(), chunk);
                added += 1;
            }
        }
        added
    }

    pub fn finish(mut self) -> ChunkBatchReport {
        let mut chunks = Vec::with_capacity(self.ordered_keys.len());
        let mut total_tokens = 0usize;
        for key in self.ordered_keys {
            if let Some(chunk) = self.by_canonical.remove(&key) {
                total_tokens += chunk.estimated_tokens;
                chunks.push(chunk);
            }
        }
        ChunkBatchReport {
            chunks,
            total_input_chunks: self.total_input_chunks,
            deduplicated_count: self.deduplicated_count,
            total_tokens,
            saved_tokens: self.saved_tokens,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct LexicalAtom {
    start: usize,
    end: usize,
    tokens: usize,
}

fn split_atoms(text: &str, max_chunk_tokens: usize) -> Vec<LexicalAtom> {
    let mut atoms = Vec::new();
    let mut in_word = false;
    let mut word_start = 0usize;

    for (idx, ch) in text.char_indices() {
        if ch.is_whitespace() {
            if in_word {
                push_bounded_atom(text, word_start, idx, max_chunk_tokens, &mut atoms);
                in_word = false;
            }
        } else if !in_word {
            word_start = idx;
            in_word = true;
        }
    }
    if in_word {
        push_bounded_atom(text, word_start, text.len(), max_chunk_tokens, &mut atoms);
    }
    atoms
}

fn push_bounded_atom(
    text: &str,
    start: usize,
    end: usize,
    max_chunk_tokens: usize,
    out: &mut Vec<LexicalAtom>,
) {
    let slice = &text[start..end];
    let tok = estimate_tokens(slice);
    if tok <= max_chunk_tokens {
        out.push(LexicalAtom {
            start,
            end,
            tokens: tok,
        });
        return;
    }

    // Split oversized unbroken strings (such as long base64 or hex lines) along UTF-8 scalar boundaries.
    let mut sub_start = start;
    let mut acc_chars = 0usize;
    let chars_per_window = (max_chunk_tokens.saturating_mul(3)).max(1);
    for (rel_idx, _) in slice.char_indices() {
        if rel_idx > 0 && acc_chars >= chars_per_window {
            let split_at = start + rel_idx;
            let piece = &text[sub_start..split_at];
            out.push(LexicalAtom {
                start: sub_start,
                end: split_at,
                tokens: estimate_tokens(piece).min(max_chunk_tokens).max(1),
            });
            sub_start = split_at;
            acc_chars = 0;
        }
        acc_chars += 1;
    }
    if sub_start < end {
        let piece = &text[sub_start..end];
        out.push(LexicalAtom {
            start: sub_start,
            end,
            tokens: estimate_tokens(piece).min(max_chunk_tokens).max(1),
        });
    }
}

fn chunk_str_into_spans(
    text: &str,
    source_id: &str,
    media_type: &str,
    page: Option<u32>,
    extractor: &str,
    config: ChunkingConfig,
) -> Vec<DocumentChunk> {
    let atoms = split_atoms(text, config.max_chunk_tokens);
    if atoms.is_empty() {
        return Vec::new();
    }

    let mut chunks = Vec::new();
    let mut cursor = 0usize;

    while cursor < atoms.len() {
        let mut end_idx = cursor;
        let mut window_tokens = 0usize;

        while end_idx < atoms.len() {
            let next_tokens = window_tokens + atoms[end_idx].tokens;
            if end_idx > cursor && next_tokens > config.max_chunk_tokens {
                break;
            }
            window_tokens = next_tokens;
            end_idx += 1;
            if window_tokens >= config.max_chunk_tokens {
                break;
            }
        }

        let byte_start = atoms[cursor].start;
        let byte_end = atoms[end_idx - 1].end;
        let slice = &text[byte_start..byte_end];
        let raw_sha256 = format!("sha256:{}", hex_digest(slice.as_bytes()));
        let canonical_sha256 = canonical_chunk_sha256(slice);
        let locator = match page {
            Some(page_num) => SourceLocator::PageSpan {
                page: page_num,
                start: byte_start as u64,
                end: byte_end as u64,
            },
            None => SourceLocator::Span {
                start: byte_start as u64,
                end: byte_end as u64,
            },
        };
        let identity = match page {
            Some(p) => format!("{source_id}\0{p}\0{byte_start}\0{byte_end}"),
            None => format!("{source_id}\0{byte_start}\0{byte_end}"),
        };
        chunks.push(DocumentChunk {
            id: format!("chunk:{}", hex_digest(identity.as_bytes())),
            source_id: source_id.to_owned(),
            media_type: media_type.to_owned(),
            text: slice.to_owned(),
            estimated_tokens: estimate_tokens(slice),
            raw_sha256,
            canonical_sha256,
            primary_provenance: SourceProvenance {
                source_id: source_id.to_owned(),
                locator,
                extractor: Some(extractor.to_owned()),
            },
            duplicate_provenances: Vec::new(),
        });

        if end_idx >= atoms.len() {
            break;
        }

        // Step forward while retaining up to `overlap_tokens` of trailing context.
        let mut overlap = 0usize;
        let mut next_cursor = end_idx;
        while next_cursor > cursor + 1 {
            let prev = atoms[next_cursor - 1].tokens;
            if overlap + prev > config.overlap_tokens {
                break;
            }
            overlap += prev;
            next_cursor -= 1;
        }
        cursor = next_cursor.max(cursor + 1);
    }

    chunks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        import_docx, import_pdf, import_text, DocxImportLimits, PdfImportLimits, TextInputKind,
        DEFAULT_MAX_TEXT_BYTES,
    };
    use lopdf::content::{Content, Operation};
    use lopdf::{dictionary, Document, Object, Stream};
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    const CAPTURED: &str = "2026-11-15T00:00:00Z";

    fn sample_pdf(page_texts: &[&str]) -> Vec<u8> {
        let mut document = Document::with_version("1.5");
        let pages_id = document.new_object_id();
        let font_id = document.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Helvetica",
        });
        let resources_id = document.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });
        let mut page_ids = Vec::new();
        for text in page_texts {
            let content = Content {
                operations: vec![
                    Operation::new("BT", vec![]),
                    Operation::new("Tf", vec!["F1".into(), 12.into()]),
                    Operation::new("Td", vec![50.into(), 780.into()]),
                    Operation::new("Tj", vec![Object::string_literal(*text)]),
                    Operation::new("ET", vec![]),
                ],
            };
            let content_id = document.add_object(Stream::new(
                dictionary! {},
                content.encode().expect("synthetic content encodes"),
            ));
            let page_id = document.add_object(dictionary! {
                "Type" => "Page",
                "Parent" => pages_id,
                "Contents" => content_id,
                "Resources" => resources_id,
                "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
            });
            page_ids.push(page_id.into());
        }
        document.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => page_ids,
                "Count" => page_texts.len() as i64,
            }),
        );
        let catalog_id = document.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        document.trailer.set("Root", catalog_id);
        document.compress();
        let mut bytes = Vec::new();
        document.save_to(&mut bytes).unwrap();
        bytes
    }

    fn sample_docx(paragraph: &str) -> Vec<u8> {
        let content_types = r#"<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"#;
        let doc_xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>{paragraph}</w:t></w:r></w:p></w:body>
</w:document>"#
        );
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        writer.start_file("[Content_Types].xml", opts).unwrap();
        writer.write_all(content_types.as_bytes()).unwrap();
        writer.start_file("word/document.xml", opts).unwrap();
        writer.write_all(doc_xml.as_bytes()).unwrap();
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn multimodal_deduplicator_merges_identical_clauses_across_pdf_docx_and_txt() {
        let shared_clause = "Warranty SLA guarantees 99.95% uptime through 2027-12-31";
        let txt = import_text(
            format!("Warranty   SLA guarantees\n99.95% uptime through 2027-12-31").as_bytes(),
            TextInputKind::PlainText,
            Some("notes.txt".into()),
            CAPTURED.into(),
            DEFAULT_MAX_TEXT_BYTES,
        )
        .unwrap();
        let docx = import_docx(
            &sample_docx(shared_clause),
            Some("agreement.docx".into()),
            CAPTURED.into(),
            DocxImportLimits::default(),
        )
        .unwrap();
        let pdf = import_pdf(
            &sample_pdf(&[shared_clause, "Unique appendix schedule B"]),
            Some("signed.pdf".into()),
            CAPTURED.into(),
            PdfImportLimits::default(),
        )
        .unwrap();

        let cfg = ChunkingConfig {
            max_chunk_tokens: 64,
            overlap_tokens: 8,
        };
        let mut dedup = ChunkDeduplicator::new();
        assert_eq!(dedup.ingest_text(&txt, cfg).unwrap(), 1);
        assert_eq!(dedup.ingest_docx(&docx, cfg).unwrap(), 0);
        assert_eq!(dedup.ingest_pdf(&pdf, cfg).unwrap(), 1);

        let report = dedup.finish();
        assert_eq!(report.total_input_chunks, 4);
        assert_eq!(report.chunks.len(), 2);
        assert_eq!(report.deduplicated_count, 2);
        assert!(report.saved_tokens > 0);
        assert_eq!(report.chunks[0].duplicate_provenances.len(), 2);
        for chunk in &report.chunks {
            chunk.primary_provenance.locator.validate().unwrap();
        }
    }

    #[test]
    fn sliding_window_preserves_exact_utf8_byte_offsets_and_rejects_bad_config() {
        assert_eq!(
            ChunkingConfig {
                max_chunk_tokens: 0,
                overlap_tokens: 0
            }
            .validate(),
            Err(IngestionError::InvalidChunkingConfig)
        );
        assert_eq!(
            ChunkingConfig {
                max_chunk_tokens: 16,
                overlap_tokens: 16
            }
            .validate(),
            Err(IngestionError::InvalidChunkingConfig)
        );

        let body = "Điều khoản bảo mật dữ liệu cá nhân năm 2026 yêu cầu xác minh SHA-256 trên mọi gói ngữ cảnh trước khi chia sẻ cho mô hình ngôn ngữ.";
        let txt = import_text(
            body.as_bytes(),
            TextInputKind::Markdown,
            Some("policy.md".into()),
            CAPTURED.into(),
            DEFAULT_MAX_TEXT_BYTES,
        )
        .unwrap();
        let chunks = chunk_text(
            &txt,
            ChunkingConfig {
                max_chunk_tokens: 18,
                overlap_tokens: 4,
            },
        )
        .unwrap();
        assert!(chunks.len() >= 2);
        for chunk in &chunks {
            if let SourceLocator::Span { start, end } = chunk.primary_provenance.locator {
                assert_eq!(&txt.text[start as usize..end as usize], chunk.text);
            } else {
                panic!("expected byte span locator");
            }
        }
    }
}
