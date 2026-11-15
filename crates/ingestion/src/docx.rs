//! Bounded, offline OOXML (`.docx`) WordprocessingML ingestion.
//!
//! Parses `word/document.xml` without external DTD resolution, macro execution,
//! or network access, preserving original `.docx` bytes as the content-addressed
//! SHA-256 source identity.

use crate::{hex_digest, IngestionError};
use foliora_domain::{
    Claim, ClaimStatus, Provenance, Sensitivity, Source, SourceLocator, SourceProvenance,
    ValidityWindow, SCHEMA_VERSION,
};
use serde_json::Value;
use std::io::{Cursor, Read};
use zip::ZipArchive;

pub const DEFAULT_MAX_DOCX_BYTES: usize = 25 * 1024 * 1024;
pub const DEFAULT_MAX_DOCX_ENTRIES: usize = 512;
pub const DEFAULT_MAX_DOCX_XML_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_DOCX_TEXT_BYTES: usize = 10 * 1024 * 1024;

const OLE2_CFB_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const DOCX_MEDIA_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocxImportLimits {
    pub max_file_bytes: usize,
    pub max_archive_entries: usize,
    pub max_xml_decompressed_bytes: usize,
    pub max_total_text_bytes: usize,
}

impl Default for DocxImportLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_DOCX_BYTES,
            max_archive_entries: DEFAULT_MAX_DOCX_ENTRIES,
            max_xml_decompressed_bytes: DEFAULT_MAX_DOCX_XML_BYTES,
            max_total_text_bytes: DEFAULT_MAX_DOCX_TEXT_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedDocx {
    pub source: Source,
    pub text: String,
    pub paragraph_count: usize,
}

/// Extracts WordprocessingML body text locally from an OOXML `.docx` archive.
pub fn import_docx(
    bytes: &[u8],
    title: Option<String>,
    captured_at: String,
    limits: DocxImportLimits,
) -> Result<ImportedDocx, IngestionError> {
    if limits.max_file_bytes == 0
        || limits.max_archive_entries == 0
        || limits.max_xml_decompressed_bytes == 0
        || limits.max_total_text_bytes == 0
    {
        return Err(IngestionError::InvalidDocxLimits);
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
    if bytes.starts_with(&OLE2_CFB_MAGIC) {
        return Err(IngestionError::EncryptedDocx);
    }
    if !bytes.starts_with(b"PK\x03\x04") {
        return Err(IngestionError::InvalidDocx);
    }

    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).map_err(|_| IngestionError::InvalidDocx)?;
    if archive.len() > limits.max_archive_entries {
        return Err(IngestionError::TooManyDocxEntries {
            actual: archive.len(),
            limit: limits.max_archive_entries,
        });
    }

    let mut has_content_types = false;
    let mut document_xml: Option<String> = None;

    for idx in 0..archive.len() {
        let file = archive
            .by_index(idx)
            .map_err(|_| IngestionError::InvalidDocx)?;
        if file.is_symlink() {
            return Err(IngestionError::InvalidDocx);
        }
        let name = file
            .enclosed_name()
            .ok_or(IngestionError::InvalidDocx)?
            .to_string_lossy()
            .replace('\\', "/");

        if name.eq_ignore_ascii_case("EncryptedPackage")
            || name.eq_ignore_ascii_case("EncryptionInfo")
        {
            return Err(IngestionError::EncryptedDocx);
        }
        if name == "[Content_Types].xml" {
            let xml = read_bounded_utf8_entry(file, &name, limits.max_xml_decompressed_bytes)?;
            reject_xml_dtd(&xml)?;
            has_content_types = true;
        } else if name == "word/document.xml" {
            let xml = read_bounded_utf8_entry(file, &name, limits.max_xml_decompressed_bytes)?;
            reject_xml_dtd(&xml)?;
            document_xml = Some(xml);
        }
    }

    if !has_content_types {
        return Err(IngestionError::InvalidDocx);
    }
    let xml = document_xml.ok_or(IngestionError::InvalidDocx)?;
    let (text, paragraph_count) = extract_wordprocessingml_text(&xml, limits.max_total_text_bytes)?;
    if text.trim().is_empty() {
        return Err(IngestionError::DocxHasNoExtractableText);
    }

    let fingerprint = format!("sha256:{}", hex_digest(bytes));
    let id = format!("source:{}", &fingerprint[7..]);
    let mut source = Source::new(id, fingerprint, DOCX_MEDIA_TYPE.to_owned(), captured_at)?;
    source.title = title.filter(|value| !value.trim().is_empty());
    source.validate()?;

    Ok(ImportedDocx {
        source,
        text,
        paragraph_count,
    })
}

/// Creates a candidate from an exact UTF-8 byte span inside extracted `.docx` text.
pub fn candidate_from_docx_span(
    imported: &ImportedDocx,
    claim_type: String,
    subject: String,
    start: usize,
    end: usize,
) -> Result<Claim, IngestionError> {
    let value = imported
        .text
        .get(start..end)
        .ok_or(IngestionError::InvalidSpan)?;
    if value.trim().is_empty() {
        return Err(IngestionError::ValueDoesNotMatchSource);
    }
    let identity = format!(
        "{}\0{}\0{}\0{}\0{}",
        imported.source.id, claim_type, subject, start, end
    );
    let claim = Claim {
        schema_version: SCHEMA_VERSION,
        id: format!("claim:{}", hex_digest(identity.as_bytes())),
        claim_type,
        subject,
        value: Value::String(value.to_owned()),
        status: ClaimStatus::Candidate,
        provenance: Provenance::Source(SourceProvenance {
            source_id: imported.source.id.clone(),
            locator: SourceLocator::Span {
                start: start as u64,
                end: end as u64,
            },
            extractor: Some("foliora:docx-ooxml:v1".to_owned()),
        }),
        captured_at: imported.source.captured_at.clone(),
        validity: ValidityWindow::default(),
        sensitivity: Sensitivity::Private,
        revision: 0,
    };
    claim.validate()?;
    Ok(claim)
}

fn read_bounded_utf8_entry<R: Read>(
    entry: R,
    entry_name: &str,
    limit: usize,
) -> Result<String, IngestionError> {
    let mut buf = Vec::new();
    entry
        .take((limit + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|_| IngestionError::InvalidDocx)?;
    if buf.len() > limit {
        return Err(IngestionError::DocxXmlTooLarge {
            entry: entry_name.to_owned(),
            limit,
        });
    }
    if buf.contains(&0) {
        return Err(IngestionError::BinaryContent);
    }
    String::from_utf8(buf).map_err(|_| IngestionError::InvalidUtf8)
}

fn reject_xml_dtd(xml: &str) -> Result<(), IngestionError> {
    let bytes = xml.as_bytes();
    for window in bytes.windows(9) {
        if window.eq_ignore_ascii_case(b"<!doctype") || window.eq_ignore_ascii_case(b"<!entity ") {
            return Err(IngestionError::InvalidDocx);
        }
    }
    Ok(())
}

fn push_bounded_str(out: &mut String, piece: &str, limit: usize) -> Result<(), IngestionError> {
    let next_len = out
        .len()
        .checked_add(piece.len())
        .ok_or(IngestionError::DocxTextTooLarge {
            actual: usize::MAX,
            limit,
        })?;
    if next_len > limit {
        return Err(IngestionError::DocxTextTooLarge {
            actual: next_len,
            limit,
        });
    }
    out.push_str(piece);
    Ok(())
}

fn push_bounded_char(out: &mut String, ch: char, limit: usize) -> Result<(), IngestionError> {
    let mut tmp = [0u8; 4];
    let encoded = ch.encode_utf8(&mut tmp);
    push_bounded_str(out, encoded, limit)
}

fn is_word_tag<'a>(raw_name: &'a str) -> Option<&'a str> {
    if let Some((prefix, local)) = raw_name.split_once(':') {
        if prefix == "w" {
            Some(local)
        } else {
            None
        }
    } else {
        Some(raw_name)
    }
}

fn decode_xml_entities_into(
    raw: &str,
    out: &mut String,
    limit: usize,
) -> Result<(), IngestionError> {
    let mut rest = raw;
    while let Some(amp) = rest.find('&') {
        let (before, after_amp) = rest.split_at(amp);
        push_bounded_str(out, before, limit)?;
        let semi = after_amp[1..]
            .find(';')
            .ok_or(IngestionError::InvalidDocx)?;
        let entity = &after_amp[1..1 + semi];
        let decoded = match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            num if num.starts_with("#x") || num.starts_with("#X") => {
                let code =
                    u32::from_str_radix(&num[2..], 16).map_err(|_| IngestionError::InvalidDocx)?;
                if code == 0 {
                    return Err(IngestionError::BinaryContent);
                }
                char::from_u32(code).ok_or(IngestionError::InvalidDocx)?
            }
            num if num.starts_with('#') => {
                let code = num[1..]
                    .parse::<u32>()
                    .map_err(|_| IngestionError::InvalidDocx)?;
                if code == 0 {
                    return Err(IngestionError::BinaryContent);
                }
                char::from_u32(code).ok_or(IngestionError::InvalidDocx)?
            }
            _ => return Err(IngestionError::InvalidDocx),
        };
        push_bounded_char(out, decoded, limit)?;
        rest = &after_amp[2 + semi..];
    }
    push_bounded_str(out, rest, limit)
}

fn extract_wordprocessingml_text(
    xml: &str,
    max_text_bytes: usize,
) -> Result<(String, usize), IngestionError> {
    let mut out = String::new();
    let mut in_text_run = false;
    let mut skip_depth = 0usize;
    let mut in_table_cell = false;
    let mut cell_index_in_row = 0usize;
    let mut cell_para_count = 0usize;
    let mut paragraph_count = 0usize;
    let mut saw_body_tag = false;

    let bytes = xml.as_bytes();
    let mut pos = 0usize;

    while pos < bytes.len() {
        if bytes[pos] == b'<' {
            if xml[pos..].starts_with("<!--") {
                let end = xml[pos + 4..]
                    .find("-->")
                    .ok_or(IngestionError::InvalidDocx)?;
                pos += 4 + end + 3;
                continue;
            }
            if xml[pos..].starts_with("<?") {
                let end = xml[pos + 2..]
                    .find("?>")
                    .ok_or(IngestionError::InvalidDocx)?;
                pos += 2 + end + 2;
                continue;
            }
            if xml[pos..].starts_with("<![CDATA[") {
                let end = xml[pos + 9..]
                    .find("]]>")
                    .ok_or(IngestionError::InvalidDocx)?;
                if in_text_run && skip_depth == 0 {
                    let cdata = &xml[pos + 9..pos + 9 + end];
                    push_bounded_str(&mut out, cdata, max_text_bytes)?;
                }
                pos += 9 + end + 3;
                continue;
            }

            let gt = find_tag_end(xml, pos + 1).ok_or(IngestionError::InvalidDocx)?;
            let tag_inner = xml[pos + 1..gt].trim();
            pos = gt + 1;

            if tag_inner.is_empty() {
                return Err(IngestionError::InvalidDocx);
            }

            let is_closing = tag_inner.starts_with('/');
            let is_self_closing = !is_closing && tag_inner.ends_with('/');
            let clean = if is_closing {
                tag_inner[1..].trim()
            } else if is_self_closing {
                tag_inner[..tag_inner.len() - 1].trim()
            } else {
                tag_inner
            };
            let raw_name = clean
                .split(|c: char| c.is_ascii_whitespace())
                .next()
                .unwrap_or("");

            if let Some(local) = is_word_tag(raw_name) {
                match (local, is_closing, is_self_closing) {
                    ("document" | "body", false, _) => {
                        saw_body_tag = true;
                    }
                    ("delText" | "instrText" | "del", false, false) => {
                        skip_depth = skip_depth.saturating_add(1);
                    }
                    ("delText" | "instrText" | "del", true, _) => {
                        skip_depth = skip_depth.saturating_sub(1);
                    }
                    ("tr", false, false) if skip_depth == 0 => {
                        cell_index_in_row = 0;
                    }
                    ("tr", true, _) if skip_depth == 0 => {
                        if !out.is_empty() && !out.ends_with('\n') {
                            push_bounded_char(&mut out, '\n', max_text_bytes)?;
                        }
                    }
                    ("tc", false, false) if skip_depth == 0 => {
                        if cell_index_in_row > 0 {
                            push_bounded_char(&mut out, '\t', max_text_bytes)?;
                        }
                        in_table_cell = true;
                        cell_para_count = 0;
                        cell_index_in_row += 1;
                    }
                    ("tc", true, _) if skip_depth == 0 => {
                        in_table_cell = false;
                    }
                    ("p", false, false) if skip_depth == 0 => {
                        if in_table_cell && cell_para_count > 0 {
                            push_bounded_char(&mut out, ' ', max_text_bytes)?;
                        }
                    }
                    ("p", false, true) if skip_depth == 0 => {
                        paragraph_count += 1;
                        if in_table_cell {
                            cell_para_count += 1;
                        } else if !out.is_empty() && !out.ends_with('\n') {
                            push_bounded_char(&mut out, '\n', max_text_bytes)?;
                        }
                    }
                    ("p", true, _) if skip_depth == 0 => {
                        paragraph_count += 1;
                        if in_table_cell {
                            cell_para_count += 1;
                        } else if !out.is_empty() && !out.ends_with('\n') {
                            push_bounded_char(&mut out, '\n', max_text_bytes)?;
                        }
                    }
                    ("t", false, false) if skip_depth == 0 => {
                        in_text_run = true;
                    }
                    ("t", true, _) => {
                        in_text_run = false;
                    }
                    ("tab", false, _) if skip_depth == 0 => {
                        push_bounded_char(&mut out, '\t', max_text_bytes)?;
                    }
                    ("br" | "cr", false, _) if skip_depth == 0 => {
                        push_bounded_char(&mut out, '\n', max_text_bytes)?;
                    }
                    _ => {}
                }
            }
        } else {
            let next_lt = xml[pos..]
                .find('<')
                .map_or(bytes.len(), |offset| pos + offset);
            if in_text_run && skip_depth == 0 {
                let raw_text = &xml[pos..next_lt];
                decode_xml_entities_into(raw_text, &mut out, max_text_bytes)?;
            }
            pos = next_lt;
        }
    }

    if !saw_body_tag {
        return Err(IngestionError::InvalidDocx);
    }
    while out.ends_with('\n') {
        out.pop();
    }
    Ok((out, paragraph_count))
}

fn find_tag_end(xml: &str, start: usize) -> Option<usize> {
    let bytes = xml.as_bytes();
    let mut quote: Option<u8> = None;
    let mut idx = start;
    while idx < bytes.len() {
        let b = bytes[idx];
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
        } else if b == b'"' || b == b'\'' {
            quote = Some(b);
        } else if b == b'>' {
            return Some(idx);
        }
        idx += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    const CAPTURED: &str = "2026-11-15T00:00:00Z";

    fn build_docx(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (name, content) in entries {
            writer.start_file(*name, options).unwrap();
            writer.write_all(content).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn standard_docx(document_xml: &str) -> Vec<u8> {
        let content_types = r#"<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"#;
        build_docx(&[
            ("[Content_Types].xml", content_types.as_bytes()),
            ("word/document.xml", document_xml.as_bytes()),
        ])
    }

    #[test]
    fn docx_import_extracts_paragraphs_tables_entities_and_ignores_deleted_runs() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r><w:t>Hop dong dich vu &amp; bao hanh</w:t></w:r>
      <w:del><w:r><w:delText>OLD DELETED CLAUSE</w:delText></w:r></w:del>
      <w:r><w:instrText>HYPERLINK "https://evil.example"</w:instrText></w:r>
    </w:p>
    <w:tbl>
      <w:tr>
        <w:tc><w:p><w:r><w:t>Ma du an</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>FLR-2026&#x2D;A</w:t></w:r></w:p></w:tc>
      </w:tr>
    </w:tbl>
    <w:p>
      <w:r><w:t>Lien he:</w:t><w:tab/><w:t>ops@foliora.local</w:t></w:r>
    </w:p>
  </w:body>
</w:document>"#;
        let bytes = standard_docx(xml);
        let imported = import_docx(
            &bytes,
            Some("contract.docx".into()),
            CAPTURED.into(),
            DocxImportLimits::default(),
        )
        .unwrap();

        assert_eq!(imported.source.media_type, DOCX_MEDIA_TYPE);
        assert_eq!(
            imported.source.fingerprint,
            format!("sha256:{}", hex_digest(&bytes))
        );
        assert!(imported.text.contains("Hop dong dich vu & bao hanh"));
        assert!(imported.text.contains("Ma du an\tFLR-2026-A"));
        assert!(imported.text.contains("Lien he:\tops@foliora.local"));
        assert!(!imported.text.contains("OLD DELETED CLAUSE"));
        assert!(!imported.text.contains("evil.example"));
        assert_eq!(imported.paragraph_count, 4);

        let start = imported.text.find("FLR-2026-A").unwrap();
        let claim = candidate_from_docx_span(
            &imported,
            "contract.code".into(),
            "project:1".into(),
            start,
            start + "FLR-2026-A".len(),
        )
        .unwrap();
        assert_eq!(claim.value, Value::String("FLR-2026-A".into()));
        assert!(claim.attributable());
    }

    #[test]
    fn docx_rejects_encrypted_xxe_dtd_and_over_limit_archives() {
        let mut ole2 = OLE2_CFB_MAGIC.to_vec();
        ole2.extend_from_slice(b"encrypted-ooxml-payload");
        assert_eq!(
            import_docx(&ole2, None, CAPTURED.into(), DocxImportLimits::default()),
            Err(IngestionError::EncryptedDocx)
        );

        let xxe_xml = r#"<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<w:document><w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body></w:document>"#;
        let xxe_bytes = standard_docx(xxe_xml);
        assert_eq!(
            import_docx(
                &xxe_bytes,
                None,
                CAPTURED.into(),
                DocxImportLimits::default()
            ),
            Err(IngestionError::InvalidDocx)
        );

        let empty_xml =
            r#"<w:document><w:body><w:p><w:r><w:t>   </w:t></w:r></w:p></w:body></w:document>"#;
        assert_eq!(
            import_docx(
                &standard_docx(empty_xml),
                None,
                CAPTURED.into(),
                DocxImportLimits::default()
            ),
            Err(IngestionError::DocxHasNoExtractableText)
        );

        let valid_xml = r#"<w:document><w:body><w:p><w:r><w:t>Valid body text</w:t></w:r></w:p></w:body></w:document>"#;
        let valid_bytes = standard_docx(valid_xml);
        assert!(matches!(
            import_docx(
                &valid_bytes,
                None,
                CAPTURED.into(),
                DocxImportLimits {
                    max_archive_entries: 1,
                    ..DocxImportLimits::default()
                }
            ),
            Err(IngestionError::TooManyDocxEntries {
                actual: 2,
                limit: 1
            })
        ));
        assert!(matches!(
            import_docx(
                &valid_bytes,
                None,
                CAPTURED.into(),
                DocxImportLimits {
                    max_total_text_bytes: 5,
                    ..DocxImportLimits::default()
                }
            ),
            Err(IngestionError::DocxTextTooLarge { .. })
        ));
    }
}
