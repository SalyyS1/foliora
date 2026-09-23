use crate::{hex_digest, ExportAuditEvent, ExportError, ReviewedBundle};
use printpdf::{
    Mm, Op, ParsedFont, PdfDocument, PdfFontHandle, PdfPage, PdfSaveOptions, Point, Pt, TextItem,
};

const PAGE_WIDTH_MM: f32 = 210.0;
const PAGE_HEIGHT_MM: f32 = 297.0;
const LEFT_MM: f32 = 18.0;
const TOP_MM: f32 = 278.0;
const BOTTOM_MM: f32 = 18.0;
const BODY_SIZE_PT: f32 = 10.0;
const LINE_HEIGHT_MM: f32 = 5.2;
const MAX_CHARS: usize = 88;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdfLocale {
    Vietnamese,
    English,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdfExport {
    /// The reviewed structure rendered into `bytes` without adding hidden claim data.
    pub preview: ReviewedBundle,
    pub bytes: Vec<u8>,
    pub audit_event: ExportAuditEvent,
}

#[derive(Clone)]
struct DisplayLine {
    text: String,
    size_pt: f32,
    gap_after_mm: f32,
}

/// Renders a reviewed bundle with an application-packaged Unicode font.
///
/// Callers should pass a redistributable font covering every locale they expose
/// (for example Noto Sans). Font bytes are embedded in the PDF; no system font
/// path or source blob is retained in the artifact.
pub fn export_reviewed_pdf(
    reviewed: &ReviewedBundle,
    unicode_font_bytes: &[u8],
    locale: PdfLocale,
) -> Result<PdfExport, ExportError> {
    validate_preview(reviewed)?;
    let mut font_warnings = Vec::new();
    let font = ParsedFont::from_bytes(unicode_font_bytes, 0, &mut font_warnings)
        .ok_or(ExportError::InvalidPdfFont)?;
    let mut document = PdfDocument::new("Foliora reviewed context pack");
    let font_id = document.add_font(&font);
    let pages = paginate(&render_lines(reviewed, locale))
        .into_iter()
        .map(|lines| render_page(lines, PdfFontHandle::External(font_id.clone())))
        .collect();
    let mut pdf_warnings = Vec::new();
    let bytes = document
        .with_pages(pages)
        .save(&PdfSaveOptions::default(), &mut pdf_warnings);
    if bytes.len() < 5 || &bytes[..5] != b"%PDF-" {
        return Err(ExportError::PdfSerialize(
            "renderer did not produce a PDF header".to_owned(),
        ));
    }
    let audit_event = ExportAuditEvent {
        event_type: "bundle.exported.pdf".to_owned(),
        bundle_id: reviewed.id.clone(),
        exported_at: reviewed.exported_at.clone(),
        payload_sha256: format!("sha256:{}", hex_digest(&bytes)),
        claim_ids: reviewed
            .claims
            .iter()
            .map(|claim| claim.id.clone())
            .collect(),
    };
    Ok(PdfExport {
        preview: reviewed.clone(),
        bytes,
        audit_event,
    })
}

fn validate_preview(reviewed: &ReviewedBundle) -> Result<(), ExportError> {
    if reviewed.schema_version != crate::EXPORT_SCHEMA_VERSION
        || reviewed.domain_schema_version != foliora_domain::SCHEMA_VERSION
        || reviewed.id.trim().is_empty()
        || reviewed.purpose.trim().is_empty()
        || reviewed.claims.is_empty()
    {
        return Err(ExportError::InvalidDomain(
            "reviewed PDF input is incomplete or has an unsupported schema".to_owned(),
        ));
    }
    foliora_domain::validate_canonical_timestamp(&reviewed.exported_at, "exported_at")?;
    if let Some(expires_at) = &reviewed.expires_at {
        foliora_domain::validate_canonical_timestamp(expires_at, "expires_at")?;
    }
    Ok(())
}

fn render_lines(reviewed: &ReviewedBundle, locale: PdfLocale) -> Vec<DisplayLine> {
    let (title, caveat, claims_heading, evidence_heading, no_source, exported, expiry) =
        match locale {
            PdfLocale::Vietnamese => (
                "FOLIORA — HỒ SƠ NGỮ CẢNH ĐÃ DUYỆT",
                "LƯU Ý: Hồ sơ này là dữ liệu tham khảo do người dùng duyệt, không phải chỉ dẫn hay tư vấn chuyên môn.",
                "DỮ KIỆN ĐÃ XÁC NHẬN",
                "CHỈ MỤC BẰNG CHỨNG",
                "Người dùng nhập trực tiếp",
                "Xuất lúc",
                "Hết hạn",
            ),
            PdfLocale::English => (
                "FOLIORA — REVIEWED CONTEXT PACK",
                "NOTICE: This pack is user-reviewed reference data, not instructions or professional advice.",
                "CONFIRMED CLAIMS",
                "EVIDENCE INDEX",
                "Entered directly by the user",
                "Exported",
                "Expires",
            ),
        };
    let mut lines = Vec::new();
    push_wrapped(&mut lines, title, 18.0, 4.0);
    push_wrapped(&mut lines, &reviewed.purpose, 13.0, 3.0);
    push_wrapped(&mut lines, caveat, 9.0, 4.0);
    push_wrapped(
        &mut lines,
        &format!("{exported}: {}", reviewed.exported_at),
        BODY_SIZE_PT,
        0.0,
    );
    if let Some(value) = &reviewed.expires_at {
        push_wrapped(&mut lines, &format!("{expiry}: {value}"), BODY_SIZE_PT, 4.0);
    }
    push_wrapped(&mut lines, claims_heading, 13.0, 2.0);
    for (index, claim) in reviewed.claims.iter().enumerate() {
        let value = serde_json::to_string(&claim.value).unwrap_or_else(|_| "null".to_owned());
        push_wrapped(
            &mut lines,
            &format!("{}. {} — {}", index + 1, claim.claim_type, value),
            BODY_SIZE_PT,
            0.0,
        );
        let source = claim
            .provenance
            .source_id
            .as_deref()
            .map(|id| format!("Source: {id}"))
            .unwrap_or_else(|| no_source.to_owned());
        push_wrapped(&mut lines, &source, 8.5, 2.5);
    }
    push_wrapped(&mut lines, evidence_heading, 13.0, 2.0);
    if reviewed.evidence.is_empty() {
        push_wrapped(&mut lines, no_source, BODY_SIZE_PT, 0.0);
    } else {
        for evidence in &reviewed.evidence {
            let title = evidence.title.as_deref().unwrap_or("Untitled source");
            push_wrapped(
                &mut lines,
                &format!(
                    "• {} — {} — {} — {}",
                    evidence.id, title, evidence.media_type, evidence.fingerprint
                ),
                8.5,
                1.5,
            );
        }
    }
    lines
}

fn push_wrapped(output: &mut Vec<DisplayLine>, text: &str, size_pt: f32, final_gap_mm: f32) {
    let wrapped = wrap_text(text, MAX_CHARS);
    let last = wrapped.len().saturating_sub(1);
    for (index, line) in wrapped.into_iter().enumerate() {
        output.push(DisplayLine {
            text: line,
            size_pt,
            gap_after_mm: if index == last { final_gap_mm } else { 0.0 },
        });
    }
}

fn wrap_text(text: &str, max_chars: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        let additional = usize::from(!current.is_empty()) + word.chars().count();
        if !current.is_empty() && current.chars().count() + additional > max_chars {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

fn paginate(lines: &[DisplayLine]) -> Vec<Vec<DisplayLine>> {
    let mut pages = vec![Vec::new()];
    let mut y = TOP_MM;
    for line in lines {
        let height = LINE_HEIGHT_MM + line.gap_after_mm;
        if y - height < BOTTOM_MM && !pages.last().expect("page exists").is_empty() {
            pages.push(Vec::new());
            y = TOP_MM;
        }
        pages.last_mut().expect("page exists").push(line.clone());
        y -= height;
    }
    pages
}

fn render_page(lines: Vec<DisplayLine>, font: PdfFontHandle) -> PdfPage {
    let mut operations = vec![Op::StartTextSection];
    let mut y = TOP_MM;
    for line in lines {
        operations.push(Op::SetTextCursor {
            pos: Point::new(Mm(LEFT_MM), Mm(y)),
        });
        operations.push(Op::SetFont {
            font: font.clone(),
            size: Pt(line.size_pt),
        });
        operations.push(Op::ShowText {
            items: vec![TextItem::Text(line.text)],
        });
        y -= LINE_HEIGHT_MM + line.gap_after_mm;
    }
    operations.push(Op::EndTextSection);
    PdfPage::new(Mm(PAGE_WIDTH_MM), Mm(PAGE_HEIGHT_MM), operations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EvidenceSource, ExportedClaim, ExportedProvenance, EXPORT_SCHEMA_VERSION};
    use foliora_domain::Sensitivity;
    use serde_json::Value;

    fn reviewed() -> ReviewedBundle {
        ReviewedBundle {
            schema_version: EXPORT_SCHEMA_VERSION,
            domain_schema_version: foliora_domain::SCHEMA_VERSION,
            id: "bundle:pdf".into(),
            purpose: "Bàn giao dự án an toàn".into(),
            exported_at: "2026-09-11T00:00:00Z".into(),
            expires_at: None,
            claims: vec![ExportedClaim {
                id: "claim:1".into(),
                claim_type: "project.goal".into(),
                subject: "project:1".into(),
                value: Value::String("Hoàn tất bản phát hành".into()),
                sensitivity: Sensitivity::Internal,
                provenance: ExportedProvenance {
                    source_id: Some("source:1".into()),
                    locator: None,
                    user_entered_at: None,
                },
            }],
            evidence: vec![EvidenceSource {
                id: "source:1".into(),
                fingerprint: format!("sha256:{}", "a".repeat(64)),
                media_type: "text/plain".into(),
                title: Some("Ghi chú dự án".into()),
                captured_at: "2026-09-11T00:00:00Z".into(),
            }],
        }
    }

    #[test]
    fn layout_contains_caveat_claim_and_evidence_without_local_paths() {
        let lines = render_lines(&reviewed(), PdfLocale::Vietnamese);
        let text = lines
            .iter()
            .map(|line| line.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("LƯU Ý"));
        assert!(text.contains("Hoàn tất bản phát hành"));
        assert!(text.contains("source:1"));
        assert!(!text.contains("C:\\"));
        assert!(!text.contains("/home/"));
    }

    #[test]
    fn long_content_paginates_deterministically() {
        let lines = (0..200)
            .map(|index| DisplayLine {
                text: format!("line {index}"),
                size_pt: BODY_SIZE_PT,
                gap_after_mm: 0.0,
            })
            .collect::<Vec<_>>();
        let first = paginate(&lines);
        assert!(first.len() > 1);
        assert_eq!(first.iter().map(Vec::len).sum::<usize>(), 200);
        assert_eq!(
            first.iter().map(Vec::len).collect::<Vec<_>>(),
            paginate(&lines).iter().map(Vec::len).collect::<Vec<_>>()
        );
    }

    #[test]
    fn invalid_or_missing_font_fails_closed() {
        assert_eq!(
            export_reviewed_pdf(&reviewed(), b"not-a-font", PdfLocale::English),
            Err(ExportError::InvalidPdfFont)
        );
    }

    #[test]
    fn installed_unicode_font_produces_audited_pdf_when_available() {
        let candidates = [
            "C:/Windows/Fonts/arial.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        ];
        let Some(font) = candidates.iter().find_map(|path| std::fs::read(path).ok()) else {
            // Packaging supplies the font in production; minimal CI images may not.
            return;
        };
        let output = export_reviewed_pdf(&reviewed(), &font, PdfLocale::Vietnamese).unwrap();
        assert!(output.bytes.starts_with(b"%PDF-"));
        // The renderer subsets fonts, so a valid artifact can be smaller than the source font.
        assert!(output.bytes.len() > 1_000);
        assert_eq!(output.preview, reviewed());
        assert_eq!(
            output.audit_event.payload_sha256,
            format!("sha256:{}", hex_digest(&output.bytes))
        );
        assert_eq!(output.audit_event.claim_ids, vec!["claim:1"]);
    }
}
