use crate::{hex_digest, ImportedText, IngestionError};
use foliora_domain::Source;
use mailparse::{DispositionType, MailHeaderMap, ParsedMail};

pub const DEFAULT_MAX_EML_BYTES: usize = 25 * 1024 * 1024;
pub const DEFAULT_MAX_EML_PARTS: usize = 256;
pub const DEFAULT_MAX_EML_ATTACHMENT_BYTES: usize = 20 * 1024 * 1024;
pub const DEFAULT_MAX_EML_DECODED_BYTES: usize = 50 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmlImportLimits {
    pub max_file_bytes: usize,
    pub max_parts: usize,
    pub max_part_bytes: usize,
    pub max_total_decoded_bytes: usize,
}

impl Default for EmlImportLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_EML_BYTES,
            max_parts: DEFAULT_MAX_EML_PARTS,
            max_part_bytes: DEFAULT_MAX_EML_ATTACHMENT_BYTES,
            max_total_decoded_bytes: DEFAULT_MAX_EML_DECODED_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailBodyKind {
    PlainText,
    HtmlConvertedToText,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailBody {
    pub part_path: String,
    pub kind: EmailBodyKind,
    /// A derived, independently fingerprinted source for exact span citations.
    pub imported: ImportedText,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailAttachment {
    pub part_path: String,
    pub filename: Option<String>,
    pub source: Source,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedEmail {
    /// The immutable raw RFC 5322 container.
    pub source: Source,
    pub subject: Option<String>,
    pub from: Option<String>,
    pub to: Vec<String>,
    pub date_header: Option<String>,
    pub body: EmailBody,
    pub attachments: Vec<EmailAttachment>,
}

pub fn import_eml(
    bytes: &[u8],
    title: Option<String>,
    captured_at: String,
    limits: EmlImportLimits,
) -> Result<ImportedEmail, IngestionError> {
    validate_limits(limits)?;
    if bytes.is_empty() {
        return Err(IngestionError::Empty);
    }
    if bytes.len() > limits.max_file_bytes {
        return Err(IngestionError::TooLarge {
            actual: bytes.len(),
            limit: limits.max_file_bytes,
        });
    }
    let parsed = mailparse::parse_mail(bytes).map_err(|_| IngestionError::InvalidEmail)?;
    // A body-only byte string is technically parseable; require at least one mail header.
    let has_standard_header = [
        "From",
        "To",
        "Subject",
        "Date",
        "Message-ID",
        "MIME-Version",
        "Content-Type",
    ]
    .iter()
    .any(|name| parsed.headers.get_first_header(name).is_some());
    if !has_standard_header {
        return Err(IngestionError::InvalidEmail);
    }
    let part_count = parsed.parts().count();
    if part_count > limits.max_parts {
        return Err(IngestionError::TooManyEmailParts {
            actual: part_count,
            limit: limits.max_parts,
        });
    }

    let fingerprint = format!("sha256:{}", hex_digest(bytes));
    let mut source = Source::new(
        format!("source:{}", &fingerprint[7..]),
        fingerprint,
        "message/rfc822".to_owned(),
        captured_at.clone(),
    )?;
    source.title = title.filter(|value| !value.trim().is_empty());
    source.validate()?;

    let mut decoded_total = 0usize;
    let mut plain_body = None;
    let mut html_body = None;
    let mut attachments = Vec::new();
    collect_parts(
        &parsed,
        "1",
        &source.id,
        &captured_at,
        limits,
        &mut decoded_total,
        &mut plain_body,
        &mut html_body,
        &mut attachments,
    )?;
    let body = plain_body
        .or(html_body)
        .ok_or(IngestionError::EmailHasNoReadableBody)?;

    Ok(ImportedEmail {
        source,
        subject: parsed.headers.get_first_value("Subject"),
        from: parsed.headers.get_first_value("From"),
        to: parsed.headers.get_all_values("To"),
        date_header: parsed.headers.get_first_value("Date"),
        body,
        attachments,
    })
}

#[allow(clippy::too_many_arguments)]
fn collect_parts(
    part: &ParsedMail<'_>,
    path: &str,
    container_id: &str,
    captured_at: &str,
    limits: EmlImportLimits,
    decoded_total: &mut usize,
    plain_body: &mut Option<EmailBody>,
    html_body: &mut Option<EmailBody>,
    attachments: &mut Vec<EmailAttachment>,
) -> Result<(), IngestionError> {
    if !part.subparts.is_empty() {
        for (index, child) in part.subparts.iter().enumerate() {
            collect_parts(
                child,
                &format!("{path}.{}", index + 1),
                container_id,
                captured_at,
                limits,
                decoded_total,
                plain_body,
                html_body,
                attachments,
            )?;
        }
        return Ok(());
    }

    let disposition = part.get_content_disposition();
    let filename = disposition
        .params
        .get("filename")
        .cloned()
        .or_else(|| part.ctype.params.get("name").cloned())
        .filter(|value| !value.trim().is_empty());
    let is_attachment = disposition.disposition == DispositionType::Attachment
        || filename.is_some()
        || !matches!(part.ctype.mimetype.as_str(), "text/plain" | "text/html");
    let decoded = part
        .get_body_raw()
        .map_err(|_| IngestionError::InvalidEmail)?;
    account_decoded(path, decoded.len(), limits, decoded_total)?;

    if is_attachment {
        attachments.push(attachment_from_part(
            decoded,
            path,
            filename,
            &part.ctype.mimetype,
            container_id,
            captured_at,
        )?);
        return Ok(());
    }
    if part.ctype.mimetype == "text/plain" && plain_body.is_none() {
        let text = part.get_body().map_err(|_| IngestionError::InvalidEmail)?;
        account_rendered_growth(path, decoded.len(), text.len(), limits, decoded_total)?;
        if !text.trim().is_empty() {
            *plain_body = Some(body_from_text(
                text,
                path,
                EmailBodyKind::PlainText,
                container_id,
                captured_at,
            )?);
        }
    } else if part.ctype.mimetype == "text/html" && html_body.is_none() {
        let text = html2text::from_read(decoded.as_slice(), 100)
            .map_err(|_| IngestionError::InvalidEmail)?;
        account_rendered_growth(path, decoded.len(), text.len(), limits, decoded_total)?;
        if !text.trim().is_empty() {
            *html_body = Some(body_from_text(
                text,
                path,
                EmailBodyKind::HtmlConvertedToText,
                container_id,
                captured_at,
            )?);
        }
    }
    Ok(())
}

fn account_rendered_growth(
    path: &str,
    decoded_size: usize,
    rendered_size: usize,
    limits: EmlImportLimits,
    total: &mut usize,
) -> Result<(), IngestionError> {
    if rendered_size > limits.max_part_bytes {
        return Err(IngestionError::EmailPartTooLarge {
            part: path.to_owned(),
            actual: rendered_size,
            limit: limits.max_part_bytes,
        });
    }
    account_decoded(
        path,
        rendered_size.saturating_sub(decoded_size),
        limits,
        total,
    )
}

fn account_decoded(
    path: &str,
    size: usize,
    limits: EmlImportLimits,
    total: &mut usize,
) -> Result<(), IngestionError> {
    if size > limits.max_part_bytes {
        return Err(IngestionError::EmailPartTooLarge {
            part: path.to_owned(),
            actual: size,
            limit: limits.max_part_bytes,
        });
    }
    *total = total
        .checked_add(size)
        .ok_or(IngestionError::EmailDecodedTooLarge {
            actual: usize::MAX,
            limit: limits.max_total_decoded_bytes,
        })?;
    if *total > limits.max_total_decoded_bytes {
        return Err(IngestionError::EmailDecodedTooLarge {
            actual: *total,
            limit: limits.max_total_decoded_bytes,
        });
    }
    Ok(())
}

fn body_from_text(
    text: String,
    path: &str,
    kind: EmailBodyKind,
    container_id: &str,
    captured_at: &str,
) -> Result<EmailBody, IngestionError> {
    let bytes = text.as_bytes();
    let fingerprint = format!("sha256:{}", hex_digest(bytes));
    let mut source = Source::new(
        derived_source_id(container_id, path, "body"),
        fingerprint,
        "text/plain; charset=utf-8".to_owned(),
        captured_at.to_owned(),
    )?;
    source.title = Some(format!("Email body {path} from {container_id}"));
    source.validate()?;
    Ok(EmailBody {
        part_path: path.to_owned(),
        kind,
        imported: ImportedText { source, text },
    })
}

fn attachment_from_part(
    bytes: Vec<u8>,
    path: &str,
    filename: Option<String>,
    media_type: &str,
    container_id: &str,
    captured_at: &str,
) -> Result<EmailAttachment, IngestionError> {
    let fingerprint = format!("sha256:{}", hex_digest(&bytes));
    let mut source = Source::new(
        derived_source_id(container_id, path, "attachment"),
        fingerprint,
        media_type.to_owned(),
        captured_at.to_owned(),
    )?;
    source.title = filename
        .clone()
        .or_else(|| Some(format!("Email attachment {path} from {container_id}")));
    source.validate()?;
    Ok(EmailAttachment {
        part_path: path.to_owned(),
        filename,
        source,
        bytes,
    })
}

fn derived_source_id(container_id: &str, path: &str, role: &str) -> String {
    let identity = format!("{container_id}\0{path}\0{role}");
    format!("source:{}", hex_digest(identity.as_bytes()))
}

fn validate_limits(limits: EmlImportLimits) -> Result<(), IngestionError> {
    if limits.max_file_bytes == 0
        || limits.max_parts == 0
        || limits.max_part_bytes == 0
        || limits.max_total_decoded_bytes == 0
    {
        return Err(IngestionError::InvalidEmail);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate_from_span;
    use foliora_domain::{Provenance, SourceLocator};

    const CAPTURED: &str = "2026-09-11T00:00:00Z";

    fn multipart() -> Vec<u8> {
        concat!(
            "From: Alice <alice@example.test>\r\n",
            "To: Bob <bob@example.test>\r\n",
            "Subject: =?UTF-8?Q?B=E1=BA=A3o_h=C3=A0nh?=\r\n",
            "Date: Fri, 11 Sep 2026 10:00:00 +0700\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=outer\r\n\r\n",
            "--outer\r\n",
            "Content-Type: multipart/alternative; boundary=alt\r\n\r\n",
            "--alt\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n",
            "Warranty code ABC-123\r\n",
            "--alt\r\nContent-Type: text/html; charset=utf-8\r\n\r\n",
            "<p>Warranty code <b>HTML-999</b></p>\r\n",
            "--alt--\r\n",
            "--outer\r\n",
            "Content-Type: application/pdf; name=receipt.pdf\r\n",
            "Content-Disposition: attachment; filename=receipt.pdf\r\n",
            "Content-Transfer-Encoding: base64\r\n\r\n",
            "JVBERi0xLjQKc3ludGhldGlj\r\n",
            "--outer--\r\n"
        )
        .as_bytes()
        .to_vec()
    }

    #[test]
    fn imports_headers_plain_body_and_attachment_without_executing_html() {
        let email = import_eml(
            &multipart(),
            Some("message.eml".into()),
            CAPTURED.into(),
            EmlImportLimits::default(),
        )
        .unwrap();
        assert_eq!(email.source.media_type, "message/rfc822");
        assert_eq!(email.subject.as_deref(), Some("Bảo hành"));
        assert_eq!(email.body.kind, EmailBodyKind::PlainText);
        assert!(email.body.imported.text.contains("ABC-123"));
        assert!(!email.body.imported.text.contains("HTML-999"));
        assert_eq!(email.attachments.len(), 1);
        assert_eq!(
            email.attachments[0].filename.as_deref(),
            Some("receipt.pdf")
        );
        assert!(email.attachments[0].bytes.starts_with(b"%PDF-"));

        let start = email.body.imported.text.find("ABC-123").unwrap();
        let claim = candidate_from_span(
            &email.body.imported,
            "warranty.code".into(),
            "device:1".into(),
            start,
            start + 7,
        )
        .unwrap();
        assert!(matches!(
            claim.provenance,
            Provenance::Source(foliora_domain::SourceProvenance {
                locator: SourceLocator::Span { .. },
                ..
            })
        ));
    }

    #[test]
    fn html_only_mail_is_converted_to_inert_text() {
        let raw = b"Subject: HTML\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<script>alert('x')</script><p>Hello <b>world</b></p>";
        let email = import_eml(raw, None, CAPTURED.into(), EmlImportLimits::default()).unwrap();
        assert_eq!(email.body.kind, EmailBodyKind::HtmlConvertedToText);
        assert!(email.body.imported.text.contains("Hello"));
        assert!(email.body.imported.text.contains("world"));
        assert!(!email.body.imported.text.contains("<script>"));
        assert!(!email.body.imported.text.contains("alert('x')"));
    }

    #[test]
    fn malformed_and_decoded_over_limit_mail_fail_closed() {
        assert_eq!(
            import_eml(
                b"not mail",
                None,
                CAPTURED.into(),
                EmlImportLimits::default()
            ),
            Err(IngestionError::InvalidEmail)
        );
        let limits = EmlImportLimits {
            max_part_bytes: 2,
            ..EmlImportLimits::default()
        };
        assert!(matches!(
            import_eml(&multipart(), None, CAPTURED.into(), limits),
            Err(IngestionError::EmailPartTooLarge { .. })
        ));
    }

    #[test]
    fn identical_attachments_keep_distinct_part_identities() {
        let bytes = concat!(
            "From: alice@example.test\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=x\r\n\r\n",
            "--x\r\nContent-Type: text/plain\r\n\r\nBody\r\n",
            "--x\r\nContent-Type: application/octet-stream; name=a.bin\r\n\r\nsame\r\n",
            "--x\r\nContent-Type: application/octet-stream; name=b.bin\r\n\r\nsame\r\n",
            "--x--\r\n"
        );
        let email = import_eml(
            bytes.as_bytes(),
            None,
            CAPTURED.into(),
            EmlImportLimits::default(),
        )
        .unwrap();
        assert_eq!(email.attachments.len(), 2);
        assert_eq!(
            email.attachments[0].source.fingerprint,
            email.attachments[1].source.fingerprint
        );
        assert_ne!(
            email.attachments[0].source.id,
            email.attachments[1].source.id
        );
    }
}
