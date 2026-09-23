use foliora_domain::templates::{compose, CompositionResult, WorkflowTemplate};
use foliora_domain::{detect_conflicts, Claim, ClaimStatus, ConflictSet, Source};
use foliora_export::{
    export_portable_archive, export_redacted_clipboard, export_reviewed_json, export_reviewed_pdf,
    ArchiveLocale, ClipboardExport, ClipboardLocale, PdfExport, PdfLocale, PortableArchiveExport,
    PortableArchiveManifest,
};
use foliora_ingestion::{
    candidate_from_ocr_region, candidate_from_pdf_page_span, candidate_from_span, import_eml,
    import_image, import_pdf, import_pdf_with_password, import_text, run_tesseract,
    EmlImportLimits, ImageImportLimits, ImageOrientation, ImportedImage, ImportedText, OcrPage,
    PdfImportLimits, SupportedImageFormat, TesseractConfig, TextInputKind, DEFAULT_MAX_EML_BYTES,
    DEFAULT_MAX_IMAGE_BYTES, DEFAULT_MAX_OCR_OUTPUT_BYTES, DEFAULT_MAX_PDF_BYTES,
    DEFAULT_MAX_TEXT_BYTES,
};
use foliora_model::{prepare_request, PreparedRequest};
use foliora_vault::{InsertOutcome, Vault};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Take, Write};
use std::path::Path;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use zeroize::Zeroizing;

const MAX_TEXT_PREVIEW_BYTES: usize = 1024 * 1024;
const MAX_PDF_PAGE_PREVIEW_BYTES: usize = 256 * 1024;
const MAX_HEADER_PREVIEW_BYTES: usize = 4 * 1024;
pub const PACKAGED_TESSERACT_VERSION: &str = "5.5.0";
const OCR_RESOURCE_LOCK: &str = include_str!("../resources/ocr/resource-lock.json");
const OCR_RESOURCE_LOCK_VERSION: u16 = 1;
const MAX_OCR_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_OCR_MODEL_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OcrResourceLock {
    schema_version: u16,
    available: bool,
    engine_version: String,
    executable: OcrLockedArtifact,
    models: OcrLockedModels,
    runtime_dependencies: Vec<OcrLockedArtifact>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OcrLockedModels {
    vie: OcrLockedArtifact,
    eng: OcrLockedArtifact,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OcrLockedArtifact {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceSummary {
    pub id: String,
    pub title: Option<String>,
    pub media_type: String,
    pub captured_at: String,
    pub byte_length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum SourceDetail {
    Text {
        source: Source,
        text: String,
        truncated: bool,
    },
    Pdf {
        source: Source,
        pages: Vec<PdfPagePreview>,
    },
    Email {
        source: Source,
        subject: Option<String>,
        from: Option<String>,
        to: Vec<String>,
        date_header: Option<String>,
        body_source_id: String,
        attachments: Vec<SourceSummary>,
    },
    Image {
        source: Source,
        format: String,
        encoded_width: u32,
        encoded_height: u32,
        display_width: u32,
        display_height: u32,
        orientation: String,
    },
    Unsupported {
        source: Source,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PdfPagePreview {
    pub page: u32,
    pub text: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSnapshot {
    pub sources: Vec<SourceSummary>,
    pub claims: Vec<Claim>,
    pub conflicts: Vec<ConflictSet>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportReceipt {
    pub path: String,
    pub bytes: usize,
    pub payload_sha256: String,
    pub bundle_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonExportPreview {
    pub content: String,
    pub bytes: usize,
    pub payload_sha256: String,
    pub bundle_id: String,
    pub exported_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClipboardExportPreview {
    pub content: String,
    pub bytes: usize,
    pub payload_sha256: String,
    pub bundle_id: String,
    pub exported_at: String,
    pub included_claim_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClipboardReceipt {
    pub bytes: usize,
    pub payload_sha256: String,
    pub bundle_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveExportPreview {
    pub manifest: PortableArchiveManifest,
    pub bytes: usize,
    pub payload_sha256: String,
    pub bundle_id: String,
    pub exported_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PdfExportPreview {
    pub bytes: usize,
    pub payload_sha256: String,
    pub bundle_id: String,
    pub exported_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedPdfExport {
    pub draft: foliora_domain::BundleDraft,
    pub preview: PdfExportPreview,
    pub bytes: Zeroizing<Vec<u8>>,
}

pub fn snapshot(vault: &Vault) -> WorkspaceSnapshot {
    let sources = vault
        .sources()
        .map(|stored| SourceSummary {
            id: stored.source.id.clone(),
            title: stored.source.title.clone(),
            media_type: stored.source.media_type.clone(),
            captured_at: stored.source.captured_at.clone(),
            byte_length: stored.content.len(),
        })
        .collect();
    let claims = vault.claims().cloned().collect::<Vec<_>>();
    let conflicts = detect_conflicts(&claims);
    WorkspaceSnapshot {
        sources,
        claims,
        conflicts,
    }
}

#[cfg(test)]
pub fn source_detail(vault: &Vault, id: &str) -> Result<SourceDetail, String> {
    source_detail_with_password(vault, id, None)
}

pub fn source_detail_with_password(
    vault: &Vault,
    id: &str,
    pdf_password: Option<&str>,
) -> Result<SourceDetail, String> {
    let stored = vault
        .source(id)
        .ok_or_else(|| "source was not found".to_string())?;
    if stored.source.media_type.starts_with("text/") {
        let full = std::str::from_utf8(&stored.content)
            .map_err(|_| "source text is not valid UTF-8".to_string())?;
        let (text, truncated) = preview_text(full, MAX_TEXT_PREVIEW_BYTES);
        return Ok(SourceDetail::Text {
            source: stored.source.clone(),
            text,
            truncated,
        });
    }
    match stored.source.media_type.as_str() {
        "application/pdf" => {
            pdf_detail_with_password(stored.source.clone(), &stored.content, pdf_password)
        }
        "message/rfc822" => email_detail(stored.source.clone(), &stored.content),
        "image/png" | "image/jpeg" => image_detail(stored.source.clone(), &stored.content),
        _ => Ok(SourceDetail::Unsupported {
            source: stored.source.clone(),
        }),
    }
}

#[cfg(test)]
pub fn import_document(vault: &mut Vault, path: &Path) -> Result<Vec<InsertOutcome>, String> {
    import_document_with_password(vault, path, None)
}

pub fn import_document_with_password(
    vault: &mut Vault,
    path: &Path,
    pdf_password: Option<&str>,
) -> Result<Vec<InsertOutcome>, String> {
    if !path.is_absolute() {
        return Err("source path must be absolute".into());
    }
    let extension = extension(path)?;
    let limit = match extension.as_str() {
        "txt" | "md" | "markdown" => DEFAULT_MAX_TEXT_BYTES,
        "pdf" => DEFAULT_MAX_PDF_BYTES,
        "eml" => DEFAULT_MAX_EML_BYTES,
        "png" | "jpg" | "jpeg" => DEFAULT_MAX_IMAGE_BYTES,
        _ => {
            return Err(
                "desktop import supports TXT, Markdown, PDF, EML, PNG, and JPEG files".into(),
            )
        }
    };
    let bytes = read_bounded(File::open(path).map_err(safe_io)?, limit)?;
    let title = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned);
    let captured_at = now_utc()?;
    let sources = match extension.as_str() {
        "txt" | "md" | "markdown" => {
            let imported = import_text(
                &bytes,
                text_kind(&extension),
                title,
                captured_at,
                DEFAULT_MAX_TEXT_BYTES,
            )
            .map_err(|error| error.to_string())?;
            vec![(imported.source, bytes)]
        }
        "pdf" => {
            let imported = import_pdf_with_password(
                &bytes,
                title,
                captured_at,
                pdf_password,
                PdfImportLimits::default(),
            )
            .map_err(|error| error.to_string())?;
            vec![(imported.source, bytes)]
        }
        "eml" => {
            let imported = import_eml(&bytes, title, captured_at, EmlImportLimits::default())
                .map_err(|error| error.to_string())?;
            let mut sources = vec![(imported.source, bytes)];
            sources.push((
                imported.body.imported.source,
                imported.body.imported.text.into_bytes(),
            ));
            sources.extend(
                imported
                    .attachments
                    .into_iter()
                    .map(|attachment| (attachment.source, attachment.bytes)),
            );
            sources
        }
        "png" | "jpg" | "jpeg" => {
            let imported = import_image(&bytes, title, captured_at, ImageImportLimits::default())
                .map_err(|error| error.to_string())?;
            vec![(imported.source, bytes)]
        }
        _ => unreachable!("extension checked above"),
    };
    vault
        .insert_sources_persisted(sources)
        .map_err(|error| error.to_string())
}

pub fn source_image_png(vault: &Vault, id: &str) -> Result<Vec<u8>, String> {
    let stored = vault
        .source(id)
        .ok_or_else(|| "source was not found".to_string())?;
    if !matches!(
        stored.source.media_type.as_str(),
        "image/png" | "image/jpeg"
    ) {
        return Err("source is not a supported image".into());
    }
    Ok(reimport_image(stored.source.clone(), &stored.content)?.ocr_input_png)
}

pub fn packaged_ocr_config(resource_dir: &Path) -> Option<TesseractConfig> {
    packaged_ocr_config_with_lock(resource_dir, OCR_RESOURCE_LOCK)
}

fn packaged_ocr_config_with_lock(resource_dir: &Path, lock_json: &str) -> Option<TesseractConfig> {
    if !resource_dir.is_absolute() {
        return None;
    }
    let lock: OcrResourceLock = serde_json::from_str(lock_json).ok()?;
    if !lock.available
        || lock.schema_version != OCR_RESOURCE_LOCK_VERSION
        || lock.engine_version != PACKAGED_TESSERACT_VERSION
    {
        return None;
    }
    let root = resource_dir.join("ocr");
    let executable_name = if cfg!(windows) {
        "tesseract.exe"
    } else {
        "tesseract"
    };
    let executable = verify_ocr_artifact(
        &root,
        &lock.executable,
        executable_name,
        MAX_OCR_EXECUTABLE_BYTES,
    )?;
    let tessdata_dir = root.join("tessdata");
    verify_ocr_artifact(
        &root,
        &lock.models.vie,
        "tessdata/vie.traineddata",
        MAX_OCR_MODEL_BYTES,
    )?;
    verify_ocr_artifact(
        &root,
        &lock.models.eng,
        "tessdata/eng.traineddata",
        MAX_OCR_MODEL_BYTES,
    )?;
    let mut expected_files = BTreeSet::from([
        executable_name.to_owned(),
        "tessdata/vie.traineddata".to_owned(),
        "tessdata/eng.traineddata".to_owned(),
    ]);
    for dependency in &lock.runtime_dependencies {
        if !is_safe_ocr_relative_path(&dependency.path)
            || !expected_files.insert(dependency.path.clone())
        {
            return None;
        }
        verify_ocr_artifact(
            &root,
            dependency,
            &dependency.path,
            MAX_OCR_EXECUTABLE_BYTES,
        )?;
    }
    if collect_ocr_resource_files(&root)? != expected_files {
        return None;
    }
    Some(TesseractConfig {
        executable,
        tessdata_dir,
        engine_version: PACKAGED_TESSERACT_VERSION.into(),
        languages: vec!["vie".into(), "eng".into()],
        page_segmentation_mode: 6,
        timeout: Duration::from_secs(45),
        max_output_bytes: DEFAULT_MAX_OCR_OUTPUT_BYTES,
    })
}

fn verify_ocr_artifact(
    root: &Path,
    artifact: &OcrLockedArtifact,
    expected_path: &str,
    max_bytes: u64,
) -> Option<std::path::PathBuf> {
    if artifact.path != expected_path
        || !is_safe_ocr_relative_path(expected_path)
        || artifact.bytes == 0
        || artifact.bytes > max_bytes
        || artifact.sha256.len() != 64
        || !artifact
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let canonical_root = root.canonicalize().ok()?;
    let path = root.join(expected_path);
    let canonical_path = path.canonicalize().ok()?;
    if !canonical_path.starts_with(&canonical_root) {
        return None;
    }
    let metadata = canonical_path.metadata().ok()?;
    if !metadata.is_file() || metadata.len() != artifact.bytes {
        return None;
    }
    let mut file = File::open(&canonical_path).ok()?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    if format!("{:x}", digest.finalize()) != artifact.sha256 {
        return None;
    }
    Some(canonical_path)
}

fn is_safe_ocr_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\\')
        && Path::new(path)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn collect_ocr_resource_files(root: &Path) -> Option<BTreeSet<String>> {
    fn visit(root: &Path, directory: &Path, files: &mut BTreeSet<String>) -> Option<()> {
        for entry in fs::read_dir(directory).ok()? {
            let entry = entry.ok()?;
            let file_type = entry.file_type().ok()?;
            if file_type.is_symlink() {
                return None;
            }
            let path = entry.path();
            if file_type.is_dir() {
                visit(root, &path, files)?;
            } else if file_type.is_file() {
                let relative = path.strip_prefix(root).ok()?;
                let normalized = relative.to_string_lossy().replace('\\', "/");
                if !matches!(normalized.as_str(), "README.md" | "resource-lock.json") {
                    files.insert(normalized);
                }
            } else {
                return None;
            }
        }
        Some(())
    }

    let mut files = BTreeSet::new();
    visit(root, root, &mut files)?;
    Some(files)
}

pub fn run_image_ocr(vault: &Vault, id: &str, config: &TesseractConfig) -> Result<OcrPage, String> {
    let stored = vault
        .source(id)
        .ok_or_else(|| "source was not found".to_string())?;
    if !matches!(
        stored.source.media_type.as_str(),
        "image/png" | "image/jpeg"
    ) {
        return Err("OCR requires a PNG or JPEG source".into());
    }
    let imported = reimport_image(stored.source.clone(), &stored.content)?;
    run_tesseract(&imported, config).map_err(|error| error.to_string())
}

pub fn create_ocr_candidate(
    vault: &mut Vault,
    source_id: &str,
    ocr: &OcrPage,
    region_index: usize,
    claim_type: String,
    subject: String,
) -> Result<Claim, String> {
    let claim_type = bounded_identifier(claim_type, "claim type", 128)?;
    let subject = bounded_identifier(subject, "subject", 256)?;
    let stored = vault
        .source(source_id)
        .ok_or_else(|| "source was not found".to_string())?;
    let imported = reimport_image(stored.source.clone(), &stored.content)?;
    let claim = candidate_from_ocr_region(&imported, ocr, region_index, claim_type, subject)
        .map_err(|error| error.to_string())?;
    vault
        .upsert_claim_persisted(claim.clone())
        .map_err(|error| error.to_string())?;
    Ok(claim)
}

pub fn create_candidate(
    vault: &mut Vault,
    source_id: &str,
    claim_type: String,
    subject: String,
    page: Option<u32>,
    start: usize,
    end: usize,
) -> Result<Claim, String> {
    let claim_type = bounded_identifier(claim_type, "claim type", 128)?;
    let subject = bounded_identifier(subject, "subject", 256)?;
    let stored = vault
        .source(source_id)
        .ok_or_else(|| "source was not found".to_string())?;
    let claim = if stored.source.media_type.starts_with("text/") {
        if page.is_some() {
            return Err("text evidence must not specify a page".into());
        }
        let text = std::str::from_utf8(&stored.content)
            .map_err(|_| "source text is not valid UTF-8".to_string())?
            .to_owned();
        candidate_from_span(
            &ImportedText {
                source: stored.source.clone(),
                text,
            },
            claim_type,
            subject,
            start,
            end,
        )
    } else if stored.source.media_type == "application/pdf" {
        let imported = import_pdf(
            &stored.content,
            stored.source.title.clone(),
            stored.source.captured_at.clone(),
            PdfImportLimits::default(),
        )
        .map_err(|error| error.to_string())?;
        candidate_from_pdf_page_span(
            &imported,
            claim_type,
            subject,
            page.ok_or_else(|| "PDF evidence requires a page".to_string())?,
            start,
            end,
        )
    } else {
        return Err("candidates from this source require a supported evidence viewer".into());
    };
    let claim = claim.map_err(|error| error.to_string())?;
    vault
        .upsert_claim_persisted(claim.clone())
        .map_err(|error| error.to_string())?;
    Ok(claim)
}

pub fn prepare_model_request(
    vault: &Vault,
    source_id: &str,
    model: &str,
    redactions: &[String],
) -> Result<PreparedRequest, String> {
    let stored = vault
        .source(source_id)
        .ok_or_else(|| "source was not found".to_string())?;
    if !stored.source.media_type.starts_with("text/") {
        return Err("model assistance only supports UTF-8 text sources".into());
    }
    let text = std::str::from_utf8(&stored.content)
        .map_err(|_| "source text is not valid UTF-8".to_string())?;
    prepare_request(
        &stored.source.id,
        &stored.source.fingerprint,
        text,
        model,
        redactions,
    )
    .map_err(|error| error.to_string())
}

#[allow(clippy::too_many_arguments)]
pub fn create_model_candidate(
    vault: &mut Vault,
    source_id: &str,
    expected_source_fingerprint: &str,
    expected_quote: &str,
    claim_type: String,
    subject: String,
    start: usize,
    end: usize,
) -> Result<Claim, String> {
    if expected_quote.is_empty() || expected_quote.len() > 4096 {
        return Err("model evidence quote must contain 1 to 4096 bytes".into());
    }
    {
        let stored = vault
            .source(source_id)
            .ok_or_else(|| "source was not found".to_string())?;
        if stored.source.fingerprint != expected_source_fingerprint {
            return Err("model suggestion source changed; request new suggestions".into());
        }
        let text = std::str::from_utf8(&stored.content)
            .map_err(|_| "source text is not valid UTF-8".to_string())?;
        if text.get(start..end) != Some(expected_quote) {
            return Err("model suggestion no longer matches its exact source quote".into());
        }
    }
    create_candidate(vault, source_id, claim_type, subject, None, start, end)
}

pub fn transition_claim(vault: &mut Vault, id: &str, status: &str) -> Result<Claim, String> {
    let status = match status {
        "confirmed" => ClaimStatus::Confirmed,
        "rejected" => ClaimStatus::Rejected,
        _ => return Err("desktop review only permits confirmed or rejected status".into()),
    };
    vault
        .transition_claim_persisted(id, status)
        .map_err(|error| error.to_string())
}

pub fn compose_bundle(
    vault: &Vault,
    workflow: &str,
    subject: &str,
) -> Result<CompositionResult, String> {
    let workflow = parse_workflow(workflow)?;
    let subject = bounded_identifier(subject.to_owned(), "subject", 256)?;
    let claims = vault.claims().cloned().collect::<Vec<_>>();
    let id = bundle_id(workflow, &subject, &claims);
    compose(workflow, &id, &subject, &claims, &now_utc()?).map_err(|error| error.to_string())
}

pub fn export_bundle_json(
    vault: &mut Vault,
    workflow: &str,
    subject: &str,
    approved_sensitive_claim_ids: Vec<String>,
    exported_at: &str,
    expected_sha256: &str,
    path: &Path,
) -> Result<ExportReceipt, String> {
    validate_export_path(path, "json")?;
    let (draft, exported) = prepare_json_export(
        vault,
        workflow,
        subject,
        approved_sensitive_claim_ids,
        exported_at,
    )?;
    if exported.audit_event.payload_sha256 != expected_sha256 {
        return Err(
            "vault changed after preview; review the refreshed export before saving".into(),
        );
    }
    write_new_atomic(path, &exported.bytes)?;
    vault
        .insert_bundle_persisted(draft.clone())
        .map_err(|error| error.to_string())?;
    Ok(ExportReceipt {
        path: path.to_string_lossy().into_owned(),
        bytes: exported.bytes.len(),
        payload_sha256: exported.audit_event.payload_sha256,
        bundle_id: draft.id,
    })
}

pub fn preview_bundle_json(
    vault: &Vault,
    workflow: &str,
    subject: &str,
    approved_sensitive_claim_ids: Vec<String>,
) -> Result<JsonExportPreview, String> {
    let exported_at = now_utc()?;
    let (draft, exported) = prepare_json_export(
        vault,
        workflow,
        subject,
        approved_sensitive_claim_ids,
        &exported_at,
    )?;
    let content = String::from_utf8(exported.bytes.clone())
        .map_err(|_| "JSON exporter produced invalid UTF-8".to_string())?;
    Ok(JsonExportPreview {
        content,
        bytes: exported.bytes.len(),
        payload_sha256: exported.audit_event.payload_sha256,
        bundle_id: draft.id,
        exported_at,
    })
}

fn prepare_json_export(
    vault: &Vault,
    workflow: &str,
    subject: &str,
    approved_sensitive_claim_ids: Vec<String>,
    exported_at: &str,
) -> Result<(foliora_domain::BundleDraft, foliora_export::JsonExport), String> {
    let composition = compose_bundle(vault, workflow, subject)?;
    let draft = composition
        .draft
        .ok_or_else(|| "bundle has no confirmed claims to export".to_string())?;
    let approvals = approved_sensitive_claim_ids
        .into_iter()
        .collect::<BTreeSet<_>>();
    if approvals.iter().any(|id| !draft.claim_ids.contains(id)) {
        return Err("sensitive approval references a claim outside this bundle".into());
    }
    let claims = vault.claims().cloned().collect::<Vec<_>>();
    let sources = vault
        .sources()
        .map(|stored| stored.source.clone())
        .collect::<Vec<_>>();
    let exported = export_reviewed_json(&draft, &claims, &sources, &approvals, exported_at)
        .map_err(|error| error.to_string())?;
    Ok((draft, exported))
}

pub fn preview_bundle_clipboard(
    vault: &Vault,
    workflow: &str,
    subject: &str,
    approved_sensitive_claim_ids: Vec<String>,
    excluded_claim_ids: Vec<String>,
    locale: &str,
) -> Result<ClipboardExportPreview, String> {
    let exported_at = now_utc()?;
    let (draft, exported) = prepare_clipboard_export(
        vault,
        workflow,
        subject,
        approved_sensitive_claim_ids,
        excluded_claim_ids,
        locale,
        &exported_at,
    )?;
    Ok(ClipboardExportPreview {
        bytes: exported.text.len(),
        content: exported.text,
        payload_sha256: exported.audit_event.payload_sha256,
        bundle_id: draft.id,
        exported_at,
        included_claim_ids: exported.audit_event.claim_ids,
    })
}

pub fn prepare_clipboard_export(
    vault: &Vault,
    workflow: &str,
    subject: &str,
    approved_sensitive_claim_ids: Vec<String>,
    excluded_claim_ids: Vec<String>,
    locale: &str,
    exported_at: &str,
) -> Result<(foliora_domain::BundleDraft, ClipboardExport), String> {
    let (draft, exported) = prepare_json_export(
        vault,
        workflow,
        subject,
        approved_sensitive_claim_ids,
        exported_at,
    )?;
    let locale = match locale {
        "vi" => ClipboardLocale::Vietnamese,
        "en" => ClipboardLocale::English,
        _ => return Err("clipboard locale must be vi or en".into()),
    };
    let excluded = excluded_claim_ids.into_iter().collect::<BTreeSet<_>>();
    let clipboard = export_redacted_clipboard(&exported.preview, &excluded, locale)
        .map_err(|error| error.to_string())?;
    Ok((draft, clipboard))
}

pub fn preview_bundle_archive(
    vault: &Vault,
    workflow: &str,
    subject: &str,
    approved_sensitive_claim_ids: Vec<String>,
    locale: &str,
) -> Result<ArchiveExportPreview, String> {
    let exported_at = now_utc()?;
    let (draft, exported) = prepare_archive_export(
        vault,
        workflow,
        subject,
        approved_sensitive_claim_ids,
        locale,
        &exported_at,
    )?;
    Ok(ArchiveExportPreview {
        manifest: exported.manifest,
        bytes: exported.bytes.len(),
        payload_sha256: exported.audit_event.payload_sha256,
        bundle_id: draft.id,
        exported_at,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn export_bundle_archive(
    vault: &mut Vault,
    workflow: &str,
    subject: &str,
    approved_sensitive_claim_ids: Vec<String>,
    locale: &str,
    exported_at: &str,
    expected_sha256: &str,
    path: &Path,
) -> Result<ExportReceipt, String> {
    validate_export_path(path, "foliora-pack")?;
    let (draft, exported) = prepare_archive_export(
        vault,
        workflow,
        subject,
        approved_sensitive_claim_ids,
        locale,
        exported_at,
    )?;
    if exported.audit_event.payload_sha256 != expected_sha256 {
        return Err("vault changed after archive preview; review it again before saving".into());
    }
    write_new_atomic(path, &exported.bytes)?;
    vault
        .insert_bundle_persisted(draft.clone())
        .map_err(|error| error.to_string())?;
    Ok(ExportReceipt {
        path: path.to_string_lossy().into_owned(),
        bytes: exported.bytes.len(),
        payload_sha256: exported.audit_event.payload_sha256,
        bundle_id: draft.id,
    })
}

fn prepare_archive_export(
    vault: &Vault,
    workflow: &str,
    subject: &str,
    approved_sensitive_claim_ids: Vec<String>,
    locale: &str,
    exported_at: &str,
) -> Result<(foliora_domain::BundleDraft, PortableArchiveExport), String> {
    let (draft, json) = prepare_json_export(
        vault,
        workflow,
        subject,
        approved_sensitive_claim_ids,
        exported_at,
    )?;
    let locale = match locale {
        "vi" => ArchiveLocale::Vietnamese,
        "en" => ArchiveLocale::English,
        _ => return Err("archive locale must be vi or en".into()),
    };
    let archive = export_portable_archive(&json.preview, &json.bytes, locale)
        .map_err(|error| error.to_string())?;
    Ok((draft, archive))
}

pub fn prepare_bundle_pdf(
    vault: &Vault,
    workflow: &str,
    subject: &str,
    approved_sensitive_claim_ids: Vec<String>,
    locale: &str,
) -> Result<PreparedPdfExport, String> {
    let exported_at = now_utc()?;
    let (draft, exported) = prepare_pdf_export(
        vault,
        workflow,
        subject,
        approved_sensitive_claim_ids,
        locale,
        &exported_at,
    )?;
    let preview = PdfExportPreview {
        bytes: exported.bytes.len(),
        payload_sha256: exported.audit_event.payload_sha256.clone(),
        bundle_id: draft.id.clone(),
        exported_at,
    };
    Ok(PreparedPdfExport {
        draft,
        preview,
        bytes: Zeroizing::new(exported.bytes),
    })
}

pub fn write_prepared_pdf(
    vault: &mut Vault,
    prepared: &PreparedPdfExport,
    expected_sha256: &str,
    path: &Path,
) -> Result<ExportReceipt, String> {
    validate_export_path(path, "pdf")?;
    if prepared.preview.payload_sha256 != expected_sha256 {
        return Err("vault changed after PDF preview; review it again before saving".into());
    }
    write_new_atomic(path, &prepared.bytes)?;
    vault
        .insert_bundle_persisted(prepared.draft.clone())
        .map_err(|error| error.to_string())?;
    Ok(ExportReceipt {
        path: path.to_string_lossy().into_owned(),
        bytes: prepared.bytes.len(),
        payload_sha256: prepared.preview.payload_sha256.clone(),
        bundle_id: prepared.draft.id.clone(),
    })
}

fn prepare_pdf_export(
    vault: &Vault,
    workflow: &str,
    subject: &str,
    approved_sensitive_claim_ids: Vec<String>,
    locale: &str,
    exported_at: &str,
) -> Result<(foliora_domain::BundleDraft, PdfExport), String> {
    let (draft, json) = prepare_json_export(
        vault,
        workflow,
        subject,
        approved_sensitive_claim_ids,
        exported_at,
    )?;
    let locale = match locale {
        "vi" => PdfLocale::Vietnamese,
        "en" => PdfLocale::English,
        _ => return Err("PDF locale must be vi or en".into()),
    };
    let pdf = export_reviewed_pdf(&json.preview, ttf_noto_sans::REGULAR, locale)
        .map_err(|error| error.to_string())?;
    Ok((draft, pdf))
}

fn extension(path: &Path) -> Result<String, String> {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| "source file must have a supported extension".into())
}

fn parse_workflow(value: &str) -> Result<WorkflowTemplate, String> {
    match value {
        "warranty_insurance" => Ok(WorkflowTemplate::WarrantyInsurance),
        "medical_visit" => Ok(WorkflowTemplate::MedicalVisit),
        "project_handoff" => Ok(WorkflowTemplate::ProjectHandoff),
        _ => Err("unknown workflow template".into()),
    }
}

fn bundle_id(workflow: WorkflowTemplate, subject: &str, claims: &[Claim]) -> String {
    let mut digest = Sha256::new();
    digest.update(format!("{workflow:?}\0{subject}").as_bytes());
    for claim in claims {
        digest.update(b"\0");
        digest.update(claim.id.as_bytes());
        digest.update(b"\0");
        digest.update(claim.revision.to_be_bytes());
    }
    format!("bundle:{:x}", digest.finalize())
}

fn validate_export_path(path: &Path, extension: &str) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("export path must be absolute".into());
    }
    if path.extension().and_then(|value| value.to_str()) != Some(extension) {
        return Err(format!("export path must use the .{extension} extension"));
    }
    if path.exists() {
        return Err("export destination already exists".into());
    }
    Ok(())
}

fn write_new_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "export path has no valid file name".to_string())?;
    let temp = path.with_file_name(format!(".{file_name}.foliora-{}.tmp", std::process::id()));
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(safe_export_io)?;
        file.write_all(bytes).map_err(safe_export_io)?;
        file.sync_all().map_err(safe_export_io)?;
        fs::rename(&temp, path).map_err(safe_export_io)
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    write_result
}

fn safe_export_io(error: std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::AlreadyExists => "export destination already exists".into(),
        std::io::ErrorKind::NotFound => "export folder was not found".into(),
        std::io::ErrorKind::PermissionDenied => "export destination permission was denied".into(),
        _ => "export artifact could not be written".into(),
    }
}

fn text_kind(extension: &str) -> TextInputKind {
    match extension {
        "txt" => TextInputKind::PlainText,
        "md" | "markdown" => TextInputKind::Markdown,
        _ => unreachable!("text extension checked by caller"),
    }
}

fn pdf_detail_with_password(
    source: Source,
    bytes: &[u8],
    pdf_password: Option<&str>,
) -> Result<SourceDetail, String> {
    let imported = import_pdf_with_password(
        bytes,
        source.title.clone(),
        source.captured_at.clone(),
        pdf_password,
        PdfImportLimits::default(),
    )
    .map_err(|error| error.to_string())?;
    let pages = imported
        .pages
        .into_iter()
        .map(|page| {
            let (text, truncated) = preview_text(&page.text, MAX_PDF_PAGE_PREVIEW_BYTES);
            PdfPagePreview {
                page: page.page,
                text,
                truncated,
            }
        })
        .collect();
    Ok(SourceDetail::Pdf { source, pages })
}

fn email_detail(source: Source, bytes: &[u8]) -> Result<SourceDetail, String> {
    let imported = import_eml(
        bytes,
        source.title.clone(),
        source.captured_at.clone(),
        EmlImportLimits::default(),
    )
    .map_err(|error| error.to_string())?;
    let attachments = imported
        .attachments
        .into_iter()
        .map(|attachment| source_summary(&attachment.source, attachment.bytes.len()))
        .collect();
    Ok(SourceDetail::Email {
        source,
        subject: imported
            .subject
            .map(|value| preview_text(&value, MAX_HEADER_PREVIEW_BYTES).0),
        from: imported
            .from
            .map(|value| preview_text(&value, MAX_HEADER_PREVIEW_BYTES).0),
        to: imported
            .to
            .into_iter()
            .take(100)
            .map(|value| preview_text(&value, MAX_HEADER_PREVIEW_BYTES).0)
            .collect(),
        date_header: imported
            .date_header
            .map(|value| preview_text(&value, MAX_HEADER_PREVIEW_BYTES).0),
        body_source_id: imported.body.imported.source.id,
        attachments,
    })
}

fn image_detail(source: Source, bytes: &[u8]) -> Result<SourceDetail, String> {
    let imported = reimport_image(source.clone(), bytes)?;
    Ok(SourceDetail::Image {
        source,
        format: match imported.format {
            SupportedImageFormat::Png => "png",
            SupportedImageFormat::Jpeg => "jpeg",
        }
        .into(),
        encoded_width: imported.encoded_width,
        encoded_height: imported.encoded_height,
        display_width: imported.display_width,
        display_height: imported.display_height,
        orientation: orientation_name(imported.orientation).into(),
    })
}

fn reimport_image(source: Source, bytes: &[u8]) -> Result<ImportedImage, String> {
    import_image(
        bytes,
        source.title,
        source.captured_at,
        ImageImportLimits::default(),
    )
    .map_err(|error| error.to_string())
}

fn orientation_name(orientation: ImageOrientation) -> &'static str {
    match orientation {
        ImageOrientation::Normal => "normal",
        ImageOrientation::Rotate90 => "rotate90",
        ImageOrientation::Rotate180 => "rotate180",
        ImageOrientation::Rotate270 => "rotate270",
        ImageOrientation::FlipHorizontal => "flipHorizontal",
        ImageOrientation::FlipVertical => "flipVertical",
        ImageOrientation::Rotate90FlipHorizontal => "rotate90FlipHorizontal",
        ImageOrientation::Rotate270FlipHorizontal => "rotate270FlipHorizontal",
    }
}

fn source_summary(source: &Source, byte_length: usize) -> SourceSummary {
    SourceSummary {
        id: source.id.clone(),
        title: source.title.clone(),
        media_type: source.media_type.clone(),
        captured_at: source.captured_at.clone(),
        byte_length,
    }
}

fn preview_text(full: &str, max_bytes: usize) -> (String, bool) {
    if full.len() <= max_bytes {
        return (full.to_owned(), false);
    }
    let boundary = full
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= max_bytes)
        .last()
        .unwrap_or(0);
    (full[..boundary].to_owned(), true)
}

fn bounded_identifier(value: String, field: &str, max_bytes: usize) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() || value.len() > max_bytes {
        return Err(format!("{field} must contain 1 to {max_bytes} bytes"));
    }
    if !value
        .chars()
        .all(|character| character.is_alphanumeric() || ".:_-/".contains(character))
    {
        return Err(format!("{field} contains unsupported characters"));
    }
    Ok(value.to_owned())
}

fn read_bounded(file: File, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut reader: Take<File> = file.take((limit as u64) + 1);
    reader.read_to_end(&mut bytes).map_err(safe_io)?;
    if bytes.len() > limit {
        return Err(format!(
            "source exceeds the configured {limit}-byte import limit"
        ));
    }
    Ok(bytes)
}

fn now_utc() -> Result<String, String> {
    OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .map_err(|_| "system clock is outside the supported range".to_string())?
        .format(&Rfc3339)
        .map_err(|_| "could not format system time".to_string())
}

fn safe_io(error: std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::NotFound => "source file was not found".into(),
        std::io::ErrorKind::PermissionDenied => "source file permission was denied".into(),
        _ => "source file could not be read".into(),
    }
}

#[cfg(test)]
#[path = "workspace_tests.rs"]
mod tests;
