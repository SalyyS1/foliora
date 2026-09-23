use super::*;
use foliora_ingestion::OcrRegion;
use foliora_vault::KdfPolicy;
use image::{codecs::png::PngEncoder, ExtendedColorType, ImageEncoder};
use lopdf::content::{Content, Operation};
use lopdf::encryption::{EncryptionState, EncryptionVersion, Permissions};
use lopdf::{dictionary, Document, Object, Stream};
use std::fs;

fn fast_vault(path: &Path) -> Vault {
    Vault::create_with_policy(
        path,
        "passphrase",
        KdfPolicy {
            memory_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
        },
    )
    .unwrap()
}

#[test]
fn import_candidate_review_round_trip_is_persisted() {
    let root = std::env::temp_dir();
    let token = std::process::id();
    let vault_path = root.join(format!("foliora-workspace-{token}.vault"));
    let source_path = root.join(format!("foliora-workspace-{token}.txt"));
    let _ = fs::remove_file(&vault_path);
    let _ = fs::remove_file(&source_path);
    fs::write(&source_path, "Mã bảo hành: VN-123").unwrap();
    let mut vault = fast_vault(&vault_path);
    assert_eq!(
        import_document(&mut vault, &source_path).unwrap(),
        vec![InsertOutcome::Inserted]
    );
    let source_id = vault.sources().next().unwrap().source.id.clone();
    let start = "Mã bảo hành: ".len();
    let claim = create_candidate(
        &mut vault,
        &source_id,
        "warranty.code".into(),
        "item:1".into(),
        None,
        start,
        start + "VN-123".len(),
    )
    .unwrap();
    transition_claim(&mut vault, &claim.id, "confirmed").unwrap();
    drop(vault);

    let reopened = Vault::open(&vault_path, "passphrase").unwrap();
    assert_eq!(reopened.source_count(), 1);
    assert!(matches!(
        reopened.claim(&claim.id).map(|claim| claim.status),
        Some(ClaimStatus::Confirmed)
    ));
    let _ = fs::remove_file(vault_path);
    let _ = fs::remove_file(source_path);
}

#[test]
fn unsupported_source_fails_before_vault_mutation() {
    let root = std::env::temp_dir();
    let token = std::process::id();
    let vault_path = root.join(format!("foliora-bounds-{token}.vault"));
    let bad_path = root.join(format!("foliora-bounds-{token}.html"));
    let _ = fs::remove_file(&vault_path);
    fs::write(&bad_path, "<script>not executed</script>").unwrap();
    let mut vault = fast_vault(&vault_path);
    assert!(import_document(&mut vault, &bad_path).is_err());
    assert_eq!(vault.source_count(), 0);
    let _ = fs::remove_file(vault_path);
    let _ = fs::remove_file(bad_path);
}

#[test]
fn model_preview_uses_encrypted_text_source_and_never_mutates_the_vault() {
    let root = std::env::temp_dir();
    let token = std::process::id();
    let vault_path = root.join(format!("foliora-model-preview-{token}.vault"));
    let source_path = root.join(format!("foliora-model-preview-{token}.txt"));
    let _ = fs::remove_file(&vault_path);
    let _ = fs::remove_file(&source_path);
    fs::write(&source_path, "Account 1234, delivery 12/09/2026").unwrap();
    let mut vault = fast_vault(&vault_path);
    import_document(&mut vault, &source_path).unwrap();
    let source = vault.sources().next().unwrap().source.clone();

    let prepared =
        prepare_model_request(&vault, &source.id, "test-model", &["1234".to_owned()]).unwrap();
    assert_eq!(prepared.preview.source_fingerprint, source.fingerprint);
    assert!(prepared.preview.payload.contains("[REDACTED]"));
    assert!(!prepared.preview.payload.contains("1234"));
    assert_eq!(vault.claims().count(), 0);

    let _ = fs::remove_file(vault_path);
    let _ = fs::remove_file(source_path);
}

#[test]
fn model_candidate_revalidates_fingerprint_and_exact_quote() {
    let root = std::env::temp_dir();
    let token = std::process::id();
    let vault_path = root.join(format!("foliora-model-candidate-{token}.vault"));
    let source_path = root.join(format!("foliora-model-candidate-{token}.txt"));
    let _ = fs::remove_file(&vault_path);
    let _ = fs::remove_file(&source_path);
    fs::write(&source_path, "Delivery 12/09/2026").unwrap();
    let mut vault = fast_vault(&vault_path);
    import_document(&mut vault, &source_path).unwrap();
    let source = vault.sources().next().unwrap().source.clone();
    let start = "Delivery ".len();

    assert!(create_model_candidate(
        &mut vault,
        &source.id,
        "sha256:wrong",
        "12/09/2026",
        "delivery.date".into(),
        "order:1".into(),
        start,
        start + "12/09/2026".len(),
    )
    .is_err());
    assert!(create_model_candidate(
        &mut vault,
        &source.id,
        &source.fingerprint,
        "wrong quote",
        "delivery.date".into(),
        "order:1".into(),
        start,
        start + "12/09/2026".len(),
    )
    .is_err());
    let claim = create_model_candidate(
        &mut vault,
        &source.id,
        &source.fingerprint,
        "12/09/2026",
        "delivery.date".into(),
        "order:1".into(),
        start,
        start + "12/09/2026".len(),
    )
    .unwrap();
    assert_eq!(claim.status, ClaimStatus::Candidate);

    let _ = fs::remove_file(vault_path);
    let _ = fs::remove_file(source_path);
}

#[test]
fn pdf_page_selection_creates_page_span_candidate() {
    let root = std::env::temp_dir();
    let token = std::process::id();
    let vault_path = root.join(format!("foliora-pdf-{token}.vault"));
    let source_path = root.join(format!("foliora-pdf-{token}.pdf"));
    let _ = fs::remove_file(&vault_path);
    fs::write(&source_path, sample_pdf("Warranty VN-456")).unwrap();
    let mut vault = fast_vault(&vault_path);
    import_document(&mut vault, &source_path).unwrap();
    let source_id = vault.sources().next().unwrap().source.id.clone();
    let detail = source_detail(&vault, &source_id).unwrap();
    let SourceDetail::Pdf { pages, .. } = detail else {
        panic!("expected PDF preview");
    };
    let page = &pages[0];
    let start = page.text.find("VN-456").unwrap();
    let claim = create_candidate(
        &mut vault,
        &source_id,
        "warranty.code".into(),
        "item:1".into(),
        Some(page.page),
        start,
        start + "VN-456".len(),
    )
    .unwrap();
    assert!(matches!(
        claim.provenance,
        foliora_domain::Provenance::Source(foliora_domain::SourceProvenance {
            locator: foliora_domain::SourceLocator::PageSpan { page: 1, .. },
            ..
        })
    ));
    let _ = fs::remove_file(vault_path);
    let _ = fs::remove_file(source_path);
}

#[test]
fn encrypted_pdf_detail_requires_unlock_then_previews_text() {
    let root = std::env::temp_dir();
    let token = std::process::id();
    let vault_path = root.join(format!("foliora-encrypted-pdf-{token}.vault"));
    let source_path = root.join(format!("foliora-encrypted-pdf-{token}.pdf"));
    let _ = fs::remove_file(&vault_path);
    let _ = fs::remove_file(&source_path);

    let mut document = Document::load_mem(&sample_pdf("Private evidence")).unwrap();
    document.trailer.set(
        "ID",
        Object::Array(vec![
            Object::string_literal(b"FOLIORA-DESKTOP-TEST-ID"),
            Object::string_literal(b"FOLIORA-DESKTOP-TEST-ID"),
        ]),
    );
    let version = EncryptionVersion::V2 {
        document: &document,
        owner_password: "owner",
        user_password: "user",
        key_length: 40,
        permissions: Permissions::all(),
    };
    let state = EncryptionState::try_from(version).unwrap();
    document.encrypt(&state).unwrap();
    let mut encrypted = Vec::new();
    document.save_to(&mut encrypted).unwrap();
    fs::write(&source_path, encrypted).unwrap();

    let mut vault = fast_vault(&vault_path);
    import_document_with_password(&mut vault, &source_path, Some("user")).unwrap();
    let source_id = vault.sources().next().unwrap().source.id.clone();
    assert!(source_detail_with_password(&vault, &source_id, None)
        .unwrap_err()
        .contains("encrypted PDF"));
    let detail = source_detail_with_password(&vault, &source_id, Some("user")).unwrap();
    let SourceDetail::Pdf { pages, .. } = detail else {
        panic!("expected unlocked PDF preview");
    };
    assert!(pages[0].text.contains("Private evidence"));

    let _ = fs::remove_file(vault_path);
    let _ = fs::remove_file(source_path);
}

#[test]
fn eml_container_body_and_attachment_are_committed_together() {
    let root = std::env::temp_dir();
    let token = std::process::id();
    let vault_path = root.join(format!("foliora-eml-{token}.vault"));
    let source_path = root.join(format!("foliora-eml-{token}.eml"));
    let _ = fs::remove_file(&vault_path);
    fs::write(&source_path, sample_eml()).unwrap();
    let mut vault = fast_vault(&vault_path);
    let outcomes = import_document(&mut vault, &source_path).unwrap();
    assert_eq!(outcomes, vec![InsertOutcome::Inserted; 3]);
    let email_id = vault
        .sources()
        .find(|stored| stored.source.media_type == "message/rfc822")
        .unwrap()
        .source
        .id
        .clone();
    let detail = source_detail(&vault, &email_id).unwrap();
    let wire = serde_json::to_value(&detail).unwrap();
    assert_eq!(wire["kind"], "email");
    assert!(wire.get("bodySourceId").is_some());
    assert!(wire.get("dateHeader").is_some());
    let SourceDetail::Email {
        subject,
        body_source_id,
        attachments,
        ..
    } = detail
    else {
        panic!("expected email detail");
    };
    assert_eq!(subject.as_deref(), Some("Warranty"));
    assert!(vault.source(&body_source_id).is_some());
    assert_eq!(attachments.len(), 1);
    assert!(vault.source(&attachments[0].id).is_some());
    let _ = fs::remove_file(vault_path);
    let _ = fs::remove_file(source_path);
}

#[test]
fn image_import_exposes_metadata_and_binary_normalized_preview() {
    let root = std::env::temp_dir();
    let token = std::process::id();
    let vault_path = root.join(format!("foliora-image-{token}.vault"));
    let source_path = root.join(format!("foliora-image-{token}.png"));
    let _ = fs::remove_file(&vault_path);
    let _ = fs::remove_file(&source_path);
    let mut png = Vec::new();
    PngEncoder::new(&mut png)
        .write_image(&[255; 18], 3, 2, ExtendedColorType::Rgb8)
        .unwrap();
    fs::write(&source_path, &png).unwrap();
    let mut vault = fast_vault(&vault_path);

    assert_eq!(
        import_document(&mut vault, &source_path).unwrap(),
        vec![InsertOutcome::Inserted]
    );
    let source_id = vault.sources().next().unwrap().source.id.clone();
    let detail = source_detail(&vault, &source_id).unwrap();
    let SourceDetail::Image {
        format,
        encoded_width,
        encoded_height,
        display_width,
        display_height,
        orientation,
        ..
    } = detail
    else {
        panic!("expected image detail");
    };
    assert_eq!(format, "png");
    assert_eq!((encoded_width, encoded_height), (3, 2));
    assert_eq!((display_width, display_height), (3, 2));
    assert_eq!(orientation, "normal");
    assert!(source_image_png(&vault, &source_id)
        .unwrap()
        .starts_with(b"\x89PNG\r\n\x1a\n"));

    let _ = fs::remove_file(vault_path);
    let _ = fs::remove_file(source_path);
}

#[test]
fn reviewed_ocr_region_creates_a_persisted_candidate() {
    let root = std::env::temp_dir();
    let token = std::process::id();
    let vault_path = root.join(format!("foliora-ocr-candidate-{token}.vault"));
    let source_path = root.join(format!("foliora-ocr-candidate-{token}.png"));
    let _ = fs::remove_file(&vault_path);
    let _ = fs::remove_file(&source_path);
    let mut png = Vec::new();
    PngEncoder::new(&mut png)
        .write_image(&[255; 18], 3, 2, ExtendedColorType::Rgb8)
        .unwrap();
    fs::write(&source_path, png).unwrap();
    let mut vault = fast_vault(&vault_path);
    import_document(&mut vault, &source_path).unwrap();
    let source_id = vault.sources().next().unwrap().source.id.clone();
    let ocr = OcrPage {
        page: 1,
        width: 3,
        height: 2,
        engine: "tesseract".into(),
        engine_version: "5.5.0".into(),
        languages: vec!["vie".into(), "eng".into()],
        regions: vec![OcrRegion {
            text: "Bảo hành".into(),
            x: 0,
            y: 0,
            width: 3,
            height: 1,
            confidence_milli: 935,
        }],
    };

    let claim = create_ocr_candidate(
        &mut vault,
        &source_id,
        &ocr,
        0,
        "warranty.note".into(),
        "item:1".into(),
    )
    .unwrap();
    assert_eq!(claim.status, ClaimStatus::Candidate);
    assert!(matches!(
        claim.provenance,
        foliora_domain::Provenance::Source(foliora_domain::SourceProvenance {
            locator: foliora_domain::SourceLocator::Region {
                page: 1,
                x: 0,
                y: 0,
                width: 3,
                height: 1,
            },
            ..
        })
    ));
    drop(vault);
    let reopened = Vault::open(&vault_path, "passphrase").unwrap();
    assert_eq!(reopened.claim(&claim.id), Some(&claim));
    let _ = fs::remove_file(vault_path);
    let _ = fs::remove_file(source_path);
}

#[test]
fn packaged_ocr_discovery_requires_binary_and_both_language_models() {
    let root = std::env::temp_dir().join(format!("foliora-ocr-resources-{}", std::process::id()));
    let executable = root.join("ocr").join(if cfg!(windows) {
        "tesseract.exe"
    } else {
        "tesseract"
    });
    let tessdata = root.join("ocr").join("tessdata");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&tessdata).unwrap();
    let executable_bytes = b"packaged executable fixture";
    let vie_bytes = b"vie fixture";
    let eng_bytes = b"eng fixture";
    fs::write(&executable, executable_bytes).unwrap();
    fs::write(tessdata.join("vie.traineddata"), vie_bytes).unwrap();
    assert!(packaged_ocr_config(&root).is_none());
    fs::write(tessdata.join("eng.traineddata"), eng_bytes).unwrap();

    let executable_name = if cfg!(windows) {
        "tesseract.exe"
    } else {
        "tesseract"
    };
    let lock = serde_json::json!({
        "schemaVersion": 1,
        "available": true,
        "engineVersion": PACKAGED_TESSERACT_VERSION,
        "executable": {
            "path": executable_name,
            "bytes": executable_bytes.len(),
            "sha256": format!("{:x}", Sha256::digest(executable_bytes)),
        },
        "models": {
            "vie": {
                "path": "tessdata/vie.traineddata",
                "bytes": vie_bytes.len(),
                "sha256": format!("{:x}", Sha256::digest(vie_bytes)),
            },
            "eng": {
                "path": "tessdata/eng.traineddata",
                "bytes": eng_bytes.len(),
                "sha256": format!("{:x}", Sha256::digest(eng_bytes)),
            }
        },
        "runtimeDependencies": []
    })
    .to_string();

    let config = packaged_ocr_config_with_lock(&root, &lock).unwrap();
    assert_eq!(config.executable, executable.canonicalize().unwrap());
    assert_eq!(config.languages, ["vie", "eng"]);
    assert_eq!(config.engine_version, PACKAGED_TESSERACT_VERSION);
    fs::write(tessdata.join("eng.traineddata"), b"tampered").unwrap();
    assert!(packaged_ocr_config_with_lock(&root, &lock).is_none());
    fs::write(tessdata.join("eng.traineddata"), eng_bytes).unwrap();
    fs::write(root.join("ocr").join("unexpected.dll"), b"unlocked").unwrap();
    assert!(packaged_ocr_config_with_lock(&root, &lock).is_none());
    assert!(packaged_ocr_config_with_lock(Path::new("relative-resource-dir"), &lock).is_none());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn corrupt_image_fails_before_vault_mutation() {
    let root = std::env::temp_dir();
    let token = std::process::id();
    let vault_path = root.join(format!("foliora-corrupt-image-{token}.vault"));
    let source_path = root.join(format!("foliora-corrupt-image-{token}.jpg"));
    let _ = fs::remove_file(&vault_path);
    fs::write(&source_path, b"not an image").unwrap();
    let mut vault = fast_vault(&vault_path);
    assert!(import_document(&mut vault, &source_path).is_err());
    assert_eq!(vault.source_count(), 0);
    let _ = fs::remove_file(vault_path);
    let _ = fs::remove_file(source_path);
}

#[test]
fn reviewed_bundle_preview_and_json_export_are_exact_and_persisted() {
    let root = std::env::temp_dir();
    let token = std::process::id();
    let vault_path = root.join(format!("foliora-export-{token}.vault"));
    let source_path = root.join(format!("foliora-export-{token}.txt"));
    let export_path = root.join(format!("foliora-export-{token}.json"));
    let archive_path = root.join(format!("foliora-export-{token}.foliora-pack"));
    let pdf_path = root.join(format!("foliora-export-{token}.pdf"));
    let _ = fs::remove_file(&vault_path);
    let _ = fs::remove_file(&source_path);
    let _ = fs::remove_file(&export_path);
    let _ = fs::remove_file(&archive_path);
    let _ = fs::remove_file(&pdf_path);
    fs::write(&source_path, "Ship safely").unwrap();
    let mut vault = fast_vault(&vault_path);
    import_document(&mut vault, &source_path).unwrap();
    let source_id = vault.sources().next().unwrap().source.id.clone();
    let claim = create_candidate(
        &mut vault,
        &source_id,
        "project.goal".into(),
        "project:1".into(),
        None,
        0,
        "Ship safely".len(),
    )
    .unwrap();
    transition_claim(&mut vault, &claim.id, "confirmed").unwrap();

    let composition = compose_bundle(&vault, "project_handoff", "project:1").unwrap();
    assert_eq!(composition.score.confirmed_required, 1);
    let draft = composition.draft.unwrap();
    let preview = preview_bundle_json(
        &vault,
        "project_handoff",
        "project:1",
        vec![claim.id.clone()],
    )
    .unwrap();
    assert!(preview.content.contains("Ship safely"));
    let clipboard = preview_bundle_clipboard(
        &vault,
        "project_handoff",
        "project:1",
        vec![claim.id.clone()],
        Vec::new(),
        "vi",
    )
    .unwrap();
    assert!(clipboard.content.contains("HỒ SƠ NGỮ CẢNH ĐÃ DUYỆT"));
    assert!(clipboard.content.contains("Ship safely"));
    assert_eq!(clipboard.included_claim_ids, vec![claim.id.clone()]);
    assert!(preview_bundle_clipboard(
        &vault,
        "project_handoff",
        "project:1",
        vec![claim.id.clone()],
        vec!["claim:unknown".into()],
        "en",
    )
    .is_err());
    let archive = preview_bundle_archive(
        &vault,
        "project_handoff",
        "project:1",
        vec![claim.id.clone()],
        "en",
    )
    .unwrap();
    assert!(!archive.manifest.includes_original_sources);
    let archive_receipt = export_bundle_archive(
        &mut vault,
        "project_handoff",
        "project:1",
        vec![claim.id.clone()],
        "en",
        &archive.exported_at,
        &archive.payload_sha256,
        &archive_path,
    )
    .unwrap();
    assert_eq!(archive_receipt.payload_sha256, archive.payload_sha256);
    assert!(fs::read(&archive_path).unwrap().starts_with(b"PK"));
    let prepared_pdf = prepare_bundle_pdf(
        &vault,
        "project_handoff",
        "project:1",
        vec![claim.id.clone()],
        "vi",
    )
    .unwrap();
    assert!(prepared_pdf.bytes.starts_with(b"%PDF-"));
    let pdf_receipt = write_prepared_pdf(
        &mut vault,
        &prepared_pdf,
        &prepared_pdf.preview.payload_sha256,
        &pdf_path,
    )
    .unwrap();
    assert_eq!(pdf_receipt.bytes, prepared_pdf.bytes.len());
    assert_eq!(fs::read(&pdf_path).unwrap(), prepared_pdf.bytes.as_slice());
    let receipt = export_bundle_json(
        &mut vault,
        "project_handoff",
        "project:1",
        vec![claim.id.clone()],
        &preview.exported_at,
        &preview.payload_sha256,
        &export_path,
    )
    .unwrap();
    let bytes = fs::read(&export_path).unwrap();
    assert_eq!(receipt.bytes, bytes.len());
    assert!(receipt.payload_sha256.starts_with("sha256:"));
    assert_eq!(vault.bundle(&draft.id), Some(&draft));
    let rejected_path = root.join(format!("foliora-export-rejected-{token}.json"));
    let _ = fs::remove_file(&rejected_path);
    assert!(export_bundle_json(
        &mut vault,
        "project_handoff",
        "project:1",
        vec![claim.id.clone()],
        &preview.exported_at,
        "sha256:wrong-preview",
        &rejected_path,
    )
    .is_err());
    assert!(!rejected_path.exists());
    assert!(export_bundle_json(
        &mut vault,
        "project_handoff",
        "project:1",
        vec![claim.id],
        &preview.exported_at,
        &preview.payload_sha256,
        &export_path,
    )
    .is_err());

    drop(vault);
    let reopened = Vault::open(&vault_path, "passphrase").unwrap();
    assert!(reopened.bundle(&draft.id).is_some());
    let _ = fs::remove_file(vault_path);
    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(export_path);
    let _ = fs::remove_file(archive_path);
    let _ = fs::remove_file(pdf_path);
    let _ = fs::remove_file(rejected_path);
}

fn sample_pdf(text: &str) -> Vec<u8> {
    let mut document = Document::with_version("1.5");
    let pages_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
    });
    let resources_id =
        document.add_object(dictionary! { "Font" => dictionary! { "F1" => font_id } });
    let content = Content {
        operations: vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 12.into()]),
            Operation::new("Td", vec![50.into(), 780.into()]),
            Operation::new("Tj", vec![Object::string_literal(text)]),
            Operation::new("ET", vec![]),
        ],
    };
    let content_id = document.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
        "Resources" => resources_id, "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
    });
    document.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
        }),
    );
    let catalog_id = document.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes).unwrap();
    bytes
}

fn sample_eml() -> Vec<u8> {
    concat!(
        "From: alice@example.test\r\n",
        "To: bob@example.test\r\n",
        "Subject: Warranty\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=x\r\n\r\n",
        "--x\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nCode VN-789\r\n",
        "--x\r\nContent-Type: text/plain; name=note.txt\r\n",
        "Content-Disposition: attachment; filename=note.txt\r\n\r\nAttached\r\n",
        "--x--\r\n"
    )
    .as_bytes()
    .to_vec()
}
