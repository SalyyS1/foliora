//! Narrow native boundary for the Foliora desktop application.

mod extension_bridge;
mod keychain;
mod native_broker;
pub mod native_host;
mod session;
mod sync;
mod workspace;

use extension_bridge::{AuthorizedGrant, NativePreview, PrepareFillRequest};
use foliora_domain::templates::CompositionResult;
use foliora_ingestion::OcrPage;
use foliora_model::{ModelRequestPreview, ModelSuggestion};
use serde::Serialize;
use session::{
    BackupReceipt, DesktopSession, OcrStatus, RecoveryKitReceipt, SessionSnapshot,
    DEFAULT_AUTO_LOCK_SECONDS,
};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use sync::{SyncConfiguration, SyncReport};
use tauri::{Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use workspace::{
    ArchiveExportPreview, ClipboardExportPreview, ClipboardReceipt, ExportReceipt,
    JsonExportPreview, PdfExportPreview, SourceDetail, WorkspaceSnapshot,
};

pub const APP_NAME: &str = "foliora";

type ManagedSession = Arc<Mutex<DesktopSession>>;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PairingGrantReceipt {
    package_json: String,
    confirmation_code: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ModelSuggestionBatch {
    source_id: String,
    source_fingerprint: String,
    payload_sha256: String,
    suggestions: Vec<ModelSuggestion>,
}

#[tauri::command]
fn session_snapshot(state: State<'_, ManagedSession>) -> Result<SessionSnapshot, String> {
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())
        .map(|mut session| session.snapshot())
}

#[tauri::command]
fn create_vault(
    path: String,
    passphrase: String,
    state: State<'_, ManagedSession>,
) -> Result<SessionSnapshot, String> {
    let path = validate_vault_path(path)?;
    let mut session = state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?;
    session.create(&path, passphrase)?;
    Ok(session.snapshot())
}

#[tauri::command]
fn open_vault(
    path: String,
    passphrase: String,
    state: State<'_, ManagedSession>,
) -> Result<SessionSnapshot, String> {
    let path = validate_vault_path(path)?;
    let mut session = state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?;
    session.open(&path, passphrase)?;
    Ok(session.snapshot())
}

#[tauri::command]
fn open_vault_with_keychain(
    path: String,
    state: State<'_, ManagedSession>,
) -> Result<SessionSnapshot, String> {
    let path = validate_vault_path(path)?;
    let mut session = state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?;
    session.open_with_keychain(&path)?;
    Ok(session.snapshot())
}

#[tauri::command]
fn has_saved_vault_passphrase(path: String) -> Result<bool, String> {
    let path = validate_vault_path(path)?;
    keychain::has(&path).map_err(|error| error.to_string())
}

#[tauri::command]
fn remember_vault_passphrase(
    path: String,
    passphrase: String,
    state: State<'_, ManagedSession>,
) -> Result<(), String> {
    let path = validate_vault_path(path)?;
    let mut session = state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?;
    session.remember_passphrase(&path, passphrase)
}

#[tauri::command]
fn forget_vault_passphrase(path: String) -> Result<(), String> {
    let path = validate_vault_path(path)?;
    keychain::forget(&path).map_err(|error| error.to_string())
}

#[tauri::command]
fn sync_configuration(state: State<'_, ManagedSession>) -> Result<SyncConfiguration, String> {
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())
        .map(|mut session| session.sync_configuration())
}

#[tauri::command]
async fn configure_sync(
    endpoint: String,
    bootstrap_token: String,
    device_label: String,
    allow_insecure_loopback: bool,
    state: State<'_, ManagedSession>,
) -> Result<SyncConfiguration, String> {
    let bootstrap_token = zeroize::Zeroizing::new(bootstrap_token);
    let (profile, device_token, guard) = state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .prepare_sync_registration(endpoint, device_label, allow_insecure_loopback)?;
    let client = profile
        .client()
        .map_err(|_| "sync endpoint or generated credential is invalid".to_string())?;
    client
        .create_vault(
            bootstrap_token.as_str(),
            &profile.vault_id,
            &profile.device,
            5 * 1024 * 1024 * 1024,
            &device_token,
        )
        .await
        .map_err(|_| "could not create the encrypted sync vault on the server".to_string())?;
    let mut session = state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?;
    session.save_sync_profile(profile, guard)?;
    Ok(session.sync_configuration())
}

#[tauri::command]
async fn sync_vault(state: State<'_, ManagedSession>) -> Result<SyncReport, String> {
    let (profile, snapshot, guard) = state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .prepare_sync()?;
    let run = tokio::time::timeout(sync::SYNC_OPERATION_TIMEOUT, sync::run(profile, snapshot))
        .await
        .map_err(|_| "sync operation exceeded the five-minute deadline".to_string())??;
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .apply_sync_run(run, guard)
}

#[tauri::command]
fn create_pairing_request(
    endpoint: String,
    vault_id: String,
    device_label: String,
    allow_insecure_loopback: bool,
    state: State<'_, ManagedSession>,
) -> Result<String, String> {
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .prepare_pairing_request(endpoint, vault_id, device_label, allow_insecure_loopback)
}

#[tauri::command]
async fn authorize_pairing_request(
    request_json: String,
    state: State<'_, ManagedSession>,
) -> Result<PairingGrantReceipt, String> {
    let (profile, request, package, guard) = state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .prepare_pairing_grant(&request_json)?;
    let client = profile
        .client()
        .map_err(|_| "stored sync endpoint or credential is invalid".to_string())?;
    client
        .pair_device(
            &profile.vault_id,
            &package.signed_grant,
            &request.recipient_token,
            request.expires_at_unix,
        )
        .await
        .map_err(|_| "could not register the new device on the sync server".to_string())?;
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .finish_pairing_grant(package, guard)
}

#[tauri::command]
async fn complete_pairing(
    package_json: String,
    confirmation_code: String,
    state: State<'_, ManagedSession>,
) -> Result<SyncConfiguration, String> {
    let (profile, guard) = state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .prepare_pairing_completion(&package_json, &confirmation_code)?;
    profile
        .client()
        .map_err(|_| "stored sync endpoint or credential is invalid".to_string())?
        .activate_pairing(&profile.vault_id, &confirmation_code)
        .await
        .map_err(|_| "could not activate this device on the sync server".to_string())?;
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .finish_pairing(profile, guard)
}

#[tauri::command]
fn restore_vault(
    backup_path: String,
    destination_path: String,
    passphrase: String,
    state: State<'_, ManagedSession>,
) -> Result<SessionSnapshot, String> {
    let backup = validate_absolute_path(backup_path, "backup")?;
    let destination = validate_vault_path(destination_path)?;
    let mut session = state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?;
    session.restore(&backup, &destination, passphrase)?;
    Ok(session.snapshot())
}

#[tauri::command]
fn create_vault_backup(
    destination_path: String,
    state: State<'_, ManagedSession>,
) -> Result<BackupReceipt, String> {
    let destination = validate_absolute_path(destination_path, "backup destination")?;
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .create_backup(&destination)
}

#[tauri::command]
fn create_recovery_kit(
    destination_path: String,
    state: State<'_, ManagedSession>,
) -> Result<RecoveryKitReceipt, String> {
    let destination = validate_absolute_path(destination_path, "recovery kit destination")?;
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .create_recovery_kit(&destination)
}

#[tauri::command]
fn rotate_recovery_key(
    destination_path: String,
    passphrase: String,
    state: State<'_, ManagedSession>,
) -> Result<RecoveryKitReceipt, String> {
    let destination = validate_absolute_path(destination_path, "recovery kit destination")?;
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .rotate_recovery_key(&destination, passphrase)
}

#[tauri::command]
fn confirm_recovery_saved(state: State<'_, ManagedSession>) -> Result<SessionSnapshot, String> {
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .confirm_recovery_saved()
}

#[tauri::command]
fn restore_vault_with_recovery(
    backup_path: String,
    recovery_kit_path: String,
    destination_path: String,
    recovery_code: String,
    new_passphrase: String,
    state: State<'_, ManagedSession>,
) -> Result<SessionSnapshot, String> {
    let backup = validate_absolute_path(backup_path, "backup")?;
    let recovery_kit = validate_absolute_path(recovery_kit_path, "recovery kit")?;
    let destination = validate_vault_path(destination_path)?;
    let mut session = state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?;
    session.restore_with_recovery(
        &backup,
        &recovery_kit,
        &destination,
        recovery_code,
        new_passphrase,
    )?;
    Ok(session.snapshot())
}

#[tauri::command]
fn lock_vault(state: State<'_, ManagedSession>) -> Result<SessionSnapshot, String> {
    let mut session = state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?;
    session.lock();
    Ok(session.snapshot())
}

#[tauri::command]
fn set_auto_lock(
    seconds: u64,
    state: State<'_, ManagedSession>,
) -> Result<SessionSnapshot, String> {
    let mut session = state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?;
    session.set_auto_lock_seconds(seconds)?;
    Ok(session.snapshot())
}

#[tauri::command]
fn workspace_snapshot(state: State<'_, ManagedSession>) -> Result<WorkspaceSnapshot, String> {
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .workspace()
}

#[tauri::command]
fn authorize_extension_grant(
    top_origin: String,
    approved_claim_ids: Vec<String>,
    lifetime_ms: u64,
    state: State<'_, ManagedSession>,
) -> Result<AuthorizedGrant, String> {
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .authorize_extension(&top_origin, approved_claim_ids, lifetime_ms)
}

#[tauri::command]
fn revoke_extension_grant(state: State<'_, ManagedSession>) -> Result<(), String> {
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .revoke_extension();
    Ok(())
}

#[tauri::command]
fn prepare_extension_fill(
    request: PrepareFillRequest,
    state: State<'_, ManagedSession>,
) -> Result<NativePreview, String> {
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .prepare_extension(request)
}

#[tauri::command]
fn source_detail(
    id: String,
    pdf_password: Option<String>,
    state: State<'_, ManagedSession>,
) -> Result<SourceDetail, String> {
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .source_detail_with_password(&id, pdf_password)
}

#[tauri::command]
fn source_image_bytes(
    id: String,
    state: State<'_, ManagedSession>,
) -> Result<tauri::ipc::Response, String> {
    let bytes = state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .source_image_png(&id)?;
    Ok(tauri::ipc::Response::new(bytes))
}

#[tauri::command]
fn ocr_status(state: State<'_, ManagedSession>) -> Result<OcrStatus, String> {
    Ok(state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .ocr_status())
}

#[tauri::command]
fn run_image_ocr(id: String, state: State<'_, ManagedSession>) -> Result<OcrPage, String> {
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .run_image_ocr(&id)
}

#[tauri::command]
fn create_ocr_candidate(
    source_id: String,
    region_index: usize,
    claim_type: String,
    subject: String,
    state: State<'_, ManagedSession>,
) -> Result<WorkspaceSnapshot, String> {
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .create_ocr_candidate(&source_id, region_index, claim_type, subject)
}

#[tauri::command]
fn import_document(
    path: String,
    pdf_password: Option<String>,
    state: State<'_, ManagedSession>,
) -> Result<WorkspaceSnapshot, String> {
    let path = validate_absolute_path(path, "source")?;
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .import_document_with_password(&path, pdf_password)
}

#[tauri::command]
fn create_evidence_candidate(
    source_id: String,
    claim_type: String,
    subject: String,
    page: Option<u32>,
    start: usize,
    end: usize,
    state: State<'_, ManagedSession>,
) -> Result<WorkspaceSnapshot, String> {
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .create_candidate(&source_id, claim_type, subject, page, start, end)
}

#[tauri::command]
fn preview_model_request(
    source_id: String,
    model: String,
    redactions: Vec<String>,
    state: State<'_, ManagedSession>,
) -> Result<ModelRequestPreview, String> {
    let prepared = state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .prepare_model_request(&source_id, &model, &redactions)?;
    Ok(prepared.preview.clone())
}

#[tauri::command]
async fn run_model_suggestions(
    source_id: String,
    model: String,
    redactions: Vec<String>,
    expected_payload_sha256: String,
    api_key: String,
    state: State<'_, ManagedSession>,
) -> Result<ModelSuggestionBatch, String> {
    let api_key = zeroize::Zeroizing::new(api_key);
    let prepared = state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .prepare_model_request(&source_id, &model, &redactions)?;
    verify_model_preview(&prepared.preview.payload_sha256, &expected_payload_sha256)?;
    let suggestions = foliora_model::request_suggestions(&prepared, api_key)
        .await
        .map_err(|error| error.to_string())?;
    Ok(ModelSuggestionBatch {
        source_id: prepared.preview.source_id.clone(),
        source_fingerprint: prepared.preview.source_fingerprint.clone(),
        payload_sha256: prepared.preview.payload_sha256.clone(),
        suggestions,
    })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn create_model_candidate(
    source_id: String,
    expected_source_fingerprint: String,
    expected_quote: String,
    claim_type: String,
    subject: String,
    start: usize,
    end: usize,
    state: State<'_, ManagedSession>,
) -> Result<WorkspaceSnapshot, String> {
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .create_model_candidate(
            &source_id,
            &expected_source_fingerprint,
            &expected_quote,
            claim_type,
            subject,
            start,
            end,
        )
}

fn verify_model_preview(actual: &str, expected: &str) -> Result<(), String> {
    if actual != expected {
        return Err("model request changed after preview; review it again before sending".into());
    }
    Ok(())
}

#[tauri::command]
fn review_claim(
    id: String,
    status: String,
    state: State<'_, ManagedSession>,
) -> Result<WorkspaceSnapshot, String> {
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .transition_claim(&id, &status)
}

#[tauri::command]
fn compose_bundle(
    workflow: String,
    subject: String,
    state: State<'_, ManagedSession>,
) -> Result<CompositionResult, String> {
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .compose_bundle(&workflow, &subject)
}

#[tauri::command]
fn export_bundle_json(
    workflow: String,
    subject: String,
    approved_sensitive_claim_ids: Vec<String>,
    exported_at: String,
    expected_sha256: String,
    path: String,
    state: State<'_, ManagedSession>,
) -> Result<ExportReceipt, String> {
    let path = validate_absolute_path(path, "export")?;
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .export_bundle_json(
            &workflow,
            &subject,
            approved_sensitive_claim_ids,
            &exported_at,
            &expected_sha256,
            &path,
        )
}

#[tauri::command]
fn preview_bundle_json(
    workflow: String,
    subject: String,
    approved_sensitive_claim_ids: Vec<String>,
    state: State<'_, ManagedSession>,
) -> Result<JsonExportPreview, String> {
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .preview_bundle_json(&workflow, &subject, approved_sensitive_claim_ids)
}

#[tauri::command]
fn preview_bundle_clipboard(
    workflow: String,
    subject: String,
    approved_sensitive_claim_ids: Vec<String>,
    excluded_claim_ids: Vec<String>,
    locale: String,
    state: State<'_, ManagedSession>,
) -> Result<ClipboardExportPreview, String> {
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .preview_bundle_clipboard(
            &workflow,
            &subject,
            approved_sensitive_claim_ids,
            excluded_claim_ids,
            &locale,
        )
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn copy_bundle_clipboard(
    workflow: String,
    subject: String,
    approved_sensitive_claim_ids: Vec<String>,
    excluded_claim_ids: Vec<String>,
    locale: String,
    exported_at: String,
    expected_sha256: String,
    app: tauri::AppHandle,
    state: State<'_, ManagedSession>,
) -> Result<ClipboardReceipt, String> {
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .copy_bundle_clipboard(
            &workflow,
            &subject,
            approved_sensitive_claim_ids,
            excluded_claim_ids,
            &locale,
            &exported_at,
            &expected_sha256,
            |text| {
                app.clipboard()
                    .write_text(text)
                    .map_err(|error| error.to_string())
            },
        )
}

#[tauri::command]
fn preview_bundle_archive(
    workflow: String,
    subject: String,
    approved_sensitive_claim_ids: Vec<String>,
    locale: String,
    state: State<'_, ManagedSession>,
) -> Result<ArchiveExportPreview, String> {
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .preview_bundle_archive(&workflow, &subject, approved_sensitive_claim_ids, &locale)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn export_bundle_archive(
    workflow: String,
    subject: String,
    approved_sensitive_claim_ids: Vec<String>,
    locale: String,
    exported_at: String,
    expected_sha256: String,
    path: String,
    state: State<'_, ManagedSession>,
) -> Result<ExportReceipt, String> {
    let path = validate_absolute_path(path, "archive export")?;
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .export_bundle_archive(
            &workflow,
            &subject,
            approved_sensitive_claim_ids,
            &locale,
            &exported_at,
            &expected_sha256,
            &path,
        )
}

#[tauri::command]
fn preview_bundle_pdf(
    workflow: String,
    subject: String,
    approved_sensitive_claim_ids: Vec<String>,
    locale: String,
    state: State<'_, ManagedSession>,
) -> Result<PdfExportPreview, String> {
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .preview_bundle_pdf(&workflow, &subject, approved_sensitive_claim_ids, &locale)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn preview_bundle_pdf_bytes(
    workflow: String,
    subject: String,
    approved_sensitive_claim_ids: Vec<String>,
    locale: String,
    exported_at: String,
    expected_sha256: String,
    state: State<'_, ManagedSession>,
) -> Result<tauri::ipc::Response, String> {
    let bytes = state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .preview_bundle_pdf_bytes(
            &workflow,
            &subject,
            approved_sensitive_claim_ids,
            &locale,
            &exported_at,
            &expected_sha256,
        )?;
    Ok(tauri::ipc::Response::new(bytes))
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn export_bundle_pdf(
    workflow: String,
    subject: String,
    approved_sensitive_claim_ids: Vec<String>,
    locale: String,
    exported_at: String,
    expected_sha256: String,
    path: String,
    state: State<'_, ManagedSession>,
) -> Result<ExportReceipt, String> {
    let path = validate_absolute_path(path, "PDF export")?;
    state
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .export_bundle_pdf(
            &workflow,
            &subject,
            approved_sensitive_claim_ids,
            &locale,
            &exported_at,
            &expected_sha256,
            &path,
        )
}

fn validate_vault_path(path: String) -> Result<PathBuf, String> {
    let path = validate_absolute_path(path, "vault")?;
    if path.extension().and_then(|value| value.to_str()) != Some("vault") {
        return Err("vault file must use the .vault extension".into());
    }
    Ok(path)
}

fn validate_absolute_path(path: String, kind: &str) -> Result<PathBuf, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(format!("choose a {kind} file"));
    }
    let path = PathBuf::from(trimmed);
    if !path.is_absolute() {
        return Err(format!("{kind} path must be absolute"));
    }
    Ok(path)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            let resource_dir = app.path().resource_dir()?;
            let ocr = workspace::packaged_ocr_config(&resource_dir);
            let session = Arc::new(Mutex::new(DesktopSession::with_ocr(
                std::time::Duration::from_secs(DEFAULT_AUTO_LOCK_SECONDS),
                ocr,
            )));
            let bridge = native_broker::NativeBridgeServer::start(
                app.path()
                    .app_data_dir()
                    .map_err(|error| error.to_string())?,
                Arc::clone(&session),
            )?;
            app.manage(session);
            app.manage(bridge);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            session_snapshot,
            create_vault,
            open_vault,
            open_vault_with_keychain,
            has_saved_vault_passphrase,
            remember_vault_passphrase,
            forget_vault_passphrase,
            sync_configuration,
            configure_sync,
            sync_vault,
            create_pairing_request,
            authorize_pairing_request,
            complete_pairing,
            restore_vault,
            create_vault_backup,
            create_recovery_kit,
            rotate_recovery_key,
            confirm_recovery_saved,
            restore_vault_with_recovery,
            lock_vault,
            set_auto_lock,
            workspace_snapshot,
            authorize_extension_grant,
            revoke_extension_grant,
            prepare_extension_fill,
            source_detail,
            source_image_bytes,
            ocr_status,
            run_image_ocr,
            create_ocr_candidate,
            import_document,
            create_evidence_candidate,
            preview_model_request,
            run_model_suggestions,
            create_model_candidate,
            review_claim,
            compose_bundle,
            preview_bundle_json,
            export_bundle_json,
            preview_bundle_clipboard,
            copy_bundle_clipboard,
            preview_bundle_archive,
            export_bundle_archive,
            preview_bundle_pdf,
            preview_bundle_pdf_bytes,
            export_bundle_pdf
        ])
        .build(tauri::generate_context!())
        .expect("failed to build Foliora desktop application")
        .run(|handle, event| {
            if matches!(event, tauri::RunEvent::Exit) {
                if let Ok(directory) = handle.path().app_data_dir() {
                    let _ = std::fs::remove_file(directory.join(native_host::RENDEZVOUS_FILE));
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_path_is_explicit_and_absolute() {
        assert!(validate_vault_path(String::new()).is_err());
        assert!(validate_vault_path("relative.vault".into()).is_err());
        assert!(
            validate_vault_path(std::env::temp_dir().join("data.txt").display().to_string())
                .is_err()
        );
        assert!(validate_vault_path(
            std::env::temp_dir()
                .join("data.vault")
                .display()
                .to_string()
        )
        .is_ok());
    }

    #[test]
    fn model_send_requires_the_exact_preview_hash() {
        assert!(verify_model_preview("sha256:a", "sha256:a").is_ok());
        assert!(verify_model_preview("sha256:a", "sha256:b")
            .unwrap_err()
            .contains("changed after preview"));
    }
}
