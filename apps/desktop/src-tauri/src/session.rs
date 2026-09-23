use foliora_ingestion::{OcrPage, TesseractConfig};
use foliora_sync::{
    DeviceIdentity, EpochKey, PairingGrantPackage, PairingRequest, PendingPairing, SyncProfile,
};
use foliora_vault::Vault;
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::extension_bridge::{self, AuthorizedGrant, NativePreview, PrepareFillRequest};
use crate::keychain;
use crate::sync::{self, SyncConfiguration, SyncReport, SyncRun};

use crate::workspace::{
    self, ArchiveExportPreview, ClipboardExportPreview, ClipboardReceipt, ExportReceipt,
    JsonExportPreview, PdfExportPreview, PreparedPdfExport, SourceDetail, WorkspaceSnapshot,
};
use foliora_domain::templates::CompositionResult;

pub const DEFAULT_AUTO_LOCK_SECONDS: u64 = 5 * 60;
pub const MIN_AUTO_LOCK_SECONDS: u64 = 30;
pub const MAX_AUTO_LOCK_SECONDS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultSummary {
    pub path: String,
    pub source_count: usize,
    pub claim_count: usize,
    pub bundle_count: usize,
    pub recovery_configured: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum SessionSnapshot {
    Locked {
        reason: LockReason,
        auto_lock_seconds: u64,
    },
    Unlocked {
        vault: VaultSummary,
        auto_lock_seconds: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LockReason {
    Startup,
    Manual,
    Idle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OcrStatus {
    pub available: bool,
    pub engine_version: Option<String>,
    pub languages: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupReceipt {
    pub path: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryKitReceipt {
    pub path: String,
    pub bytes: u64,
    pub recovery_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_revocation_complete: Option<bool>,
}

pub struct DesktopSession {
    vault: Option<Vault>,
    // Guards retain this allocation, so its identity cannot be reused after lock/reopen.
    generation: Arc<()>,
    last_activity: Instant,
    auto_lock: Duration,
    lock_reason: LockReason,
    pdf_preview: Option<CachedPdfPreview>,
    ocr_config: Option<TesseractConfig>,
    ocr_results: BTreeMap<String, OcrPage>,
    recovery_kit_pending: bool,
    extension_grant: Option<AuthorizedGrant>,
}

pub struct VaultApplyGuard {
    vault_path: PathBuf,
    generation: Arc<()>,
}

pub struct SyncApplyGuard {
    vault: VaultApplyGuard,
    profile: SyncProfile,
    snapshot_sha256: [u8; 32],
}

pub struct PairingApplyGuard {
    vault: VaultApplyGuard,
    pending: PendingPairing,
    snapshot_sha256: [u8; 32],
}

pub struct PairingGrantGuard {
    vault: VaultApplyGuard,
    profile: SyncProfile,
}

#[derive(Clone)]
struct CachedPdfPreview {
    workflow: String,
    subject: String,
    approvals: Vec<String>,
    locale: String,
    prepared: PreparedPdfExport,
}

impl Default for DesktopSession {
    fn default() -> Self {
        Self::new(Duration::from_secs(DEFAULT_AUTO_LOCK_SECONDS))
    }
}

impl DesktopSession {
    pub fn new(auto_lock: Duration) -> Self {
        Self::with_ocr(auto_lock, None)
    }

    pub fn with_ocr(auto_lock: Duration, ocr_config: Option<TesseractConfig>) -> Self {
        Self {
            vault: None,
            generation: Arc::new(()),
            last_activity: Instant::now(),
            auto_lock,
            lock_reason: LockReason::Startup,
            pdf_preview: None,
            ocr_config,
            ocr_results: BTreeMap::new(),
            recovery_kit_pending: false,
            extension_grant: None,
        }
    }

    pub fn create(&mut self, path: &Path, passphrase: String) -> Result<(), String> {
        self.expire_if_idle();
        let passphrase = Zeroizing::new(passphrase);
        let vault = Vault::create(path, passphrase.as_str()).map_err(safe_vault_error)?;
        self.unlock(vault);
        Ok(())
    }

    pub fn open(&mut self, path: &Path, passphrase: String) -> Result<(), String> {
        self.expire_if_idle();
        let passphrase = Zeroizing::new(passphrase);
        let vault = Vault::open(path, passphrase.as_str()).map_err(safe_vault_error)?;
        self.unlock(vault);
        Ok(())
    }

    pub fn open_with_keychain(&mut self, path: &Path) -> Result<(), String> {
        self.expire_if_idle();
        let passphrase = keychain::load(path).map_err(|error| error.to_string())?;
        let vault = Vault::open(path, passphrase.as_str()).map_err(safe_vault_error)?;
        self.unlock(vault);
        Ok(())
    }

    pub fn remember_passphrase(&mut self, path: &Path, passphrase: String) -> Result<(), String> {
        self.expire_if_idle();
        let vault = self.active_vault()?;
        if vault.path() != path {
            return Err("the requested path is not the unlocked vault".into());
        }
        let passphrase = Zeroizing::new(passphrase);
        keychain::save(path, passphrase.as_str()).map_err(|error| error.to_string())?;
        self.touch();
        Ok(())
    }

    pub fn prepare_sync_registration(
        &mut self,
        endpoint: String,
        device_label: String,
        allow_insecure_loopback: bool,
    ) -> Result<(SyncProfile, String, VaultApplyGuard), String> {
        let guard = self.prepare_vault_guard()?;
        let vault = self.active_vault()?;
        if vault.sync_profile().is_some() {
            return Err("sync is already configured for this vault".into());
        }
        let mut vault_bytes = [0_u8; 16];
        OsRng.fill_bytes(&mut vault_bytes);
        let mut token_bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut token_bytes);
        let vault_id = format!("vault:{}", hex(&vault_bytes));
        let device_token = hex(&token_bytes);
        let identity = DeviceIdentity::generate().map_err(|error| error.to_string())?;
        let epoch_key = EpochKey::generate().map_err(|error| error.to_string())?;
        let device = identity
            .record(device_label)
            .map_err(|error| error.to_string())?;
        let profile = SyncProfile::new(
            endpoint,
            vault_id,
            device,
            &identity,
            device_token,
            &epoch_key,
            allow_insecure_loopback,
        )
        .map_err(|error| error.to_string())?;
        let device_token = profile.device_token.clone();
        Ok((profile, device_token, guard))
    }

    pub fn save_sync_profile(
        &mut self,
        profile: SyncProfile,
        guard: VaultApplyGuard,
    ) -> Result<(), String> {
        let vault = self.guarded_vault(&guard)?;
        if vault.sync_profile().is_some() {
            return Err("the vault changed while sync was being configured; retry".into());
        }
        vault
            .set_sync_profile_persisted(profile)
            .map_err(|error| error.to_string())?;
        self.touch();
        Ok(())
    }

    pub fn sync_configuration(&mut self) -> SyncConfiguration {
        self.expire_if_idle();
        sync::configuration(self.vault.as_ref())
    }

    pub fn prepare_sync(&mut self) -> Result<(SyncProfile, Vec<u8>, SyncApplyGuard), String> {
        let vault_guard = self.prepare_vault_guard()?;
        let vault = self.active_vault()?;
        let (profile, snapshot) = sync::prepare(vault)?;
        let guard = SyncApplyGuard {
            vault: vault_guard,
            profile: profile.clone(),
            snapshot_sha256: Sha256::digest(&snapshot).into(),
        };
        Ok((profile, snapshot, guard))
    }

    pub fn apply_sync_run(
        &mut self,
        run: SyncRun,
        guard: SyncApplyGuard,
    ) -> Result<SyncReport, String> {
        let report = run.report.clone();
        let vault = self.guarded_vault(&guard.vault)?;
        if vault.sync_profile() != Some(&guard.profile) {
            return Err(
                "the vault changed while sync was running; remote data was not applied".into(),
            );
        }
        // A successful upload consumed a sequence on the server. Preserve its
        // checkpoint even if content changed (or grew beyond the snapshot limit).
        // This writes credentials/history only, never the captured old content.
        if run.own_upload_committed && run.remote_snapshot.is_none() {
            vault
                .set_sync_profile_persisted(run.profile)
                .map_err(|error| error.to_string())?;
            return Ok(report);
        }
        let current_snapshot = vault.sync_snapshot().map_err(|error| error.to_string())?;
        if <[u8; 32]>::from(Sha256::digest(&current_snapshot)) != guard.snapshot_sha256 {
            return Err(
                "the vault changed while sync was running; remote data was not applied".into(),
            );
        }
        if let Some(snapshot) = run.remote_snapshot {
            if guard.profile.initial_download_pending {
                sync::ensure_empty_for_pairing(vault)?;
            }
            vault
                .replace_from_sync_snapshot_with_profile(&snapshot, Some(run.profile))
                .map_err(|error| error.to_string())?;
        } else if report.state == "idle" {
            vault
                .set_sync_profile_persisted(run.profile)
                .map_err(|error| error.to_string())?;
        }
        self.touch();
        Ok(report)
    }

    pub fn prepare_pairing_request(
        &mut self,
        endpoint: String,
        vault_id: String,
        device_label: String,
        allow_insecure_loopback: bool,
    ) -> Result<String, String> {
        self.expire_if_idle();
        let vault = self.active_vault()?;
        if vault.sync_profile().is_some() {
            return Err("this vault already has sync configured".into());
        }
        if vault
            .pending_sync_pairing()
            .is_some_and(|pending| !pending.request.is_expired())
        {
            return Err("a pairing request is already pending for this vault".into());
        }
        if vault
            .pending_sync_pairing()
            .is_some_and(|pending| pending.request.is_expired())
        {
            vault
                .clear_pending_sync_pairing_persisted()
                .map_err(|error| error.to_string())?;
        }
        sync::ensure_empty_for_pairing(vault)?;
        let pending =
            PendingPairing::new(endpoint, vault_id, device_label, allow_insecure_loopback)
                .map_err(|error| error.to_string())?;
        let request = serde_json::to_string_pretty(pending.request())
            .map_err(|_| "could not serialize the pairing request".to_string())?;
        vault
            .set_pending_sync_pairing_persisted(pending)
            .map_err(|error| error.to_string())?;
        Ok(request)
    }

    pub fn prepare_pairing_grant(
        &mut self,
        request_json: &str,
    ) -> Result<
        (
            SyncProfile,
            PairingRequest,
            PairingGrantPackage,
            PairingGrantGuard,
        ),
        String,
    > {
        let vault = self.prepare_vault_guard()?;
        let request: PairingRequest = serde_json::from_str(request_json)
            .map_err(|_| "pairing request JSON is invalid".to_string())?;
        request
            .validate()
            .map_err(|_| "pairing request is invalid".to_string())?;
        let profile = self
            .active_vault()?
            .sync_profile()
            .cloned()
            .ok_or_else(|| {
                "configure sync on this vault before authorizing a device".to_string()
            })?;
        if profile.endpoint != request.endpoint
            || profile.vault_id != request.vault_id
            || profile.allow_insecure_loopback != request.allow_insecure_loopback
        {
            return Err("pairing request targets a different sync vault or endpoint".into());
        }
        let identity = profile
            .identity()
            .map_err(|_| "stored device identity is invalid".to_string())?;
        let epoch_key = profile
            .epoch_key()
            .map_err(|_| "stored sync key is invalid".to_string())?;
        let mut trusted_devices = profile.trusted_devices.clone();
        trusted_devices.push(profile.device.clone());
        let grant = identity
            .grant_epoch_key_with_context(
                &profile.vault_id,
                profile.epoch,
                &epoch_key,
                request.recipient.clone(),
                trusted_devices,
                profile.heads.clone(),
            )
            .map_err(|_| "could not create a valid pairing grant".to_string())?;
        let package = PairingGrantPackage::new(profile.device.clone(), grant)
            .map_err(|_| "could not package the pairing grant".to_string())?;
        let guard = PairingGrantGuard {
            vault,
            profile: profile.clone(),
        };
        Ok((profile, request, package, guard))
    }

    pub fn finish_pairing_grant(
        &mut self,
        package: PairingGrantPackage,
        guard: PairingGrantGuard,
    ) -> Result<crate::PairingGrantReceipt, String> {
        let vault = self.guarded_vault(&guard.vault)?;
        if vault.sync_profile() != Some(&guard.profile) {
            return Err("sync configuration changed while authorizing the device; retry".into());
        }
        Ok(crate::PairingGrantReceipt {
            package_json: serde_json::to_string_pretty(&package)
                .map_err(|_| "could not serialize the pairing grant".to_string())?,
            confirmation_code: package
                .signed_grant
                .confirmation_code()
                .map_err(|_| "could not calculate the pairing confirmation code".to_string())?,
        })
    }

    pub fn prepare_pairing_completion(
        &mut self,
        package_json: &str,
        confirmed_code: &str,
    ) -> Result<(SyncProfile, PairingApplyGuard), String> {
        let vault_guard = self.prepare_vault_guard()?;
        let package: PairingGrantPackage = serde_json::from_str(package_json)
            .map_err(|_| "pairing grant JSON is invalid".to_string())?;
        let (profile, guard) = {
            let vault = self.active_vault()?;
            sync::ensure_empty_for_pairing(vault)?;
            if vault.sync_profile().is_some() {
                return Err("this vault already has sync configured".into());
            }
            let pending = vault
                .pending_sync_pairing()
                .cloned()
                .ok_or_else(|| "create a pairing request on this device first".to_string())?;
            let profile = pending
                .complete(&package, &package.authorizer, confirmed_code)
                .map_err(|_| "pairing grant or confirmation code is invalid".to_string())?;
            let guard = PairingApplyGuard {
                vault: vault_guard,
                pending,
                snapshot_sha256: Sha256::digest(
                    vault.sync_snapshot().map_err(|error| error.to_string())?,
                )
                .into(),
            };
            (profile, guard)
        };
        Ok((profile, guard))
    }

    pub fn finish_pairing(
        &mut self,
        profile: SyncProfile,
        guard: PairingApplyGuard,
    ) -> Result<SyncConfiguration, String> {
        let vault = self.guarded_vault(&guard.vault)?;
        sync::ensure_empty_for_pairing(vault)?;
        if vault.sync_profile().is_some()
            || vault.pending_sync_pairing() != Some(&guard.pending)
            || <[u8; 32]>::from(Sha256::digest(
                vault.sync_snapshot().map_err(|error| error.to_string())?,
            )) != guard.snapshot_sha256
        {
            return Err("the pending pairing changed while activation was running; retry".into());
        }
        vault
            .finish_pending_sync_pairing(profile)
            .map_err(|error| error.to_string())?;
        Ok(self.sync_configuration())
    }

    pub fn restore(
        &mut self,
        backup: &Path,
        destination: &Path,
        passphrase: String,
    ) -> Result<(), String> {
        self.expire_if_idle();
        let passphrase = Zeroizing::new(passphrase);
        let vault = Vault::restore_to_new_path(backup, destination, passphrase.as_str())
            .map_err(safe_vault_error)?;
        self.unlock(vault);
        Ok(())
    }

    pub fn create_backup(&mut self, destination: &Path) -> Result<BackupReceipt, String> {
        self.pdf_preview = None;
        let vault = self.active_vault()?;
        let bytes = vault
            .create_verified_backup(destination)
            .map_err(safe_vault_error)?;
        Ok(BackupReceipt {
            path: destination.to_string_lossy().into_owned(),
            bytes,
        })
    }

    pub fn create_recovery_kit(
        &mut self,
        destination: &Path,
    ) -> Result<RecoveryKitReceipt, String> {
        self.pdf_preview = None;
        let vault = self.active_vault()?;
        let receipt = vault
            .create_recovery_kit(destination)
            .map_err(safe_vault_error)?;
        let response = RecoveryKitReceipt {
            path: receipt.path.to_string_lossy().into_owned(),
            bytes: receipt.bytes,
            recovery_code: receipt.recovery_code.to_string(),
            local_revocation_complete: None,
        };
        self.recovery_kit_pending = true;
        Ok(response)
    }

    pub fn rotate_recovery_key(
        &mut self,
        destination: &Path,
        passphrase: String,
    ) -> Result<RecoveryKitReceipt, String> {
        self.pdf_preview = None;
        let passphrase = Zeroizing::new(passphrase);
        let vault = self.active_vault()?;
        let receipt = vault
            .rotate_recovery_key(destination, passphrase.as_str())
            .map_err(safe_vault_error)?;
        let response = RecoveryKitReceipt {
            path: receipt.kit.path.to_string_lossy().into_owned(),
            bytes: receipt.kit.bytes,
            recovery_code: receipt.kit.recovery_code.to_string(),
            local_revocation_complete: Some(receipt.local_revocation_complete),
        };
        self.recovery_kit_pending = true;
        Ok(response)
    }

    pub fn confirm_recovery_saved(&mut self) -> Result<SessionSnapshot, String> {
        if !self.recovery_kit_pending {
            return Err("create a recovery kit before confirming it was saved".into());
        }
        let auto_lock_seconds = self.auto_lock.as_secs();
        let vault = self.active_vault()?;
        vault
            .confirm_recovery_configured()
            .map_err(safe_vault_error)?;
        let vault = summary(vault);
        self.recovery_kit_pending = false;
        Ok(SessionSnapshot::Unlocked {
            vault,
            auto_lock_seconds,
        })
    }

    pub fn restore_with_recovery(
        &mut self,
        backup: &Path,
        recovery_kit: &Path,
        destination: &Path,
        recovery_code: String,
        new_passphrase: String,
    ) -> Result<(), String> {
        self.expire_if_idle();
        let recovery_code = Zeroizing::new(recovery_code);
        let new_passphrase = Zeroizing::new(new_passphrase);
        let vault = Vault::restore_with_recovery(
            backup,
            recovery_kit,
            destination,
            recovery_code.as_str(),
            new_passphrase.as_str(),
        )
        .map_err(safe_vault_error)?;
        self.unlock(vault);
        Ok(())
    }

    pub fn lock(&mut self) {
        self.generation = Arc::new(());
        self.vault = None;
        self.pdf_preview = None;
        self.ocr_results.clear();
        self.recovery_kit_pending = false;
        self.extension_grant = None;
        self.lock_reason = LockReason::Manual;
    }

    pub fn set_auto_lock_seconds(&mut self, seconds: u64) -> Result<(), String> {
        if !(MIN_AUTO_LOCK_SECONDS..=MAX_AUTO_LOCK_SECONDS).contains(&seconds) {
            return Err(format!(
                "auto-lock must be between {MIN_AUTO_LOCK_SECONDS} and {MAX_AUTO_LOCK_SECONDS} seconds"
            ));
        }
        self.auto_lock = Duration::from_secs(seconds);
        self.touch();
        Ok(())
    }

    pub fn workspace(&mut self) -> Result<WorkspaceSnapshot, String> {
        let vault = self.active_vault()?;
        Ok(workspace::snapshot(vault))
    }

    pub fn authorize_extension(
        &mut self,
        top_origin: &str,
        approved_claim_ids: Vec<String>,
        lifetime_ms: u64,
    ) -> Result<AuthorizedGrant, String> {
        let now_ms = unix_time_ms()?;
        let claims = self.active_vault()?.claims().cloned().collect::<Vec<_>>();
        let grant = extension_bridge::authorize(
            top_origin,
            approved_claim_ids,
            now_ms,
            lifetime_ms,
            &claims,
        )?;
        self.extension_grant = Some(grant.clone());
        Ok(grant)
    }

    pub fn revoke_extension(&mut self) {
        self.extension_grant = None;
    }

    pub fn prepare_extension(
        &mut self,
        request: PrepareFillRequest,
    ) -> Result<NativePreview, String> {
        let grant = self.extension_grant.clone().ok_or_else(|| {
            "approve this origin and claim subset in Foliora Desktop first".to_string()
        })?;
        let now_ms = unix_time_ms()?;
        let claims = self.active_vault()?.claims().cloned().collect::<Vec<_>>();
        extension_bridge::prepare(&grant, request, &claims, now_ms)
    }

    pub fn source_detail_with_password(
        &mut self,
        id: &str,
        pdf_password: Option<String>,
    ) -> Result<SourceDetail, String> {
        let pdf_password = pdf_password.map(Zeroizing::new);
        let vault = self.active_vault()?;
        workspace::source_detail_with_password(
            vault,
            id,
            pdf_password.as_ref().map(|password| password.as_str()),
        )
    }

    pub fn source_image_png(&mut self, id: &str) -> Result<Vec<u8>, String> {
        let vault = self.active_vault()?;
        workspace::source_image_png(vault, id)
    }

    pub fn ocr_status(&self) -> OcrStatus {
        match &self.ocr_config {
            Some(config) => OcrStatus {
                available: true,
                engine_version: Some(config.engine_version.clone()),
                languages: config.languages.clone(),
            },
            None => OcrStatus {
                available: false,
                engine_version: None,
                languages: vec!["vie".into(), "eng".into()],
            },
        }
    }

    pub fn run_image_ocr(&mut self, source_id: &str) -> Result<OcrPage, String> {
        let config = self.ocr_config.clone().ok_or_else(|| {
            "packaged Vietnamese/English OCR resources are unavailable".to_string()
        })?;
        let vault = self.active_vault()?;
        let result = workspace::run_image_ocr(vault, source_id, &config)?;
        self.ocr_results.insert(source_id.into(), result.clone());
        Ok(result)
    }

    pub fn create_ocr_candidate(
        &mut self,
        source_id: &str,
        region_index: usize,
        claim_type: String,
        subject: String,
    ) -> Result<WorkspaceSnapshot, String> {
        self.pdf_preview = None;
        let ocr = self
            .ocr_results
            .get(source_id)
            .cloned()
            .ok_or_else(|| "run and review OCR for this source first".to_string())?;
        let vault = self.active_vault()?;
        workspace::create_ocr_candidate(vault, source_id, &ocr, region_index, claim_type, subject)?;
        Ok(workspace::snapshot(vault))
    }

    #[cfg(test)]
    pub fn import_document(&mut self, path: &Path) -> Result<WorkspaceSnapshot, String> {
        self.import_document_with_password(path, None)
    }

    pub fn import_document_with_password(
        &mut self,
        path: &Path,
        pdf_password: Option<String>,
    ) -> Result<WorkspaceSnapshot, String> {
        self.pdf_preview = None;
        self.ocr_results.clear();
        let pdf_password = pdf_password.map(Zeroizing::new);
        let vault = self.active_vault()?;
        workspace::import_document_with_password(
            vault,
            path,
            pdf_password.as_ref().map(|password| password.as_str()),
        )?;
        Ok(workspace::snapshot(vault))
    }

    pub fn create_candidate(
        &mut self,
        source_id: &str,
        claim_type: String,
        subject: String,
        page: Option<u32>,
        start: usize,
        end: usize,
    ) -> Result<WorkspaceSnapshot, String> {
        self.pdf_preview = None;
        let vault = self.active_vault()?;
        workspace::create_candidate(vault, source_id, claim_type, subject, page, start, end)?;
        Ok(workspace::snapshot(vault))
    }

    pub fn prepare_model_request(
        &mut self,
        source_id: &str,
        model: &str,
        redactions: &[String],
    ) -> Result<foliora_model::PreparedRequest, String> {
        let vault = self.active_vault()?;
        workspace::prepare_model_request(vault, source_id, model, redactions)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_model_candidate(
        &mut self,
        source_id: &str,
        expected_source_fingerprint: &str,
        expected_quote: &str,
        claim_type: String,
        subject: String,
        start: usize,
        end: usize,
    ) -> Result<WorkspaceSnapshot, String> {
        self.pdf_preview = None;
        let vault = self.active_vault()?;
        workspace::create_model_candidate(
            vault,
            source_id,
            expected_source_fingerprint,
            expected_quote,
            claim_type,
            subject,
            start,
            end,
        )?;
        Ok(workspace::snapshot(vault))
    }

    pub fn transition_claim(
        &mut self,
        id: &str,
        status: &str,
    ) -> Result<WorkspaceSnapshot, String> {
        self.pdf_preview = None;
        let vault = self.active_vault()?;
        workspace::transition_claim(vault, id, status)?;
        Ok(workspace::snapshot(vault))
    }

    pub fn compose_bundle(
        &mut self,
        workflow: &str,
        subject: &str,
    ) -> Result<CompositionResult, String> {
        let vault = self.active_vault()?;
        workspace::compose_bundle(vault, workflow, subject)
    }

    pub fn export_bundle_json(
        &mut self,
        workflow: &str,
        subject: &str,
        approved_sensitive_claim_ids: Vec<String>,
        exported_at: &str,
        expected_sha256: &str,
        path: &Path,
    ) -> Result<ExportReceipt, String> {
        let vault = self.active_vault()?;
        workspace::export_bundle_json(
            vault,
            workflow,
            subject,
            approved_sensitive_claim_ids,
            exported_at,
            expected_sha256,
            path,
        )
    }

    pub fn preview_bundle_json(
        &mut self,
        workflow: &str,
        subject: &str,
        approved_sensitive_claim_ids: Vec<String>,
    ) -> Result<JsonExportPreview, String> {
        let vault = self.active_vault()?;
        workspace::preview_bundle_json(vault, workflow, subject, approved_sensitive_claim_ids)
    }

    pub fn preview_bundle_clipboard(
        &mut self,
        workflow: &str,
        subject: &str,
        approved_sensitive_claim_ids: Vec<String>,
        excluded_claim_ids: Vec<String>,
        locale: &str,
    ) -> Result<ClipboardExportPreview, String> {
        let vault = self.active_vault()?;
        workspace::preview_bundle_clipboard(
            vault,
            workflow,
            subject,
            approved_sensitive_claim_ids,
            excluded_claim_ids,
            locale,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn copy_bundle_clipboard(
        &mut self,
        workflow: &str,
        subject: &str,
        approved_sensitive_claim_ids: Vec<String>,
        excluded_claim_ids: Vec<String>,
        locale: &str,
        exported_at: &str,
        expected_sha256: &str,
        write: impl FnOnce(&str) -> Result<(), String>,
    ) -> Result<ClipboardReceipt, String> {
        let vault = self.active_vault()?;
        let (draft, exported) = workspace::prepare_clipboard_export(
            vault,
            workflow,
            subject,
            approved_sensitive_claim_ids,
            excluded_claim_ids,
            locale,
            exported_at,
        )?;
        if exported.audit_event.payload_sha256 != expected_sha256 {
            return Err(
                "vault or redaction changed after preview; review the clipboard content again"
                    .into(),
            );
        }
        write(&exported.text)?;
        vault
            .insert_bundle_persisted(draft.clone())
            .map_err(|error| error.to_string())?;
        Ok(ClipboardReceipt {
            bytes: exported.text.len(),
            payload_sha256: exported.audit_event.payload_sha256,
            bundle_id: draft.id,
        })
    }

    pub fn preview_bundle_archive(
        &mut self,
        workflow: &str,
        subject: &str,
        approved_sensitive_claim_ids: Vec<String>,
        locale: &str,
    ) -> Result<ArchiveExportPreview, String> {
        let vault = self.active_vault()?;
        workspace::preview_bundle_archive(
            vault,
            workflow,
            subject,
            approved_sensitive_claim_ids,
            locale,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn export_bundle_archive(
        &mut self,
        workflow: &str,
        subject: &str,
        approved_sensitive_claim_ids: Vec<String>,
        locale: &str,
        exported_at: &str,
        expected_sha256: &str,
        path: &Path,
    ) -> Result<ExportReceipt, String> {
        let vault = self.active_vault()?;
        workspace::export_bundle_archive(
            vault,
            workflow,
            subject,
            approved_sensitive_claim_ids,
            locale,
            exported_at,
            expected_sha256,
            path,
        )
    }

    pub fn preview_bundle_pdf(
        &mut self,
        workflow: &str,
        subject: &str,
        approved_sensitive_claim_ids: Vec<String>,
        locale: &str,
    ) -> Result<PdfExportPreview, String> {
        let approvals = normalized_ids(approved_sensitive_claim_ids);
        let vault = self.active_vault()?;
        let prepared =
            workspace::prepare_bundle_pdf(vault, workflow, subject, approvals.clone(), locale)?;
        let preview = prepared.preview.clone();
        self.pdf_preview = Some(CachedPdfPreview {
            workflow: workflow.into(),
            subject: subject.into(),
            approvals,
            locale: locale.into(),
            prepared,
        });
        Ok(preview)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn preview_bundle_pdf_bytes(
        &mut self,
        workflow: &str,
        subject: &str,
        approved_sensitive_claim_ids: Vec<String>,
        locale: &str,
        exported_at: &str,
        expected_sha256: &str,
    ) -> Result<Vec<u8>, String> {
        self.active_vault()?;
        let cached = self.valid_pdf_preview(
            workflow,
            subject,
            approved_sensitive_claim_ids,
            locale,
            exported_at,
            expected_sha256,
        )?;
        Ok(cached.prepared.bytes.to_vec())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn export_bundle_pdf(
        &mut self,
        workflow: &str,
        subject: &str,
        approved_sensitive_claim_ids: Vec<String>,
        locale: &str,
        exported_at: &str,
        expected_sha256: &str,
        path: &Path,
    ) -> Result<ExportReceipt, String> {
        self.active_vault()?;
        let prepared = self
            .valid_pdf_preview(
                workflow,
                subject,
                approved_sensitive_claim_ids,
                locale,
                exported_at,
                expected_sha256,
            )?
            .prepared
            .clone();
        let vault = self.active_vault()?;
        workspace::write_prepared_pdf(vault, &prepared, expected_sha256, path)
    }

    pub fn snapshot(&mut self) -> SessionSnapshot {
        self.expire_if_idle();
        let auto_lock_seconds = self.auto_lock.as_secs();
        match &self.vault {
            Some(vault) => SessionSnapshot::Unlocked {
                vault: summary(vault),
                auto_lock_seconds,
            },
            None => SessionSnapshot::Locked {
                reason: self.lock_reason,
                auto_lock_seconds,
            },
        }
    }

    fn unlock(&mut self, vault: Vault) {
        self.generation = Arc::new(());
        self.vault = Some(vault);
        self.pdf_preview = None;
        self.ocr_results.clear();
        self.recovery_kit_pending = false;
        self.extension_grant = None;
        self.touch();
    }

    fn prepare_vault_guard(&mut self) -> Result<VaultApplyGuard, String> {
        let vault_path = self.active_vault()?.path().to_path_buf();
        Ok(VaultApplyGuard {
            vault_path,
            generation: self.generation.clone(),
        })
    }

    fn guarded_vault(&mut self, guard: &VaultApplyGuard) -> Result<&mut Vault, String> {
        self.expire_if_idle();
        if !Arc::ptr_eq(&self.generation, &guard.generation) {
            return Err("the vault session changed while the operation was running; retry".into());
        }
        let vault = self.active_vault()?;
        if vault.path() != guard.vault_path {
            return Err("the vault session changed while the operation was running; retry".into());
        }
        Ok(vault)
    }

    fn active_vault(&mut self) -> Result<&mut Vault, String> {
        self.expire_if_idle();
        if self.vault.is_none() {
            return Err("vault is locked".into());
        }
        self.touch();
        self.vault.as_mut().ok_or_else(|| "vault is locked".into())
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    fn expire_if_idle(&mut self) {
        if self.vault.is_some() && self.last_activity.elapsed() >= self.auto_lock {
            self.generation = Arc::new(());
            self.vault = None;
            self.pdf_preview = None;
            self.ocr_results.clear();
            self.extension_grant = None;
            self.lock_reason = LockReason::Idle;
        }
    }

    #[cfg(test)]
    fn force_idle_for(&mut self, duration: Duration) {
        self.last_activity = Instant::now() - duration;
    }

    fn valid_pdf_preview(
        &self,
        workflow: &str,
        subject: &str,
        approved_sensitive_claim_ids: Vec<String>,
        locale: &str,
        exported_at: &str,
        expected_sha256: &str,
    ) -> Result<&CachedPdfPreview, String> {
        let approvals = normalized_ids(approved_sensitive_claim_ids);
        self.pdf_preview
            .as_ref()
            .filter(|cached| {
                cached.workflow == workflow
                    && cached.subject == subject
                    && cached.approvals == approvals
                    && cached.locale == locale
                    && cached.prepared.preview.exported_at == exported_at
                    && cached.prepared.preview.payload_sha256 == expected_sha256
            })
            .ok_or_else(|| "PDF preview expired or inputs changed; preview it again".into())
    }
}

fn unix_time_ms() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_string())?
        .as_millis()
        .try_into()
        .map_err(|_| "system clock is outside the supported range".to_string())
}

fn normalized_ids(mut ids: Vec<String>) -> Vec<String> {
    ids.sort();
    ids.dedup();
    ids
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn summary(vault: &Vault) -> VaultSummary {
    VaultSummary {
        path: vault.path().to_string_lossy().into_owned(),
        source_count: vault.source_count(),
        claim_count: vault.claim_count(),
        bundle_count: vault.bundle_count(),
        recovery_configured: vault.recovery_configured(),
    }
}

fn safe_vault_error(error: foliora_vault::VaultError) -> String {
    match error {
        foliora_vault::VaultError::AuthenticationFailed => {
            "could not unlock vault with the provided passphrase".into()
        }
        foliora_vault::VaultError::Io(io_error)
            if io_error.kind() == std::io::ErrorKind::NotFound =>
        {
            "vault file was not found".into()
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
