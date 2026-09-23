use super::*;
use std::fs;
use std::path::PathBuf;

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "foliora-desktop-{name}-{}.vault",
        std::process::id()
    ))
}

#[test]
fn create_snapshot_and_manual_lock_do_not_retain_passphrase() {
    let path = temp_path("session");
    let _ = fs::remove_file(&path);
    let mut session = DesktopSession::new(Duration::from_secs(60));
    session
        .create(&path, "correct horse battery staple".into())
        .unwrap();
    assert!(matches!(
        session.snapshot(),
        SessionSnapshot::Unlocked { vault, .. }
            if vault.path == path.to_string_lossy() && vault.source_count == 0
    ));
    session.lock();
    assert!(matches!(
        session.snapshot(),
        SessionSnapshot::Locked {
            reason: LockReason::Manual,
            ..
        }
    ));
    let _ = fs::remove_file(path);
}

#[test]
fn idle_session_locks_before_returning_state() {
    let path = temp_path("idle");
    let _ = fs::remove_file(&path);
    let mut session = DesktopSession::new(Duration::from_secs(30));
    session.create(&path, "passphrase".into()).unwrap();
    session.force_idle_for(Duration::from_secs(31));
    assert!(matches!(
        session.snapshot(),
        SessionSnapshot::Locked {
            reason: LockReason::Idle,
            ..
        }
    ));
    let _ = fs::remove_file(path);
}

#[test]
fn failed_unlock_does_not_disclose_crypto_details() {
    let path = temp_path("wrong-passphrase");
    let _ = fs::remove_file(&path);
    Vault::create(&path, "right passphrase").unwrap();
    let mut session = DesktopSession::default();
    let error = session.open(&path, "wrong passphrase".into()).unwrap_err();
    assert_eq!(error, "could not unlock vault with the provided passphrase");
    assert!(matches!(session.snapshot(), SessionSnapshot::Locked { .. }));
    let _ = fs::remove_file(path);
}

#[test]
fn auto_lock_bounds_are_enforced() {
    let mut session = DesktopSession::default();
    assert!(session.set_auto_lock_seconds(29).is_err());
    assert!(session.set_auto_lock_seconds(300).is_ok());
    assert!(session
        .set_auto_lock_seconds(MAX_AUTO_LOCK_SECONDS + 1)
        .is_err());
}

#[test]
fn pairing_round_trip_keeps_private_key_out_of_transfer_package() {
    let owner_path = temp_path("pairing-owner");
    let recipient_path = temp_path("pairing-recipient");
    for path in [&owner_path, &recipient_path] {
        let _ = fs::remove_file(path);
    }
    let vault_id = "vault:0123456789abcdef";
    let owner_identity = foliora_sync::DeviceIdentity::generate().unwrap();
    let owner_device = owner_identity.record("Owner").unwrap();
    let mut owner_profile = foliora_sync::SyncProfile::new(
        "https://sync.example".into(),
        vault_id.into(),
        owner_device.clone(),
        &owner_identity,
        "owner-device-token-with-at-least-32-bytes".into(),
        &foliora_sync::EpochKey::from_bytes([7; 32]),
        false,
    )
    .unwrap();
    let paired_head = format!("revision:{}", "a".repeat(64));
    owner_profile.heads = vec![paired_head.clone()];
    let mut owner_vault = Vault::create(&owner_path, "owner passphrase").unwrap();
    owner_vault
        .set_sync_profile_persisted(owner_profile)
        .unwrap();
    drop(owner_vault);

    let mut owner = DesktopSession::default();
    owner.open(&owner_path, "owner passphrase".into()).unwrap();
    let mut recipient = DesktopSession::default();
    recipient
        .create(&recipient_path, "recipient passphrase".into())
        .unwrap();
    let request_json = recipient
        .prepare_pairing_request(
            "https://sync.example".into(),
            vault_id.into(),
            "Recipient".into(),
            false,
        )
        .unwrap();
    assert!(!request_json.contains("recipientSecret"));
    let (_, _, package, _) = owner.prepare_pairing_grant(&request_json).unwrap();
    let package_json = serde_json::to_string(&package).unwrap();
    let code = package.signed_grant.confirmation_code().unwrap();
    let (completed, guard) = recipient
        .prepare_pairing_completion(&package_json, &code)
        .unwrap();
    assert_eq!(completed.pairing_heads, [paired_head]);
    assert_eq!(
        completed
            .trusted_device(&owner_device.device_id)
            .map(|device| &device.public_key),
        Some(&owner_device.public_key)
    );
    let configuration = recipient.finish_pairing(completed, guard).unwrap();
    assert!(configuration.configured);
    assert_eq!(configuration.vault_id.as_deref(), Some(vault_id));

    let _ = fs::remove_file(owner_path);
    let _ = fs::remove_file(recipient_path);
}

#[test]
fn stale_sync_result_cannot_be_applied_to_a_different_vault() {
    let first_path = temp_path("sync-cas-first");
    let second_path = temp_path("sync-cas-second");
    for path in [&first_path, &second_path] {
        let _ = fs::remove_file(path);
    }
    let identity = foliora_sync::DeviceIdentity::generate().unwrap();
    let device = identity.record("Owner").unwrap();
    let profile = foliora_sync::SyncProfile::new(
        "https://sync.example".into(),
        "vault:0123456789abcdef".into(),
        device,
        &identity,
        "owner-device-token-with-at-least-32-bytes".into(),
        &foliora_sync::EpochKey::from_bytes([19; 32]),
        false,
    )
    .unwrap();
    let mut first = Vault::create(&first_path, "first passphrase").unwrap();
    first.set_sync_profile_persisted(profile).unwrap();
    drop(first);
    drop(Vault::create(&second_path, "second passphrase").unwrap());

    let mut session = DesktopSession::default();
    session
        .open(&first_path, "first passphrase".into())
        .unwrap();
    let (profile, _snapshot, guard) = session.prepare_sync().unwrap();
    session
        .open(&second_path, "second passphrase".into())
        .unwrap();
    let run = SyncRun {
        profile,
        remote_snapshot: None,
        own_upload_committed: false,
        report: SyncReport {
            state: "idle".into(),
            uploaded: false,
            downloaded: false,
            epoch: 1,
            heads: vec![],
            detail: "stale test result".into(),
        },
    };

    assert_eq!(
        session.apply_sync_run(run, guard).unwrap_err(),
        "the vault session changed while the operation was running; retry"
    );
    assert!(!session.sync_configuration().configured);
    let _ = fs::remove_file(first_path);
    let _ = fs::remove_file(second_path);
}

#[test]
fn ocr_status_is_honest_when_packaged_resources_are_absent() {
    let session = DesktopSession::default();
    assert_eq!(
        session.ocr_status(),
        OcrStatus {
            available: false,
            engine_version: None,
            languages: vec!["vie".into(), "eng".into()],
        }
    );
}

#[test]
fn session_backup_and_restore_unlock_the_verified_new_vault() {
    let path = temp_path("backup-source");
    let backup = std::env::temp_dir().join(format!(
        "foliora-desktop-backup-{}.foliora-backup",
        std::process::id()
    ));
    let restored = temp_path("backup-restored");
    for candidate in [&path, &backup, &restored] {
        let _ = fs::remove_file(candidate);
    }
    let mut session = DesktopSession::new(Duration::from_secs(60));
    session.create(&path, "passphrase".into()).unwrap();
    let receipt = session.create_backup(&backup).unwrap();
    assert_eq!(receipt.path, backup.to_string_lossy());
    session.lock();
    session
        .restore(&backup, &restored, "passphrase".into())
        .unwrap();
    assert!(matches!(
        session.snapshot(),
        SessionSnapshot::Unlocked { vault, .. } if vault.path == restored.to_string_lossy()
    ));
    for candidate in [path, backup, restored] {
        let _ = fs::remove_file(candidate);
    }
}

#[test]
fn session_recovery_uses_new_passphrase_and_unlocks_restored_vault() {
    let path = temp_path("recovery-source");
    let backup = std::env::temp_dir().join(format!(
        "foliora-desktop-recovery-backup-{}.foliora-backup",
        std::process::id()
    ));
    let kit = std::env::temp_dir().join(format!(
        "foliora-desktop-recovery-kit-{}.foliora-recovery",
        std::process::id()
    ));
    let restored = temp_path("recovery-restored");
    for candidate in [&path, &backup, &kit, &restored] {
        let _ = fs::remove_file(candidate);
    }
    let mut session = DesktopSession::new(Duration::from_secs(60));
    session.create(&path, "old passphrase".into()).unwrap();
    session.create_backup(&backup).unwrap();
    let recovery = session.create_recovery_kit(&kit).unwrap();
    session.lock();
    session
        .restore_with_recovery(
            &backup,
            &kit,
            &restored,
            recovery.recovery_code,
            "new passphrase".into(),
        )
        .unwrap();
    assert!(matches!(
        session.snapshot(),
        SessionSnapshot::Unlocked { .. }
    ));
    session.lock();
    assert!(session.open(&restored, "old passphrase".into()).is_err());
    session.open(&restored, "new passphrase".into()).unwrap();
    for candidate in [path, backup, kit, restored] {
        let _ = fs::remove_file(candidate);
    }
}

#[test]
fn recovery_confirmation_requires_a_kit_and_persists_in_snapshot() {
    let path = temp_path("recovery-confirmation");
    let kit = std::env::temp_dir().join(format!(
        "foliora-desktop-confirmation-kit-{}.foliora-recovery",
        std::process::id()
    ));
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&kit);
    let mut session = DesktopSession::new(Duration::from_secs(60));
    session.create(&path, "passphrase".into()).unwrap();
    assert!(session.confirm_recovery_saved().is_err());
    session.create_recovery_kit(&kit).unwrap();
    assert!(matches!(
        session.confirm_recovery_saved().unwrap(),
        SessionSnapshot::Unlocked { vault, .. } if vault.recovery_configured
    ));
    session.lock();
    session.open(&path, "passphrase".into()).unwrap();
    assert!(matches!(
        session.snapshot(),
        SessionSnapshot::Unlocked { vault, .. } if vault.recovery_configured
    ));
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(kit);
}

#[test]
fn session_recovery_rotation_requires_confirmation_of_the_new_kit() {
    let path = temp_path("recovery-rotation");
    let old_kit = std::env::temp_dir().join(format!(
        "foliora-desktop-rotation-old-{}.foliora-recovery",
        std::process::id()
    ));
    let new_kit = std::env::temp_dir().join(format!(
        "foliora-desktop-rotation-new-{}.foliora-recovery",
        std::process::id()
    ));
    for candidate in [&path, &old_kit, &new_kit] {
        let _ = fs::remove_file(candidate);
    }
    let mut session = DesktopSession::new(Duration::from_secs(60));
    session.create(&path, "passphrase".into()).unwrap();
    session.create_recovery_kit(&old_kit).unwrap();
    session.confirm_recovery_saved().unwrap();

    let receipt = session
        .rotate_recovery_key(&new_kit, "passphrase".into())
        .unwrap();
    assert_eq!(receipt.local_revocation_complete, Some(true));
    assert!(matches!(
        session.snapshot(),
        SessionSnapshot::Unlocked { vault, .. } if !vault.recovery_configured
    ));
    assert!(matches!(
        session.confirm_recovery_saved().unwrap(),
        SessionSnapshot::Unlocked { vault, .. } if vault.recovery_configured
    ));

    for candidate in [path, old_kit, new_kit] {
        let _ = fs::remove_file(candidate);
    }
}

#[test]
fn pdf_preview_bytes_are_exact_and_invalidated_by_mutation_or_lock() {
    let path = temp_path("pdf-preview");
    let source_path = std::env::temp_dir().join(format!(
        "foliora-desktop-pdf-preview-{}.txt",
        std::process::id()
    ));
    let second_path = std::env::temp_dir().join(format!(
        "foliora-desktop-pdf-preview-second-{}.txt",
        std::process::id()
    ));
    let _ = fs::remove_file(&path);
    fs::write(&source_path, "Ship safely").unwrap();
    fs::write(&second_path, "Another source").unwrap();
    let mut session = DesktopSession::new(Duration::from_secs(60));
    session.create(&path, "passphrase".into()).unwrap();
    let workspace = session.import_document(&source_path).unwrap();
    let source_id = workspace.sources[0].id.clone();
    let workspace = session
        .create_candidate(
            &source_id,
            "project.goal".into(),
            "project:1".into(),
            None,
            0,
            "Ship safely".len(),
        )
        .unwrap();
    let claim_id = workspace.claims[0].id.clone();
    session.transition_claim(&claim_id, "confirmed").unwrap();
    let preview = session
        .preview_bundle_pdf("project_handoff", "project:1", vec![claim_id.clone()], "vi")
        .unwrap();
    let bytes = session
        .preview_bundle_pdf_bytes(
            "project_handoff",
            "project:1",
            vec![claim_id.clone()],
            "vi",
            &preview.exported_at,
            &preview.payload_sha256,
        )
        .unwrap();
    assert_eq!(bytes.len(), preview.bytes);
    assert!(bytes.starts_with(b"%PDF-"));

    session.import_document(&second_path).unwrap();
    assert!(session
        .preview_bundle_pdf_bytes(
            "project_handoff",
            "project:1",
            vec![claim_id.clone()],
            "vi",
            &preview.exported_at,
            &preview.payload_sha256,
        )
        .is_err());
    let refreshed = session
        .preview_bundle_pdf("project_handoff", "project:1", vec![claim_id], "vi")
        .unwrap();
    session.lock();
    assert!(session
        .preview_bundle_pdf_bytes(
            "project_handoff",
            "project:1",
            Vec::new(),
            "vi",
            &refreshed.exported_at,
            &refreshed.payload_sha256,
        )
        .is_err());
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(second_path);
}

// Each race test pauses at the same prepare/finish boundary used by async IPC.
// Fixtures exercise real encrypted persistence without a timing-dependent server.
struct SyncFixture {
    session: DesktopSession,
    path: PathBuf,
}

impl SyncFixture {
    fn new(name: &str, configured: bool) -> Self {
        let mut nonce = [0; 16];
        OsRng.fill_bytes(&mut nonce);
        let path = temp_path(&format!("{name}-{}", hex(&nonce)));
        let mut session = DesktopSession::default();
        session.create(&path, "passphrase".into()).unwrap();
        if configured {
            let (profile, _, guard) = session
                .prepare_sync_registration("https://sync.example".into(), "Owner".into(), false)
                .unwrap();
            session.save_sync_profile(profile, guard).unwrap();
        }
        Self { session, path }
    }

    fn reopen(&mut self) {
        self.session.open(&self.path, "passphrase".into()).unwrap();
    }

    fn import(&mut self) {
        let source = self.path.with_extension("txt");
        fs::write(&source, "Local edits must survive sync").unwrap();
        let result = self.session.import_document(&source);
        fs::remove_file(source).unwrap();
        result.unwrap();
    }

    fn content(&mut self) -> Vec<u8> {
        self.session
            .active_vault()
            .unwrap()
            .sync_snapshot()
            .unwrap()
    }

    fn profile(&mut self) -> SyncProfile {
        self.session
            .active_vault()
            .unwrap()
            .sync_profile()
            .unwrap()
            .clone()
    }
}

impl Drop for SyncFixture {
    fn drop(&mut self) {
        self.session.lock();
        let _ = fs::remove_file(&self.path);
    }
}

fn pairing_package(owner: &mut SyncFixture, recipient: &mut SyncFixture) -> (String, String) {
    let profile = owner.profile();
    let request = recipient
        .session
        .prepare_pairing_request(
            profile.endpoint.clone(),
            profile.vault_id.clone(),
            "Recipient".into(),
            false,
        )
        .unwrap();
    let (_, _, package, guard) = owner.session.prepare_pairing_grant(&request).unwrap();
    let receipt = owner.session.finish_pairing_grant(package, guard).unwrap();
    (receipt.package_json, receipt.confirmation_code)
}

fn uploaded_run(mut profile: SyncProfile, snapshot: &[u8], conflict: bool) -> SyncRun {
    profile.next_sequence += 1;
    profile.heads = vec![format!("revision:{}", "a".repeat(64))];
    profile.last_snapshot_sha256 = Some(hex(&Sha256::digest(snapshot)));
    profile.initial_download_pending = false;
    profile.pairing_heads.clear();
    SyncRun {
        report: SyncReport {
            state: if conflict { "conflict" } else { "uploaded" }.into(),
            uploaded: true,
            downloaded: false,
            epoch: profile.epoch,
            heads: if conflict {
                vec![format!("revision:{}", "b".repeat(64))]
            } else {
                profile.heads.clone()
            },
            detail: "confirmed own upload".into(),
        },
        profile,
        remote_snapshot: None,
        own_upload_committed: true,
    }
}

fn downloaded_run(mut profile: SyncProfile, snapshot: Vec<u8>) -> SyncRun {
    profile.heads = vec![format!("revision:{}", "c".repeat(64))];
    profile.last_snapshot_sha256 = Some(hex(&Sha256::digest(&snapshot)));
    profile.initial_download_pending = false;
    profile.pairing_heads.clear();
    SyncRun {
        report: SyncReport {
            state: "downloaded".into(),
            uploaded: false,
            downloaded: true,
            epoch: profile.epoch,
            heads: profile.heads.clone(),
            detail: "verified download".into(),
        },
        profile,
        remote_snapshot: Some(snapshot),
        own_upload_committed: false,
    }
}

#[test]
fn registration_guard_rejects_same_path_session_aba() {
    for idle in [false, true] {
        let mut fixture = SyncFixture::new("registration-aba", false);
        let (profile, _, guard) = fixture
            .session
            .prepare_sync_registration("https://sync.example".into(), "Owner".into(), false)
            .unwrap();
        if idle {
            fixture.session.force_idle_for(Duration::from_secs(301));
            assert!(matches!(
                fixture.session.snapshot(),
                SessionSnapshot::Locked { .. }
            ));
        } else {
            fixture.session.lock();
        }
        fixture.reopen();
        assert!(fixture.session.save_sync_profile(profile, guard).is_err());
        assert!(!fixture.session.sync_configuration().configured);
    }
}

#[test]
fn sync_guards_reject_upload_and_download_after_same_path_reopen() {
    for upload in [false, true] {
        for mode in ["manual", "idle", "replace", "switch"] {
            let mut fixture = SyncFixture::new("sync-aba", true);
            let mut other = SyncFixture::new("sync-aba-other", false);
            other.import();
            let (profile, snapshot, guard) = fixture.session.prepare_sync().unwrap();
            let run = if upload {
                uploaded_run(profile.clone(), &snapshot, false)
            } else {
                downloaded_run(profile.clone(), other.content())
            };
            match mode {
                "manual" => fixture.session.lock(),
                "idle" => {
                    fixture.session.force_idle_for(Duration::from_secs(301));
                    fixture.session.snapshot();
                }
                "switch" => fixture
                    .session
                    .open(&other.path, "passphrase".into())
                    .unwrap(),
                _ => {}
            }
            fixture.reopen();
            assert!(
                fixture.session.apply_sync_run(run, guard).is_err(),
                "{mode}, upload={upload}"
            );
            assert_eq!(fixture.profile(), profile);
            assert_eq!(fixture.content(), snapshot);
        }
    }
}

#[test]
fn pairing_rejects_edits_before_completion_and_during_activation() {
    for during_activation in [false, true] {
        let mut owner = SyncFixture::new("pair-edit-owner", true);
        let mut recipient = SyncFixture::new("pair-edit-recipient", false);
        let (package, code) = pairing_package(&mut owner, &mut recipient);
        if during_activation {
            let (profile, guard) = recipient
                .session
                .prepare_pairing_completion(&package, &code)
                .unwrap();
            recipient.import();
            assert!(recipient.session.finish_pairing(profile, guard).is_err());
        } else {
            recipient.import();
            assert!(recipient
                .session
                .prepare_pairing_completion(&package, &code)
                .is_err());
        }
        let edited = recipient.content();
        recipient.reopen();
        assert_eq!(recipient.content(), edited);
        assert!(!recipient.session.sync_configuration().configured);
        assert!(recipient
            .session
            .active_vault()
            .unwrap()
            .pending_sync_pairing()
            .is_some());
    }
}

#[test]
fn pairing_completion_rejects_same_path_reopen_and_new_profile() {
    for changed_profile in [false, true] {
        let mut owner = SyncFixture::new("pair-aba-owner", true);
        let mut recipient = SyncFixture::new("pair-aba-recipient", false);
        let (package, code) = pairing_package(&mut owner, &mut recipient);
        let (profile, guard) = recipient
            .session
            .prepare_pairing_completion(&package, &code)
            .unwrap();
        let expected_profile = if changed_profile {
            let (new_profile, _, registration) = recipient
                .session
                .prepare_sync_registration("https://sync.example".into(), "New owner".into(), false)
                .unwrap();
            recipient
                .session
                .save_sync_profile(new_profile.clone(), registration)
                .unwrap();
            Some(new_profile)
        } else {
            recipient.session.lock();
            recipient.reopen();
            None
        };
        assert!(recipient.session.finish_pairing(profile, guard).is_err());
        assert_eq!(
            recipient.session.active_vault().unwrap().sync_profile(),
            expected_profile.as_ref()
        );
    }
}

#[test]
fn initial_download_rejects_edits_before_prepare_and_before_apply() {
    for during_download in [false, true] {
        let mut owner = SyncFixture::new("bootstrap-edit-owner", true);
        let mut recipient = SyncFixture::new("bootstrap-edit-recipient", false);
        let (package, code) = pairing_package(&mut owner, &mut recipient);
        let (profile, guard) = recipient
            .session
            .prepare_pairing_completion(&package, &code)
            .unwrap();
        recipient
            .session
            .finish_pairing(profile.clone(), guard)
            .unwrap();
        if during_download {
            let (_, _, guard) = recipient.session.prepare_sync().unwrap();
            let run = downloaded_run(profile.clone(), owner.content());
            recipient.import();
            assert!(recipient.session.apply_sync_run(run, guard).is_err());
        } else {
            recipient.import();
            assert!(recipient.session.prepare_sync().is_err());
            assert!(sync::prepare(recipient.session.active_vault().unwrap()).is_err());
        }
        let edited = recipient.content();
        recipient.reopen();
        assert_eq!(recipient.content(), edited);
        assert_eq!(recipient.profile(), profile);
    }
}

#[test]
fn initial_download_applies_to_unchanged_empty_recipient() {
    let mut owner = SyncFixture::new("bootstrap-owner", true);
    let mut recipient = SyncFixture::new("bootstrap-recipient", false);
    owner.import();
    let (package, code) = pairing_package(&mut owner, &mut recipient);
    let (profile, guard) = recipient
        .session
        .prepare_pairing_completion(&package, &code)
        .unwrap();
    recipient.session.finish_pairing(profile, guard).unwrap();
    let (profile, _, guard) = recipient.session.prepare_sync().unwrap();
    let remote = owner.content();
    let report = recipient
        .session
        .apply_sync_run(downloaded_run(profile, remote.clone()), guard)
        .unwrap();
    assert!(report.downloaded);
    recipient.reopen();
    assert_eq!(recipient.content(), remote);
    assert!(!recipient.profile().initial_download_pending);
}

#[test]
fn upload_checkpoint_survives_local_edits_and_persists_for_next_sync() {
    for conflict in [false, true] {
        let mut fixture = SyncFixture::new("upload-edit", true);
        let (profile, snapshot, guard) = fixture.session.prepare_sync().unwrap();
        let run = uploaded_run(profile, &snapshot, conflict);
        let checkpoint = run.profile.clone();
        fixture.import();
        let edited = fixture.content();
        let report = fixture.session.apply_sync_run(run, guard).unwrap();
        assert!(report.uploaded);
        fixture.reopen();
        let (next_profile, next_snapshot, _) = fixture.session.prepare_sync().unwrap();
        assert_eq!(next_profile, checkpoint);
        assert_eq!(next_profile.next_sequence, 2);
        assert_eq!(
            next_profile.last_snapshot_sha256,
            Some(hex(&Sha256::digest(&snapshot)))
        );
        assert_eq!(next_snapshot, edited);
        assert_ne!(snapshot, next_snapshot);
    }
}

#[test]
fn reconciled_upload_checkpoint_survives_edits_but_ordinary_idle_does_not() {
    for reconciled in [false, true] {
        let mut fixture = SyncFixture::new("idle-edit", true);
        let (profile, snapshot, guard) = fixture.session.prepare_sync().unwrap();
        let mut run = uploaded_run(profile.clone(), &snapshot, false);
        run.report.state = "idle".into();
        run.report.uploaded = false;
        run.own_upload_committed = reconciled;
        if !reconciled {
            run.profile = profile.clone();
        }
        let checkpoint = run.profile.clone();
        fixture.import();
        let edited = fixture.content();
        let result = fixture.session.apply_sync_run(run, guard);
        assert_eq!(result.is_ok(), reconciled);
        fixture.reopen();
        assert_eq!(fixture.content(), edited);
        assert_eq!(fixture.profile(), checkpoint);
    }
}

#[test]
fn upload_checkpoint_rejects_changed_profile() {
    let mut fixture = SyncFixture::new("upload-profile", true);
    let (mut profile, snapshot, guard) = fixture.session.prepare_sync().unwrap();
    let run = uploaded_run(profile.clone(), &snapshot, false);
    profile.device_token = "replacement-device-token-with-at-least-32-bytes".into();
    fixture
        .session
        .active_vault()
        .unwrap()
        .set_sync_profile_persisted(profile.clone())
        .unwrap();
    fixture.import();
    let edited = fixture.content();
    assert!(fixture.session.apply_sync_run(run, guard).is_err());
    fixture.reopen();
    assert_eq!(fixture.profile(), profile);
    assert_eq!(fixture.content(), edited);
}

#[test]
fn ordinary_download_still_rejects_local_edits() {
    let mut fixture = SyncFixture::new("download-edit", true);
    let (profile, snapshot, guard) = fixture.session.prepare_sync().unwrap();
    let run = downloaded_run(profile.clone(), snapshot);
    fixture.import();
    let edited = fixture.content();
    assert!(fixture.session.apply_sync_run(run, guard).is_err());
    assert_eq!(fixture.content(), edited);
    assert_eq!(fixture.profile(), profile);
}

#[test]
fn pairing_grant_receipt_rejects_lock_idle_reopen_switch_and_profile_changes() {
    for mode in ["locked", "idle", "reopened", "switch", "profile"] {
        let mut owner = SyncFixture::new("grant-owner", true);
        let other = SyncFixture::new("grant-other", false);
        let profile = owner.profile();
        let pending = PendingPairing::new(
            profile.endpoint.clone(),
            profile.vault_id.clone(),
            "Recipient".into(),
            false,
        )
        .unwrap();
        let request = serde_json::to_string(pending.request()).unwrap();
        let (_, _, package, guard) = owner.session.prepare_pairing_grant(&request).unwrap();
        match mode {
            "locked" => owner.session.lock(),
            "idle" => owner.session.force_idle_for(Duration::from_secs(301)),
            "reopened" => {
                owner.session.lock();
                owner.reopen();
            }
            "switch" => owner
                .session
                .open(&other.path, "passphrase".into())
                .unwrap(),
            _ => {
                let mut changed = profile;
                changed.heads = vec![format!("revision:{}", "d".repeat(64))];
                owner
                    .session
                    .active_vault()
                    .unwrap()
                    .set_sync_profile_persisted(changed)
                    .unwrap();
            }
        }
        assert!(
            owner.session.finish_pairing_grant(package, guard).is_err(),
            "{mode}"
        );
    }
}
