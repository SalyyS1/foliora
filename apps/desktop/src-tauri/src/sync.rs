use foliora_sync::{
    client::{SyncHttpClient, SyncOutcome, VaultStatus},
    ManifestDraft, SignedManifest, SignedPairingGrant, SyncProfile, MAX_OBJECT_BYTES,
};
use foliora_vault::Vault;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const MAX_DEVICE_AUTHORIZATION_DEPTH: usize = 32;
const MAX_MANIFEST_ANCESTRY_VISITS: usize = 4_096;
pub const SYNC_OPERATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5 * 60);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncReport {
    pub state: String,
    pub uploaded: bool,
    pub downloaded: bool,
    pub epoch: u64,
    pub heads: Vec<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncConfiguration {
    pub configured: bool,
    pub endpoint: Option<String>,
    pub vault_id: Option<String>,
    pub device_id: Option<String>,
    pub epoch: Option<u64>,
    pub heads: Vec<String>,
}

pub struct SyncRun {
    pub profile: SyncProfile,
    pub remote_snapshot: Option<Vec<u8>>,
    // True only for our acknowledged commit or a cryptographically reconciled
    // prior commit. An ordinary idle response does not acknowledge an upload.
    pub own_upload_committed: bool,
    pub report: SyncReport,
}

pub fn configuration(vault: Option<&Vault>) -> SyncConfiguration {
    let Some(profile) = vault.and_then(Vault::sync_profile) else {
        return SyncConfiguration {
            configured: false,
            endpoint: None,
            vault_id: None,
            device_id: None,
            epoch: None,
            heads: vec![],
        };
    };
    SyncConfiguration {
        configured: true,
        endpoint: Some(profile.endpoint.clone()),
        vault_id: Some(profile.vault_id.clone()),
        device_id: Some(profile.device.device_id.clone()),
        epoch: Some(profile.epoch),
        heads: profile.heads.clone(),
    }
}

pub fn prepare(vault: &Vault) -> Result<(SyncProfile, Vec<u8>), String> {
    let profile = vault
        .sync_profile()
        .cloned()
        .ok_or_else(|| "sync is not configured for this vault".to_string())?;
    profile
        .validate()
        .map_err(|_| "stored sync configuration is invalid; reconfigure this vault".to_string())?;
    if profile.initial_download_pending {
        ensure_empty_for_pairing(vault)?;
    }
    let snapshot = vault
        .sync_snapshot()
        .map_err(|error| format!("could not prepare encrypted sync snapshot: {error}"))?;
    if snapshot.len() > MAX_OBJECT_BYTES {
        return Err("sync snapshot exceeds the 25 MiB protocol limit".into());
    }
    Ok((profile, snapshot))
}

pub(crate) fn ensure_empty_for_pairing(vault: &Vault) -> Result<(), String> {
    if vault.source_count() != 0 || vault.claim_count() != 0 || vault.bundle_count() != 0 {
        return Err("pairing a device requires an empty vault before initial download".into());
    }
    Ok(())
}

pub async fn run(profile: SyncProfile, snapshot: Vec<u8>) -> Result<SyncRun, String> {
    let local_digest = digest(&snapshot);
    let client = profile
        .client()
        .map_err(|_| "stored sync endpoint or credential is invalid".to_string())?;
    let status = client
        .status(&profile.vault_id)
        .await
        .map_err(safe_client_error)?;
    if status.epoch != profile.epoch {
        return Err("sync key epoch changed; pair this device again before syncing".into());
    }
    if initial_checkpoint_mismatch(&profile, &status.heads) {
        if let Some(reconciled) =
            reconcile_ambiguous_upload(&client, &profile, &status.heads, &local_digest).await?
        {
            return Ok(reconciled);
        }
        return Ok(conflict_run(profile, status.epoch, status.heads));
    }
    if status.heads.len() > 1 {
        return Ok(conflict_run(profile, status.epoch, status.heads));
    }
    let server_heads = status.heads.clone();
    let local_heads = profile.heads.clone();
    if server_heads != local_heads {
        let initial_download = profile.initial_download_pending
            && profile.last_snapshot_sha256.is_none()
            && local_heads.is_empty()
            && !server_heads.is_empty();
        if initial_download
            || profile.last_snapshot_sha256.as_deref() == Some(local_digest.as_str())
        {
            if server_heads.is_empty() {
                return Err(
                    "sync server history was reset; restore or re-pair before writing".into(),
                );
            }
            let head = server_heads.first().expect("checked non-empty");
            let manifest = client
                .get_manifest(&profile.vault_id, head)
                .await
                .map_err(safe_client_error)?;
            authenticate_manifest(&client, &profile, &manifest).await?;
            if !initial_download
                && !remote_descends_from(&client, &profile, &manifest, &local_heads).await?
            {
                return Ok(conflict_run(profile, status.epoch, server_heads));
            }
            if manifest.manifest.epoch != profile.epoch || manifest.manifest.object_ids.len() != 1 {
                return Err("sync head has an unsupported encrypted snapshot shape".into());
            }
            let object = client
                .get_object(&profile.vault_id, &manifest.manifest.object_ids[0])
                .await
                .map_err(safe_client_error)?;
            let plaintext = profile
                .epoch_key()
                .map_err(|_| "stored sync key is invalid".to_string())?
                .decrypt(&object)
                .map_err(|_| "downloaded sync object failed authentication".to_string())?;
            let remote = plaintext.to_vec();
            if remote.len() > MAX_OBJECT_BYTES {
                return Err("downloaded sync snapshot exceeds the protocol limit".into());
            }
            let mut updated = profile;
            updated.heads = server_heads.clone();
            updated.last_snapshot_sha256 = Some(digest(&remote));
            updated.initial_download_pending = false;
            updated.pairing_heads.clear();
            return Ok(SyncRun {
                profile: updated,
                remote_snapshot: Some(remote),
                own_upload_committed: false,
                report: SyncReport {
                    state: "downloaded".into(),
                    uploaded: false,
                    downloaded: true,
                    epoch: status.epoch,
                    heads: server_heads,
                    detail: "downloaded the newer encrypted snapshot".into(),
                },
            });
        }
        if let Some(reconciled) =
            reconcile_ambiguous_upload(&client, &profile, &server_heads, &local_digest).await?
        {
            return Ok(reconciled);
        }
        return Ok(conflict_run(profile, status.epoch, server_heads));
    }
    if profile.last_snapshot_sha256.as_deref() == Some(local_digest.as_str()) {
        return Ok(SyncRun {
            profile,
            remote_snapshot: None,
            own_upload_committed: false,
            report: SyncReport {
                state: "idle".into(),
                uploaded: false,
                downloaded: false,
                epoch: status.epoch,
                heads: server_heads,
                detail: "local vault and sync history are already up to date".into(),
            },
        });
    }
    let identity = profile
        .identity()
        .map_err(|_| "stored device identity is invalid".to_string())?;
    let key = profile
        .epoch_key()
        .map_err(|_| "stored sync key is invalid".to_string())?;
    let object = key
        .encrypt(&profile.vault_id, profile.epoch, &snapshot)
        .map_err(|_| "could not encrypt the sync snapshot".to_string())?;
    let object_id = object.object_id.clone();
    match client
        .upload_object(&object)
        .await
        .map_err(safe_client_error)?
    {
        SyncOutcome::Inserted | SyncOutcome::AlreadyPresent => {}
    }
    let sequence = profile.next_sequence;
    let manifest = identity
        .sign(
            ManifestDraft {
                vault_id: profile.vault_id.clone(),
                epoch: profile.epoch,
                parents: profile.heads.clone(),
                object_ids: vec![object_id],
                tombstones: vec![],
                device_id: profile.device.device_id.clone(),
                sequence,
            }
            .finalize()
            .map_err(|_| "could not create a valid sync manifest".to_string())?,
        )
        .map_err(|_| "could not sign the sync manifest".to_string())?;
    client
        .commit_manifest(&manifest)
        .await
        .map_err(safe_client_error)?;
    let final_status = client
        .status(&profile.vault_id)
        .await
        .map_err(safe_client_error)?;
    finish_upload(
        profile,
        sequence,
        manifest.manifest.revision_id,
        local_digest,
        final_status,
    )
}

fn initial_checkpoint_mismatch(profile: &SyncProfile, server_heads: &[String]) -> bool {
    profile.initial_download_pending && server_heads != profile.pairing_heads
}

async fn reconcile_ambiguous_upload(
    client: &SyncHttpClient,
    profile: &SyncProfile,
    server_heads: &[String],
    local_digest: &str,
) -> Result<Option<SyncRun>, String> {
    let [head_id] = server_heads else {
        return Ok(None);
    };
    let manifest = client
        .get_manifest(&profile.vault_id, head_id)
        .await
        .map_err(safe_client_error)?;
    authenticate_manifest(client, profile, &manifest).await?;
    if !matches_ambiguous_upload(profile, &manifest, local_digest, None) {
        return Ok(None);
    }
    let object = client
        .get_object(&profile.vault_id, &manifest.manifest.object_ids[0])
        .await
        .map_err(safe_client_error)?;
    let plaintext = profile
        .epoch_key()
        .map_err(|_| "stored sync key is invalid".to_string())?
        .decrypt(&object)
        .map_err(|_| "downloaded sync object failed authentication".to_string())?;
    let remote_digest = digest(&plaintext);
    if !matches_ambiguous_upload(profile, &manifest, local_digest, Some(&remote_digest)) {
        return Ok(None);
    }
    let mut updated = profile.clone();
    updated.next_sequence = updated
        .next_sequence
        .checked_add(1)
        .ok_or_else(|| "sync sequence exhausted; re-pair this device".to_string())?;
    updated.heads = server_heads.to_vec();
    updated.last_snapshot_sha256 = Some(local_digest.to_string());
    updated.initial_download_pending = false;
    updated.pairing_heads.clear();
    Ok(Some(SyncRun {
        profile: updated,
        remote_snapshot: None,
        own_upload_committed: true,
        report: SyncReport {
            state: "idle".into(),
            uploaded: false,
            downloaded: false,
            epoch: manifest.manifest.epoch,
            heads: server_heads.to_vec(),
            detail:
                "reconciled a previously committed signed snapshot after an interrupted response"
                    .into(),
        },
    }))
}

fn matches_ambiguous_upload(
    profile: &SyncProfile,
    manifest: &SignedManifest,
    local_digest: &str,
    remote_digest: Option<&str>,
) -> bool {
    manifest.manifest.device_id == profile.device.device_id
        && manifest.manifest.sequence == profile.next_sequence
        && manifest.manifest.parents == profile.heads
        && manifest.manifest.object_ids.len() == 1
        && manifest.manifest.tombstones.is_empty()
        && remote_digest.is_none_or(|digest| digest == local_digest)
}

fn finish_upload(
    profile: SyncProfile,
    sequence: u64,
    committed_revision: String,
    local_digest: String,
    final_status: VaultStatus,
) -> Result<SyncRun, String> {
    if final_status.epoch != profile.epoch {
        return Err("sync key epoch changed after upload; pair this device again".into());
    }
    let next_sequence = sequence
        .checked_add(1)
        .ok_or_else(|| "sync sequence exhausted; re-pair this device".to_string())?;
    let mut updated = profile;
    updated.next_sequence = next_sequence;
    updated.heads = vec![committed_revision.clone()];
    updated.last_snapshot_sha256 = Some(local_digest);
    updated.initial_download_pending = false;
    updated.pairing_heads.clear();
    if final_status.heads != updated.heads {
        return Ok(SyncRun {
            profile: updated,
            remote_snapshot: None,
            own_upload_committed: true,
            report: SyncReport {
                state: "conflict".into(),
                uploaded: true,
                downloaded: false,
                epoch: final_status.epoch,
                heads: final_status.heads,
                detail: "the signed snapshot was uploaded, but the server head set changed; local history remains anchored to the committed revision".into(),
            },
        });
    }
    Ok(SyncRun {
        profile: updated,
        remote_snapshot: None,
        own_upload_committed: true,
        report: SyncReport {
            state: "uploaded".into(),
            uploaded: true,
            downloaded: false,
            epoch: final_status.epoch,
            heads: final_status.heads,
            detail: "encrypted snapshot uploaded and signed manifest committed".into(),
        },
    })
}

async fn remote_descends_from(
    client: &SyncHttpClient,
    profile: &SyncProfile,
    head: &SignedManifest,
    required_ancestors: &[String],
) -> Result<bool, String> {
    let required: BTreeSet<_> = required_ancestors.iter().cloned().collect();
    let mut found = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut pending = head.manifest.parents.clone();
    while let Some(revision_id) = pending.pop() {
        if required.contains(&revision_id) {
            found.insert(revision_id);
            continue;
        }
        if !seen.insert(revision_id.clone()) {
            continue;
        }
        if seen.len() > MAX_MANIFEST_ANCESTRY_VISITS {
            return Err("sync manifest ancestry exceeds the verification limit".into());
        }
        let ancestor = client
            .get_manifest(&profile.vault_id, &revision_id)
            .await
            .map_err(safe_client_error)?;
        if ancestor.manifest.epoch != profile.epoch {
            return Err("sync manifest ancestry uses an unexpected key epoch".into());
        }
        authenticate_manifest(client, profile, &ancestor).await?;
        pending.extend(ancestor.manifest.parents);
    }
    Ok(found == required)
}

async fn authenticate_manifest(
    client: &SyncHttpClient,
    profile: &SyncProfile,
    manifest: &SignedManifest,
) -> Result<(), String> {
    let mut current = manifest.manifest.device_id.clone();
    let mut seen = BTreeSet::new();
    let mut chain = Vec::new();
    while profile.trusted_device(&current).is_none() {
        if chain.len() == MAX_DEVICE_AUTHORIZATION_DEPTH || !seen.insert(current.clone()) {
            return Err("sync manifest signer authorization is invalid".into());
        }
        let grant = client
            .get_device_authorization(&profile.vault_id, &current)
            .await
            .map_err(safe_client_error)?;
        current = grant.grant.authorizing_device_id.clone();
        chain.push(grant);
    }
    verify_manifest_chain(profile, manifest, &chain)
}

fn verify_manifest_chain(
    profile: &SyncProfile,
    manifest: &SignedManifest,
    chain_from_signer: &[SignedPairingGrant],
) -> Result<(), String> {
    if manifest.manifest.epoch != profile.epoch {
        return Err("sync manifest uses an unexpected key epoch".into());
    }
    let anchor_id = chain_from_signer
        .last()
        .map(|grant| grant.grant.authorizing_device_id.as_str())
        .unwrap_or(manifest.manifest.device_id.as_str());
    let mut authorizer = profile
        .trusted_device(anchor_id)
        .cloned()
        .ok_or_else(|| "sync manifest signer is not anchored to a trusted device".to_string())?;
    for grant in chain_from_signer.iter().rev() {
        if grant.grant.vault_id != profile.vault_id
            || grant.grant.epoch != profile.epoch
            || grant.grant.authorizing_device_id != authorizer.device_id
        {
            return Err("sync device authorization chain is invalid".into());
        }
        grant
            .verify(&authorizer)
            .map_err(|_| "sync device authorization signature is invalid".to_string())?;
        authorizer = grant.grant.recipient.clone();
    }
    if authorizer.device_id != manifest.manifest.device_id {
        return Err("sync device authorization does not match manifest signer".into());
    }
    manifest
        .verify(&authorizer)
        .map_err(|_| "downloaded sync manifest signature is invalid".to_string())
}

fn conflict_run(profile: SyncProfile, epoch: u64, heads: Vec<String>) -> SyncRun {
    SyncRun {
        profile,
        remote_snapshot: None,
        own_upload_committed: false,
        report: SyncReport {
            state: "conflict".into(),
            uploaded: false,
            downloaded: false,
            epoch,
            heads,
            detail: "both local and remote history changed; no data was overwritten".into(),
        },
    }
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn safe_client_error(_: foliora_sync::client::ClientError) -> String {
    "sync operation failed; verify the endpoint, credentials, and network".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use foliora_sync::{DeviceIdentity, EpochKey};

    #[test]
    fn manifest_signature_requires_a_chain_to_a_local_trust_anchor() {
        let owner_identity = DeviceIdentity::generate().unwrap();
        let child_identity = DeviceIdentity::generate().unwrap();
        let attacker_identity = DeviceIdentity::generate().unwrap();
        let owner = owner_identity.record("Owner").unwrap();
        let child = child_identity.record("Child").unwrap();
        let attacker = attacker_identity.record("Attacker").unwrap();
        let key = EpochKey::from_bytes([66; 32]);
        let profile = SyncProfile::new(
            "https://sync.example".into(),
            "vault:0123456789abcdef".into(),
            owner.clone(),
            &owner_identity,
            "owner-device-token-with-at-least-32-bytes".into(),
            &key,
            false,
        )
        .unwrap();
        let authorization = owner_identity
            .grant_epoch_key(&profile.vault_id, 1, &key, child.clone())
            .unwrap();
        let child_manifest = child_identity
            .sign(
                ManifestDraft {
                    vault_id: profile.vault_id.clone(),
                    epoch: 1,
                    parents: vec![],
                    object_ids: vec![],
                    tombstones: vec![],
                    device_id: child.device_id.clone(),
                    sequence: 1,
                }
                .finalize()
                .unwrap(),
            )
            .unwrap();
        assert!(verify_manifest_chain(&profile, &child_manifest, &[authorization]).is_ok());

        let grandchild_identity = DeviceIdentity::generate().unwrap();
        let grandchild = grandchild_identity.record("Grandchild").unwrap();
        let owner_to_child = owner_identity
            .grant_epoch_key(&profile.vault_id, 1, &key, child.clone())
            .unwrap();
        let child_to_grandchild = child_identity
            .grant_epoch_key(&profile.vault_id, 1, &key, grandchild.clone())
            .unwrap();
        let grandchild_manifest = grandchild_identity
            .sign(
                ManifestDraft {
                    vault_id: profile.vault_id.clone(),
                    epoch: 1,
                    parents: vec![],
                    object_ids: vec![],
                    tombstones: vec![],
                    device_id: grandchild.device_id,
                    sequence: 1,
                }
                .finalize()
                .unwrap(),
            )
            .unwrap();
        assert!(verify_manifest_chain(
            &profile,
            &grandchild_manifest,
            &[child_to_grandchild, owner_to_child],
        )
        .is_ok());

        let attacker_manifest = attacker_identity
            .sign(
                ManifestDraft {
                    vault_id: profile.vault_id.clone(),
                    epoch: 1,
                    parents: vec![],
                    object_ids: vec![],
                    tombstones: vec![],
                    device_id: attacker.device_id,
                    sequence: 1,
                }
                .finalize()
                .unwrap(),
            )
            .unwrap();
        assert!(verify_manifest_chain(&profile, &attacker_manifest, &[]).is_err());

        let mut tampered = child_manifest;
        tampered.signature[0] ^= 1;
        let authorization = owner_identity
            .grant_epoch_key(
                &profile.vault_id,
                1,
                &key,
                child_identity.record("Child").unwrap(),
            )
            .unwrap();
        assert!(verify_manifest_chain(&profile, &tampered, &[authorization]).is_err());

        let old_authorization = owner_identity
            .grant_epoch_key(
                &profile.vault_id,
                1,
                &key,
                child_identity.record("Child").unwrap(),
            )
            .unwrap();
        let epoch_two_manifest = child_identity
            .sign(
                ManifestDraft {
                    vault_id: profile.vault_id.clone(),
                    epoch: 2,
                    parents: vec![],
                    object_ids: vec![],
                    tombstones: vec![],
                    device_id: child_identity.record("Child").unwrap().device_id,
                    sequence: 1,
                }
                .finalize()
                .unwrap(),
            )
            .unwrap();
        let mut epoch_two_profile = profile.clone();
        epoch_two_profile.epoch = 2;
        assert!(verify_manifest_chain(
            &epoch_two_profile,
            &epoch_two_manifest,
            &[old_authorization],
        )
        .is_err());
    }

    #[test]
    fn upload_result_stays_anchored_to_the_revision_the_client_signed() {
        let identity = DeviceIdentity::generate().unwrap();
        let device = identity.record("Owner").unwrap();
        let profile = SyncProfile::new(
            "https://sync.example".into(),
            "vault:0123456789abcdef".into(),
            device,
            &identity,
            "owner-device-token-with-at-least-32-bytes".into(),
            &EpochKey::from_bytes([67; 32]),
            false,
        )
        .unwrap();
        let committed = format!("revision:{}", "a".repeat(64));
        let substituted = format!("revision:{}", "b".repeat(64));
        let run = finish_upload(
            profile,
            1,
            committed.clone(),
            "c".repeat(64),
            VaultStatus {
                epoch: 1,
                used_bytes: 1,
                quota_bytes: 10,
                heads: vec![substituted.clone()],
                active_devices: 1,
                object_count: 1,
                manifest_count: 1,
                manifest_bytes: 1,
            },
        )
        .unwrap();

        assert_eq!(run.report.state, "conflict");
        assert!(run.report.uploaded);
        assert!(run.own_upload_committed);
        assert_eq!(run.report.heads, [substituted]);
        assert_eq!(run.profile.heads, [committed]);
        assert_eq!(run.profile.next_sequence, 2);
    }

    #[test]
    fn only_confirmed_upload_results_acknowledge_a_checkpoint() {
        let identity = DeviceIdentity::generate().unwrap();
        let profile = SyncProfile::new(
            "https://sync.example".into(),
            "vault:0123456789abcdef".into(),
            identity.record("Owner").unwrap(),
            &identity,
            "owner-device-token-with-at-least-32-bytes".into(),
            &EpochKey::from_bytes([70; 32]),
            false,
        )
        .unwrap();
        let committed = format!("revision:{}", "a".repeat(64));
        let conflict = conflict_run(profile.clone(), 1, vec![committed.clone()]);
        assert!(!conflict.own_upload_committed);
        let run = finish_upload(
            profile,
            1,
            committed.clone(),
            "b".repeat(64),
            VaultStatus {
                epoch: 1,
                used_bytes: 1,
                quota_bytes: 10,
                heads: vec![committed],
                active_devices: 1,
                object_count: 1,
                manifest_count: 1,
                manifest_bytes: 1,
            },
        )
        .unwrap();
        assert!(run.own_upload_committed);
        assert!(run.remote_snapshot.is_none());
        assert_eq!(run.report.state, "uploaded");
    }

    #[test]
    fn initial_pairing_checkpoint_rejects_an_empty_server_rollback() {
        let identity = DeviceIdentity::generate().unwrap();
        let device = identity.record("Recipient").unwrap();
        let mut profile = SyncProfile::new(
            "https://sync.example".into(),
            "vault:0123456789abcdef".into(),
            device,
            &identity,
            "recipient-device-token-with-at-least-32-bytes".into(),
            &EpochKey::from_bytes([68; 32]),
            false,
        )
        .unwrap();
        profile.initial_download_pending = true;
        profile.pairing_heads = vec![format!("revision:{}", "d".repeat(64))];

        assert!(initial_checkpoint_mismatch(&profile, &[]));
        assert!(!initial_checkpoint_mismatch(
            &profile,
            &profile.pairing_heads
        ));
    }

    #[test]
    fn interrupted_commit_is_reconciled_only_for_the_expected_snapshot_and_sequence() {
        let identity = DeviceIdentity::generate().unwrap();
        let device = identity.record("Owner").unwrap();
        let profile = SyncProfile::new(
            "https://sync.example".into(),
            "vault:0123456789abcdef".into(),
            device.clone(),
            &identity,
            "owner-device-token-with-at-least-32-bytes".into(),
            &EpochKey::from_bytes([69; 32]),
            false,
        )
        .unwrap();
        let manifest = identity
            .sign(
                ManifestDraft {
                    vault_id: profile.vault_id.clone(),
                    epoch: profile.epoch,
                    parents: profile.heads.clone(),
                    object_ids: vec![format!("object:{}", "e".repeat(64))],
                    tombstones: vec![],
                    device_id: device.device_id,
                    sequence: profile.next_sequence,
                }
                .finalize()
                .unwrap(),
            )
            .unwrap();

        assert!(matches_ambiguous_upload(
            &profile,
            &manifest,
            &"f".repeat(64),
            Some(&"f".repeat(64)),
        ));
        assert!(!matches_ambiguous_upload(
            &profile,
            &manifest,
            &"f".repeat(64),
            Some(&"0".repeat(64)),
        ));
        let mut wrong_sequence = manifest;
        wrong_sequence.manifest.sequence += 1;
        assert!(!matches_ambiguous_upload(
            &profile,
            &wrong_sequence,
            &"f".repeat(64),
            Some(&"f".repeat(64)),
        ));
    }
}
