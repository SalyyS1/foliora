import React, { FormEvent, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { invoke } from '@tauri-apps/api/core';
import './styles.css';
import { copy, type Copy, type Language } from './copy';
import { VaultWorkspace } from './vault-workspace';

type LockReason = 'startup' | 'manual' | 'idle';
type Snapshot =
  | { state: 'locked'; reason: LockReason; autoLockSeconds: number }
  | {
      state: 'unlocked';
      autoLockSeconds: number;
      vault: {
        path: string;
        sourceCount: number;
        claimCount: number;
        bundleCount: number;
        recoveryConfigured: boolean;
      };
    };

type Mode = 'open' | 'create' | 'restore' | 'recover';

type SyncConfiguration = {
  configured: boolean;
  endpoint: string | null;
  vaultId: string | null;
  deviceId: string | null;
  epoch: number | null;
  heads: string[];
};

type SyncReport = {
  state: string;
  uploaded: boolean;
  downloaded: boolean;
  epoch: number;
  heads: string[];
  detail: string;
};

type PairingGrantReceipt = {
  packageJson: string;
  confirmationCode: string;
};

function App() {
  const [language, setLanguage] = useState<Language>('vi');
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [mode, setMode] = useState<Mode>('open');
  const [path, setPath] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [restoreDestination, setRestoreDestination] = useState('');
  const [recoveryKitPath, setRecoveryKitPath] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [rememberOnDevice, setRememberOnDevice] = useState(false);
  const [keychainSaved, setKeychainSaved] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const t = copy[language];

  useEffect(() => {
    void refresh();
    const poll = window.setInterval(() => void refresh(), 15_000);
    return () => window.clearInterval(poll);
  }, []);

  useEffect(() => {
    setKeychainSaved(false);
    if (mode !== 'open' || !path.trim()) return;
    let current = true;
    const timer = window.setTimeout(() => {
      void invoke<boolean>('has_saved_vault_passphrase', { path })
        .then((saved) => { if (current) setKeychainSaved(saved); })
        .catch(() => { if (current) setKeychainSaved(false); });
    }, 220);
    return () => {
      current = false;
      window.clearTimeout(timer);
    };
  }, [mode, path]);

  async function refresh() {
    try {
      setSnapshot(await invoke<Snapshot>('session_snapshot'));
    } catch (reason) {
      setError(String(reason));
    }
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const targetPath = mode === 'restore' || mode === 'recover' ? restoreDestination : path;
      if (mode === 'recover') {
        setSnapshot(await invoke<Snapshot>('restore_vault_with_recovery', {
          backupPath: path, recoveryKitPath, destinationPath: restoreDestination,
          recoveryCode, newPassphrase: passphrase,
        }));
      } else if (mode === 'restore') {
        setSnapshot(await invoke<Snapshot>('restore_vault', {
          backupPath: path, destinationPath: restoreDestination, passphrase,
        }));
      } else {
        const command = mode === 'create' ? 'create_vault' : 'open_vault';
        setSnapshot(await invoke<Snapshot>(command, { path, passphrase }));
      }
      if (rememberOnDevice) {
        try {
          await invoke('remember_vault_passphrase', { path: targetPath, passphrase });
          setKeychainSaved(true);
        } catch (reason) {
          setError(String(reason));
        }
      }
      setPassphrase('');
      setRecoveryCode('');
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function unlockWithKeychain() {
    setBusy(true);
    setError('');
    try {
      setSnapshot(await invoke<Snapshot>('open_vault_with_keychain', { path }));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function forgetKeychainPassphrase() {
    setBusy(true);
    setError('');
    try {
      await invoke('forget_vault_passphrase', { path });
      setKeychainSaved(false);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function lock() {
    setError('');
    setSnapshot(await invoke<Snapshot>('lock_vault'));
  }

  async function changeAutoLock(minutes: number) {
    setError('');
    try {
      setSnapshot(await invoke<Snapshot>('set_auto_lock', { seconds: minutes * 60 }));
    } catch (reason) {
      setError(String(reason));
    }
  }

  return (
    <main>
      <header>
        <a className="brand" href="#top" aria-label="Foliora">
          <span className="mark" aria-hidden="true"><i /><i /></span>
          <span>foliora</span>
        </a>
        <button className="language" onClick={() => setLanguage(language === 'vi' ? 'en' : 'vi')}>
          {language === 'vi' ? 'EN' : 'VI'}
        </button>
      </header>

      <section className="hero" id="top">
        <p className="eyebrow">{t.eyebrow}</p>
        <h1>{t.title}</h1>
        <p className="subtitle">{t.subtitle}</p>
      </section>

      <section className="trust" aria-label="Privacy properties">
        {([
          ['01', t.local, t.localDetail],
          ['02', t.encrypted, t.encryptedDetail],
          ['03', t.noAccount, t.noAccountDetail],
        ] as const).map(([number, label, detail]) => (
          <article key={number}><b>{number}</b><div><strong>{label}</strong><span>{detail}</span></div></article>
        ))}
      </section>

      {snapshot?.state === 'unlocked' ? (
        <VaultHome snapshot={snapshot} t={t} onLock={() => void lock()} onAutoLock={(value) => void changeAutoLock(value)} onRefresh={refresh} />
      ) : (
        <section className="vault-panel" aria-live="polite">
          <div className="panel-intro">
            <span className="lock-icon" aria-hidden="true">⌁</span>
            <p>{snapshot ? t[`locked${snapshot.reason[0].toUpperCase()}${snapshot.reason.slice(1)}` as 'lockedIdle'] : t.lockedStartup}</p>
          </div>
          <div className="tabs" role="tablist">
            <button role="tab" aria-selected={mode === 'open'} onClick={() => setMode('open')}>{t.open}</button>
            <button role="tab" aria-selected={mode === 'create'} onClick={() => setMode('create')}>{t.create}</button>
            <button role="tab" aria-selected={mode === 'restore'} onClick={() => setMode('restore')}>{t.restore}</button>
            <button role="tab" aria-selected={mode === 'recover'} onClick={() => setMode('recover')}>{t.recover}</button>
          </div>
          <form onSubmit={(event) => void submit(event)}>
            <label>{mode === 'restore' || mode === 'recover' ? t.backupPath : t.path}<input value={path} onChange={(event) => setPath(event.target.value)} placeholder={mode === 'restore' || mode === 'recover' ? t.backupHint : t.pathHint} autoComplete="off" required /></label>
            {(mode === 'restore' || mode === 'recover') && <label>{t.restoreDestination}<input value={restoreDestination} onChange={(event) => setRestoreDestination(event.target.value)} placeholder={t.pathHint} autoComplete="off" required /></label>}
            {mode === 'recover' && <><label>{t.recoveryKitPath}<input value={recoveryKitPath} onChange={(event) => setRecoveryKitPath(event.target.value)} placeholder={t.recoveryHint} autoComplete="off" required /></label><label>{t.recoveryCode}<input value={recoveryCode} onChange={(event) => setRecoveryCode(event.target.value)} autoComplete="off" spellCheck={false} required /></label></>}
            <label>{mode === 'recover' ? t.newPassphrase : t.passphrase}<input type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} autoComplete={mode === 'create' || mode === 'recover' ? 'new-password' : 'current-password'} required /></label>
            <label className="checkbox-row"><input type="checkbox" checked={rememberOnDevice} onChange={(event) => setRememberOnDevice(event.target.checked)} />{t.rememberOnDevice}</label>
            {mode === 'open' && keychainSaved && <div className="keychain-actions">
              <button type="button" className="outline" disabled={busy} onClick={() => void unlockWithKeychain()}>{t.unlockWithDevice}</button>
              <button type="button" className="text-button" disabled={busy} onClick={() => void forgetKeychainPassphrase()}>{t.forgetDeviceUnlock}</button>
            </div>}
            {(mode === 'restore' || mode === 'recover') && <p className="form-note">{mode === 'recover' ? t.recoverSafety : t.restoreSafety}</p>}
            <button className="primary" disabled={busy}>{mode === 'create' ? t.submitCreate : mode === 'restore' ? t.restoreSubmit : mode === 'recover' ? t.recoverSubmit : t.submitOpen}</button>
          </form>
        </section>
      )}

      {error && <div className="error" role="alert"><strong>{t.error}</strong><span>{error}</span></div>}
    </main>
  );
}

function VaultHome({ snapshot, t, onLock, onAutoLock, onRefresh }: {
  snapshot: Extract<Snapshot, { state: 'unlocked' }>;
  t: Copy;
  onLock: () => void;
  onAutoLock: (minutes: number) => void;
  onRefresh: () => Promise<void>;
}) {
  type RecoveryResult = { path: string; bytes: number; recoveryCode: string; localRevocationComplete?: boolean };
  const [backupPath, setBackupPath] = useState('');
  const [backupBusy, setBackupBusy] = useState(false);
  const [backupResult, setBackupResult] = useState<{ path: string; bytes: number } | null>(null);
  const [backupError, setBackupError] = useState('');
  const [recoveryPath, setRecoveryPath] = useState('');
  const [recoveryResult, setRecoveryResult] = useState<RecoveryResult | null>(null);
  const [recoverySaved, setRecoverySaved] = useState(false);
  const [recoveryReady, setRecoveryReady] = useState(snapshot.vault.recoveryConfigured);
  const [rotationPassphrase, setRotationPassphrase] = useState('');

  async function createBackup(event: FormEvent) {
    event.preventDefault();
    setBackupBusy(true);
    setBackupError('');
    setBackupResult(null);
    try {
      setBackupResult(await invoke<{ path: string; bytes: number }>('create_vault_backup', { destinationPath: backupPath }));
    } catch (reason) {
      setBackupError(String(reason));
    } finally {
      setBackupBusy(false);
    }
  }

  async function createRecovery(event: FormEvent) {
    event.preventDefault();
    setBackupBusy(true);
    setBackupError('');
    setRecoveryResult(null);
    setRecoverySaved(false);
    try {
      setRecoveryResult(await invoke<RecoveryResult>('create_recovery_kit', { destinationPath: recoveryPath }));
    } catch (reason) {
      setBackupError(String(reason));
    } finally {
      setBackupBusy(false);
    }
  }

  async function confirmRecovery() {
    setBackupBusy(true);
    setBackupError('');
    try {
      await invoke<Snapshot>('confirm_recovery_saved');
      setRecoveryResult(null);
      setRecoverySaved(false);
      setRecoveryReady(true);
    } catch (reason) {
      setBackupError(String(reason));
    } finally {
      setBackupBusy(false);
    }
  }

  async function rotateRecovery(event: FormEvent) {
    event.preventDefault();
    setBackupBusy(true);
    setBackupError('');
    setRecoveryResult(null);
    setRecoverySaved(false);
    try {
      setRecoveryResult(await invoke<RecoveryResult>('rotate_recovery_key', {
        destinationPath: recoveryPath,
        passphrase: rotationPassphrase,
      }));
      setRotationPassphrase('');
      setRecoveryReady(false);
    } catch (reason) {
      setBackupError(String(reason));
    } finally {
      setBackupBusy(false);
    }
  }

  return (
    <section className="vault-home">
      <div className="vault-heading">
        <div><span className="status-dot" />{t.unlocked}<small title={snapshot.vault.path}>{snapshot.vault.path}</small></div>
        <button className="outline" onClick={onLock}>{t.lockNow}</button>
      </div>
      <div className="stats">
        <article><b>{snapshot.vault.sourceCount}</b><span>{t.sources}</span></article>
        <article><b>{snapshot.vault.claimCount}</b><span>{t.claims}</span></article>
        <article><b>{snapshot.vault.bundleCount}</b><span>{t.packs}</span></article>
      </div>
      <p className="empty-state">{t.empty}</p>
      <label className="auto-lock">{t.autoLock}
        <select value={snapshot.autoLockSeconds / 60} onChange={(event) => onAutoLock(Number(event.target.value))}>
          {[1, 5, 15, 30, 60].map((minutes) => <option key={minutes} value={minutes}>{minutes} {t.minutes}</option>)}
        </select>
      </label>
      <SyncPanel t={t} onRefresh={onRefresh} />
      {recoveryReady && <section className="backup-panel">
        <h3>{t.backupTitle}</h3>
        <p>{t.backupDescription}</p>
        <form onSubmit={(event) => void createBackup(event)}>
          <label>{t.backupDestination}<input value={backupPath} onChange={(event) => setBackupPath(event.target.value)} placeholder={t.backupHint} required /></label>
          <button className="outline" disabled={backupBusy}>{t.createBackup}</button>
        </form>
        {backupResult && <div className="backup-success" role="status"><strong>{t.backupComplete}</strong><span>{backupResult.path} · {formatBytes(backupResult.bytes)}</span></div>}
        {backupError && <div className="error" role="alert"><span>{backupError}</span></div>}
      </section>}
      <section className="backup-panel recovery-panel">
        <h3>{t.recoveryTitle}</h3>
        <p>{t.recoveryDescription}</p>
        <form onSubmit={(event) => void createRecovery(event)}>
          <label>{t.recoveryDestination}<input value={recoveryPath} onChange={(event) => setRecoveryPath(event.target.value)} placeholder={t.recoveryHint} required /></label>
          <button className="outline" disabled={backupBusy || !!recoveryResult}>{t.createRecovery}</button>
        </form>
        {recoveryResult && <div className="recovery-code" role="status">
          <strong>{t.recoveryCodeOnce}</strong><code>{recoveryResult.recoveryCode}</code><p>{t.recoveryWarning}</p>
          {recoveryResult.localRevocationComplete === false && <p className="critical-warning">{t.recoveryLocalCleanupWarning}</p>}
          <label><input type="checkbox" checked={recoverySaved} onChange={(event) => setRecoverySaved(event.target.checked)} />{t.recoverySaved}</label>
          <button className="primary" disabled={!recoverySaved || backupBusy} onClick={() => void confirmRecovery()}>{t.dismissRecovery}</button>
        </div>}
        {recoveryReady && <div className="recovery-rotate">
          <h4>{t.recoveryRotateTitle}</h4>
          <p>{t.recoveryRotateDescription}</p>
          <form onSubmit={(event) => void rotateRecovery(event)}>
            <label>{t.recoveryRotatePassphrase}<input type="password" value={rotationPassphrase} onChange={(event) => setRotationPassphrase(event.target.value)} placeholder={t.recoveryRotatePassphraseHint} autoComplete="current-password" required /></label>
            <button className="outline" disabled={backupBusy}>{t.rotateRecovery}</button>
          </form>
          <small>{t.recoveryRotationWarning}</small>
        </div>}
      </section>
      {recoveryReady ? <VaultWorkspace t={t} /> : <p className="recovery-required">{t.recoveryRequired}</p>}
    </section>
  );
}

function SyncPanel({ t, onRefresh }: { t: Copy; onRefresh: () => Promise<void> }) {
  const [configuration, setConfiguration] = useState<SyncConfiguration | null>(null);
  const [endpoint, setEndpoint] = useState('');
  const [bootstrapToken, setBootstrapToken] = useState('');
  const [deviceLabel, setDeviceLabel] = useState('');
  const [pairEndpoint, setPairEndpoint] = useState('');
  const [pairVaultId, setPairVaultId] = useState('');
  const [pairDeviceLabel, setPairDeviceLabel] = useState('');
  const [pairRequest, setPairRequest] = useState('');
  const [pairGrant, setPairGrant] = useState('');
  const [confirmationCode, setConfirmationCode] = useState('');
  const [grantReceipt, setGrantReceipt] = useState<PairingGrantReceipt | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [report, setReport] = useState<SyncReport | null>(null);

  useEffect(() => {
    void loadConfiguration();
  }, []);

  async function loadConfiguration() {
    try {
      setConfiguration(await invoke<SyncConfiguration>('sync_configuration'));
    } catch (reason) {
      setError(String(reason));
    }
  }

  async function configure(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const next = await invoke<SyncConfiguration>('configure_sync', {
        endpoint, bootstrapToken, deviceLabel, allowInsecureLoopback: false,
      });
      setConfiguration(next);
      setBootstrapToken('');
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function syncNow() {
    setBusy(true);
    setError('');
    try {
      setReport(await invoke<SyncReport>('sync_vault'));
      await loadConfiguration();
      await onRefresh();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function createPairingRequest(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      setPairRequest(await invoke<string>('create_pairing_request', {
        endpoint: pairEndpoint,
        vaultId: pairVaultId,
        deviceLabel: pairDeviceLabel,
        allowInsecureLoopback: false,
      }));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function authorizePairing(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    setGrantReceipt(null);
    try {
      setGrantReceipt(await invoke<PairingGrantReceipt>('authorize_pairing_request', { requestJson: pairRequest }));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function completePairing(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      setConfiguration(await invoke<SyncConfiguration>('complete_pairing', {
        packageJson: pairGrant,
        confirmationCode,
      }));
      setPairGrant('');
      setConfirmationCode('');
      await onRefresh();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  const stateCopy = report?.state === 'uploaded' ? t.syncUploaded
    : report?.state === 'downloaded' ? t.syncDownloaded
      : report?.state === 'conflict' ? t.syncConflict
        : report?.state === 'idle' ? t.syncIdle : report?.detail;

  return (
    <section className="sync-panel" aria-labelledby="sync-title">
      <div className="sync-heading">
        <div><h3 id="sync-title">{t.syncTitle}</h3><p>{t.syncDescription}</p></div>
        <span className={configuration?.configured ? 'sync-state ready' : 'sync-state'}>{configuration?.configured ? t.syncConfigured : t.syncNotConfigured}</span>
      </div>
      {!configuration?.configured ? (
        <>
          <form onSubmit={(event) => void configure(event)}>
            <label>{t.syncEndpoint}<input type="url" value={endpoint} onChange={(event) => setEndpoint(event.target.value)} placeholder={t.syncEndpointHint} autoComplete="url" required /></label>
            <label>{t.syncBootstrap}<input type="password" value={bootstrapToken} onChange={(event) => setBootstrapToken(event.target.value)} placeholder={t.syncBootstrapHint} autoComplete="off" required /></label>
            <label>{t.syncDeviceLabel}<input value={deviceLabel} onChange={(event) => setDeviceLabel(event.target.value)} placeholder={t.syncDeviceLabelHint} autoComplete="off" required /></label>
            <p className="form-note">{t.syncEndpointSecurity}</p>
            <button className="outline" disabled={busy}>{t.syncConfigure}</button>
          </form>
          <div className="sync-pairing">
            <h4>{t.syncPairingTitle}</h4><p>{t.syncPairingDescription}</p>
            <form onSubmit={(event) => void createPairingRequest(event)}>
              <label>{t.syncPairEndpoint}<input type="url" value={pairEndpoint} onChange={(event) => setPairEndpoint(event.target.value)} placeholder={t.syncEndpointHint} autoComplete="url" required /></label>
              <label>{t.syncPairVaultId}<input value={pairVaultId} onChange={(event) => setPairVaultId(event.target.value)} placeholder="vault:…" autoComplete="off" required /></label>
              <label>{t.syncDeviceLabel}<input value={pairDeviceLabel} onChange={(event) => setPairDeviceLabel(event.target.value)} placeholder={t.syncDeviceLabelHint} autoComplete="off" required /></label>
              <button className="outline" disabled={busy}>{t.syncCreateRequest}</button>
            </form>
            {pairRequest && <div className="sync-package"><strong>{t.syncPairRequest}</strong><textarea value={pairRequest} readOnly spellCheck={false} /><p>{t.syncRequestCreated}</p></div>}
            <form onSubmit={(event) => void completePairing(event)}>
              <label>{t.syncPairGrant}<textarea value={pairGrant} onChange={(event) => setPairGrant(event.target.value)} placeholder={t.syncPairGrantHint} required spellCheck={false} /></label>
              <label>{t.syncConfirmationCode}<input value={confirmationCode} onChange={(event) => setConfirmationCode(event.target.value)} placeholder={t.syncConfirmationHint} autoComplete="off" spellCheck={false} required /></label>
              <button className="outline" disabled={busy}>{t.syncCompletePairing}</button>
            </form>
          </div>
        </>
      ) : (
        <>
          <div className="sync-configured">
            <dl>
              <div><dt>{t.syncEndpoint}</dt><dd>{configuration.endpoint}</dd></div>
              <div><dt>Vault</dt><dd>{configuration.vaultId}</dd></div>
              <div><dt>Device</dt><dd>{configuration.deviceId}</dd></div>
            </dl>
            <button className="primary" onClick={() => void syncNow()} disabled={busy}>{t.syncNow}</button>
          </div>
          <div className="sync-pairing">
            <h4>{t.syncPairingTitle}</h4><p>{t.syncPairingDescription}</p>
            <form onSubmit={(event) => void authorizePairing(event)}>
              <label>{t.syncPairRequest}<textarea value={pairRequest} onChange={(event) => setPairRequest(event.target.value)} placeholder={t.syncPairRequestHint} required spellCheck={false} /></label>
              <button className="outline" disabled={busy}>{t.syncAuthorize}</button>
            </form>
            {grantReceipt && <div className="sync-package"><strong>{t.syncPairGrant}</strong><textarea value={grantReceipt.packageJson} readOnly spellCheck={false} /><strong>{t.syncConfirmationCode}: <code>{grantReceipt.confirmationCode}</code></strong><p>{t.syncGrantCreated}</p></div>}
          </div>
        </>
      )}
      {report && <div className={`sync-result ${report.state}`} role="status"><strong>{t.syncLastResult}</strong><span>{stateCopy}</span><small>{report.heads.length ? `${report.heads.length} head(s) · epoch ${report.epoch}` : `epoch ${report.epoch}`}</small></div>}
      {error && <div className="error" role="alert"><span>{error}</span></div>}
    </section>
  );
}

function formatBytes(bytes: number): string {
  return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KB`;
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>);
