import { invoke } from '@tauri-apps/api/core';
import { FormEvent, useMemo, useState } from 'react';
import type { Copy } from './copy';
import type { AuthorizedExtensionGrant, Claim, WorkspaceSnapshot } from './workspace-types';

const FIVE_MINUTES_MS = 5 * 60 * 1_000;

export function ExtensionAccess({ workspace, t, busy, setBusy, setError }: {
  workspace: WorkspaceSnapshot | null;
  t: Copy;
  busy: boolean;
  setBusy: (value: boolean) => void;
  setError: (value: string) => void;
}) {
  const [origin, setOrigin] = useState('');
  const [selected, setSelected] = useState<string[]>([]);
  const [grant, setGrant] = useState<AuthorizedExtensionGrant | null>(null);
  const conflicted = useMemo(() => new Set(workspace?.conflicts.flatMap((item) => item.claim_ids) ?? []), [workspace]);
  const eligible = (workspace?.claims ?? []).filter((claim) => eligibleClaim(claim, conflicted));

  function toggle(id: string) {
    setSelected((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id]);
    setGrant(null);
  }

  async function authorize(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      setGrant(await invoke<AuthorizedExtensionGrant>('authorize_extension_grant', {
        topOrigin: origin,
        approvedClaimIds: selected,
        lifetimeMs: FIVE_MINUTES_MS,
      }));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function revoke() {
    setBusy(true);
    setError('');
    try {
      await invoke('revoke_extension_grant');
      setGrant(null);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  return <section className="extension-access">
    <h3>{t.extensionTitle}</h3>
    <p>{t.extensionHelp}</p>
    <form onSubmit={(event) => void authorize(event)}>
      <label>{t.extensionOrigin}<input type="url" value={origin} placeholder={t.extensionOriginHint} onChange={(event) => { setOrigin(event.target.value); setGrant(null); }} required /></label>
      <fieldset><legend>{t.extensionClaims}</legend>
        {eligible.map((claim) => <label key={claim.id}>
          <input type="checkbox" checked={selected.includes(claim.id)} onChange={() => toggle(claim.id)} />
          <span><strong>{displayValue(claim.value)}</strong><small>{claim.claim_type}</small></span>
        </label>)}
        {!eligible.length && <p className="blank">{t.extensionNoEligible}</p>}
      </fieldset>
      <button className="outline" disabled={busy || selected.length === 0}>{t.extensionAuthorize}</button>
    </form>
    {grant && <div className="extension-grant" role="status"><div><strong>{t.extensionActive}</strong><span>{grant.topOrigin}</span><small>{new Date(grant.expiresAtMs).toLocaleTimeString()}</small></div><button onClick={() => void revoke()} disabled={busy}>{t.extensionRevoke}</button></div>}
  </section>;
}

function eligibleClaim(claim: Claim, conflicted: Set<string>): boolean {
  return claim.status === 'confirmed'
    && !conflicted.has(claim.id)
    && (typeof claim.value === 'string' || typeof claim.value === 'number' || typeof claim.value === 'boolean')
    && String(claim.value).length > 0;
}

function displayValue(value: unknown): string {
  return typeof value === 'string' ? value : JSON.stringify(value);
}
