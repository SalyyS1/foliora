import { validateApply, validatePreview, type FieldDescriptor, type FillPreview, type FrozenClaim, type OriginGrant } from './policy';

const NATIVE_HOST = 'app.foliora.desktop';
const pending = new Map<number, {grant: OriginGrant; claims: FrozenClaim[]; preview: FillPreview; fields: FieldDescriptor[]}>();

chrome.runtime.onMessage.addListener((message: unknown, sender, respond) => {
  if (sender.id !== chrome.runtime.id || !isRecord(message)) return false;
  if (message.type === 'foliora.prepare') {
    void prepare().then(respond, (error) => respond({ok: false, error: safeError(error)}));
    return true;
  }
  if (message.type === 'foliora.fill') {
    void fill(message.mappingIndexes).then(respond, (error) => respond({ok: false, error: safeError(error)}));
    return true;
  }
  return false;
});

async function prepare() {
  const tab = await activeTab();
  if (!tab.id || !tab.url || new URL(tab.url).protocol !== 'https:') throw new Error('Open an HTTPS form first.');
  await chrome.scripting.executeScript({target: {tabId: tab.id}, files: ['content.js']});
  const inspected = await chrome.tabs.sendMessage(tab.id, {type: 'foliora.inspect'}) as Inspection;
  const response = await nativeMessage({
    type: 'prepareFillPreview', protocolVersion: 1, tabId: tab.id,
    topOrigin: inspected.topOrigin, documentToken: inspected.documentToken,
    domRevision: inspected.domRevision, fieldFingerprint: inspected.fieldFingerprint, fields: inspected.fields,
  }) as NativePreview;
  if (!response || response.type !== 'fillPreview'
    || !validatePreview(response.preview, response.grant, response.claims, inspected.fields, Date.now())) {
    throw new Error('The desktop app returned an invalid or expired preview.');
  }
  pending.set(tab.id, {grant: response.grant, claims: response.claims, preview: response.preview, fields: inspected.fields});
  return {
    ok: true,
    rows: response.preview.mappings.map((mapping, index) => {
      const claim = response.claims.find((item) => item.id === mapping.claimId)!;
      const field = inspected.fields.find((item) => item.fieldId === mapping.fieldId)!;
      return {index, label: claim.label, value: claim.value, field: field.name || field.type, confidenceMilli: mapping.confidenceMilli};
    }),
  };
}

async function fill(rawIndexes: unknown) {
  if (!Array.isArray(rawIndexes) || !rawIndexes.every(Number.isSafeInteger)) throw new Error('Choose valid preview rows.');
  const tab = await activeTab();
  if (!tab.id || !tab.url) throw new Error('The original tab is unavailable.');
  const prepared = pending.get(tab.id);
  if (!prepared) throw new Error('Preview the fields again.');
  const current = await chrome.tabs.sendMessage(tab.id, {type: 'foliora.inspect'}) as Inspection;
  if (!validatePreview(prepared.preview, prepared.grant, prepared.claims, current.fields, Date.now())
    || !validateApply(prepared.preview, current.documentToken, current.domRevision, current.topOrigin, current.fields)) {
    pending.delete(tab.id);
    throw new Error('The page changed. Preview it again before filling.');
  }
  const selected = new Set(rawIndexes as number[]);
  const mappings = prepared.preview.mappings.filter((_, index) => selected.has(index));
  if (!mappings.length) throw new Error('Choose at least one field.');
  const claims = new Map(prepared.claims.map((claim) => [claim.id, claim.value]));
  const values = Object.fromEntries(mappings.map((mapping) => [mapping.fieldId, claims.get(mapping.claimId)]));
  const result = await chrome.tabs.sendMessage(tab.id, {type: 'foliora.apply', preview: {...prepared.preview, mappings}, values});
  pending.delete(tab.id);
  return result;
}

async function activeTab(): Promise<chrome.tabs.Tab> {
  const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
  if (!tab) throw new Error('No active tab.');
  return tab;
}

function nativeMessage(message: object): Promise<unknown> {
  return new Promise((resolve, reject) => chrome.runtime.sendNativeMessage(NATIVE_HOST, message, (response) => {
    const error = chrome.runtime.lastError;
    if (error) reject(new Error('Open and unlock Foliora Desktop, then try again.'));
    else resolve(response);
  }));
}

function safeError(error: unknown): string { return error instanceof Error ? error.message : 'Could not complete the request.'; }
function isRecord(value: unknown): value is Record<string, any> { return typeof value === 'object' && value !== null; }

interface Inspection { documentToken: string; domRevision: number; topOrigin: string; fieldFingerprint: string; fields: FieldDescriptor[] }
interface NativePreview { type: 'fillPreview'; grant: OriginGrant; claims: FrozenClaim[]; preview: FillPreview }
