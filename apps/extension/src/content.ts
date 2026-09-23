import type { FieldDescriptor, FillPreview } from './policy';

declare global {
  interface Window { __folioraContentReady?: boolean }
}

if (!window.__folioraContentReady) {
  window.__folioraContentReady = true;
  const documentToken = `document:${crypto.randomUUID()}`;
  const ids = new WeakMap<Element, string>();
  let nextId = 1;
  let domRevision = 0;
  const observer = new MutationObserver(() => { domRevision += 1; });
  observer.observe(document.documentElement, {
    childList: true, subtree: true, attributes: true,
    attributeFilter: ['type', 'name', 'autocomplete', 'disabled', 'readonly', 'hidden', 'style', 'class'],
  });

  chrome.runtime.onMessage.addListener((message: unknown, sender, respond) => {
    if (sender.id !== chrome.runtime.id || !isRecord(message)) return false;
    if (message.type === 'foliora.inspect') {
      respond(snapshot());
      return false;
    }
    if (message.type === 'foliora.apply') {
      respond(apply(message.preview, message.values));
      return false;
    }
    return false;
  });

  function snapshot() {
    const fields = supportedElements().map(describe);
    return {
      documentToken, domRevision, topOrigin: location.origin,
      fieldFingerprint: fingerprint(fields), fields,
    };
  }

  function apply(rawPreview: unknown, rawValues: unknown) {
    if (!isPreview(rawPreview) || !isRecord(rawValues)) return {ok: false, reason: 'invalid-request'};
    const current = snapshot();
    if (rawPreview.documentToken !== documentToken
      || rawPreview.domRevision !== domRevision
      || rawPreview.topOrigin !== location.origin
      || rawPreview.fieldFingerprint !== current.fieldFingerprint) {
      return {ok: false, reason: 'stale-preview'};
    }
    const approvedFields = new Set(rawPreview.mappings.map((mapping) => mapping.fieldId));
    let filled = 0;
    for (const element of supportedElements()) {
      const descriptor = describe(element);
      const value = rawValues[descriptor.fieldId];
      if (!approvedFields.has(descriptor.fieldId) || typeof value !== 'string' || !safe(descriptor)) continue;
      if (setValue(element, value)) filled += 1;
    }
    return {ok: true, filled};
  }

  function supportedElements(): Array<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement> {
    return Array.from(document.querySelectorAll<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>('input, textarea, select'));
  }

  function describe(element: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement): FieldDescriptor {
    let fieldId = ids.get(element);
    if (!fieldId) { fieldId = `field:${nextId++}`; ids.set(element, fieldId); }
    const tag = element.tagName.toLowerCase() as FieldDescriptor['tag'];
    return {
      fieldId, tag, type: tag === 'input' ? (element as HTMLInputElement).type : tag,
      name: element.name || element.id || '', autocomplete: element.autocomplete || '',
      disabled: element.disabled, readOnly: 'readOnly' in element && element.readOnly,
      hidden: element.hidden || element.getAttribute('aria-hidden') === 'true' || element.getClientRects().length === 0,
      frameOrigin: location.origin,
    };
  }
}

function safe(field: FieldDescriptor): boolean {
  const allowed = new Set(['text', 'email', 'tel', 'url', 'date', 'month', 'number', 'search']);
  return location.protocol === 'https:' && !field.disabled && !field.readOnly && !field.hidden
    && (field.tag !== 'input' || allowed.has(field.type.toLowerCase()))
    && !/(?:current-password|new-password|one-time-code|cc-)/i.test(field.autocomplete)
    && !/(?:password|passwd|card.?number|credit.?card|cvv|cvc|security.?code|iban|routing|bank.?account)/i.test(field.name);
}

function fingerprint(fields: FieldDescriptor[]): string {
  return fields.map((field) => [field.fieldId, field.tag, field.type.toLowerCase(), field.name, field.autocomplete.toLowerCase(), field.frameOrigin, Number(field.disabled), Number(field.readOnly), Number(field.hidden)].join('\u001f')).sort().join('\u001e');
}

function setValue(element: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement, value: string): boolean {
  if (element instanceof HTMLSelectElement) {
    if (!Array.from(element.options).some((option) => option.value === value)) return false;
    element.value = value;
  } else {
    const prototype = element instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(prototype, 'value')?.set;
    if (!setter) return false;
    setter.call(element, value);
  }
  element.dispatchEvent(new Event('input', {bubbles: true}));
  element.dispatchEvent(new Event('change', {bubbles: true}));
  return true;
}

function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === 'object' && value !== null;
}

function isPreview(value: unknown): value is FillPreview {
  return isRecord(value) && Array.isArray(value.mappings)
    && value.mappings.every((mapping) => isRecord(mapping) && typeof mapping.fieldId === 'string');
}
