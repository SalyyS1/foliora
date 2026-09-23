export const PROTOCOL_VERSION = 1;
export const MAX_MAPPINGS = 100;
export const MAX_VALUE_LENGTH = 10_000;

export interface FrozenClaim {
  id: string;
  label: string;
  value: string;
}

export interface FieldDescriptor {
  fieldId: string;
  tag: 'input' | 'textarea' | 'select';
  type: string;
  name: string;
  autocomplete: string;
  disabled: boolean;
  readOnly: boolean;
  hidden: boolean;
  frameOrigin: string;
}

export interface Mapping {
  fieldId: string;
  claimId: string;
  confidenceMilli: number;
}

export interface OriginGrant {
  id: string;
  topOrigin: string;
  frameOrigins: string[];
  documentToken: string;
  approvedClaimIds: string[];
  issuedAtMs: number;
  expiresAtMs: number;
}

export interface FillPreview {
  protocolVersion: number;
  grantId: string;
  topOrigin: string;
  documentToken: string;
  domRevision: number;
  fieldFingerprint: string;
  mappings: Mapping[];
  createdAtMs: number;
}

const forbiddenAutocomplete = /(?:^|\s)(?:current-password|new-password|one-time-code|cc-[^\s]+)(?:\s|$)/i;
const forbiddenName = /(?:password|passwd|card.?number|credit.?card|cvv|cvc|security.?code|iban|routing|bank.?account)/i;
const allowedInputTypes = new Set(['text', 'email', 'tel', 'url', 'date', 'month', 'number', 'search']);

export function validWebOrigin(origin: string): boolean {
  try {
    const parsed = new URL(origin);
    return parsed.origin === origin && parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

export function safeField(field: FieldDescriptor): boolean {
  if (!validWebOrigin(field.frameOrigin) || field.disabled || field.readOnly || field.hidden) return false;
  if (field.tag === 'input' && !allowedInputTypes.has(field.type.toLowerCase())) return false;
  return !forbiddenAutocomplete.test(field.autocomplete) && !forbiddenName.test(field.name);
}

export function fieldFingerprint(fields: FieldDescriptor[]): string {
  return fields.map((field) => [
    field.fieldId, field.tag, field.type.toLowerCase(), field.name,
    field.autocomplete.toLowerCase(), field.frameOrigin,
    Number(field.disabled), Number(field.readOnly), Number(field.hidden),
  ].join('\u001f')).sort().join('\u001e');
}

export function validatePreview(
  preview: FillPreview,
  grant: OriginGrant,
  claims: FrozenClaim[],
  fields: FieldDescriptor[],
  nowMs: number,
): boolean {
  if (preview.protocolVersion !== PROTOCOL_VERSION
    || preview.grantId !== grant.id
    || preview.topOrigin !== grant.topOrigin
    || preview.documentToken !== grant.documentToken
    || preview.createdAtMs < grant.issuedAtMs
    || nowMs > grant.expiresAtMs
    || preview.domRevision < 0
    || preview.fieldFingerprint !== fieldFingerprint(fields)
    || preview.mappings.length === 0
    || preview.mappings.length > MAX_MAPPINGS) return false;
  if (!validWebOrigin(grant.topOrigin) || !grant.frameOrigins.every(validWebOrigin)) return false;
  const claimIds = new Set(claims.map((claim) => claim.id));
  const approved = new Set(grant.approvedClaimIds);
  const byField = new Map(fields.map((field) => [field.fieldId, field]));
  const seenFields = new Set<string>();
  return claimIds.size === claims.length
    && claims.every((claim) => approved.has(claim.id) && claim.value.length <= MAX_VALUE_LENGTH)
    && preview.mappings.every((mapping) => {
      const field = byField.get(mapping.fieldId);
      if (!field || seenFields.has(mapping.fieldId)) return false;
      seenFields.add(mapping.fieldId);
      return safeField(field)
        && grant.frameOrigins.includes(field.frameOrigin)
        && claimIds.has(mapping.claimId) && approved.has(mapping.claimId)
        && mapping.confidenceMilli >= 0 && mapping.confidenceMilli <= 1000;
    });
}

export function validateApply(
  preview: FillPreview,
  currentDocumentToken: string,
  currentDomRevision: number,
  currentTopOrigin: string,
  currentFields: FieldDescriptor[],
): boolean {
  return preview.documentToken === currentDocumentToken
    && preview.domRevision === currentDomRevision
    && preview.topOrigin === currentTopOrigin
    && preview.fieldFingerprint === fieldFingerprint(currentFields);
}
