import { describe, expect, it } from 'vitest';
import { fieldFingerprint, safeField, validateApply, validatePreview, type FieldDescriptor, type FillPreview, type OriginGrant } from './policy';

const field = (overrides: Partial<FieldDescriptor> = {}): FieldDescriptor => ({
  fieldId: 'field:1', tag: 'input', type: 'text', name: 'full_name', autocomplete: 'name',
  disabled: false, readOnly: false, hidden: false, frameOrigin: 'https://forms.example', ...overrides,
});
const grant: OriginGrant = {
  id: 'grant:1', topOrigin: 'https://forms.example', frameOrigins: ['https://forms.example'],
  documentToken: 'document:1', approvedClaimIds: ['claim:1'], issuedAtMs: 100, expiresAtMs: 200,
};
const preview = (fields: FieldDescriptor[]): FillPreview => ({
  protocolVersion: 1, grantId: grant.id, topOrigin: grant.topOrigin,
  documentToken: grant.documentToken, domRevision: 3, fieldFingerprint: fieldFingerprint(fields),
  mappings: [{fieldId: 'field:1', claimId: 'claim:1', confidenceMilli: 900}], createdAtMs: 120,
});

describe('extension fill policy', () => {
  it('accepts only an exact approved preview', () => {
    const fields = [field()];
    expect(validatePreview(preview(fields), grant, [{id: 'claim:1', label: 'Name', value: 'An'}], fields, 150)).toBe(true);
    expect(validateApply(preview(fields), 'document:1', 3, grant.topOrigin, fields)).toBe(true);
  });

  it.each([
    {type: 'password'}, {type: 'hidden'}, {type: 'file'}, {autocomplete: 'cc-number'},
    {autocomplete: 'one-time-code'}, {name: 'billing_cvv'}, {hidden: true}, {readOnly: true},
    {disabled: true}, {frameOrigin: 'http://forms.example'},
  ])('rejects hostile or sensitive fields %#', (change) => expect(safeField(field(change))).toBe(false));

  it('invalidates navigation, DOM mutation, expiry, frame swaps, and unapproved claims', () => {
    const fields = [field()];
    const exact = preview(fields);
    expect(validateApply(exact, 'new-document', 3, grant.topOrigin, fields)).toBe(false);
    expect(validateApply(exact, 'document:1', 4, grant.topOrigin, fields)).toBe(false);
    expect(validateApply(exact, 'document:1', 3, 'https://evil.example', fields)).toBe(false);
    expect(validateApply(exact, 'document:1', 3, grant.topOrigin, [field({name: 'changed'})])).toBe(false);
    expect(validatePreview(exact, grant, [{id: 'claim:1', label: 'Name', value: 'An'}], fields, 201)).toBe(false);
    expect(validatePreview({...exact, mappings: [{...exact.mappings[0], claimId: 'claim:2'}]}, grant, [{id: 'claim:2', label: 'Other', value: 'X'}], fields, 150)).toBe(false);
  });

  it('rejects an extra claim outside the frozen approved subset', () => {
    const fields = [field()];
    expect(validatePreview(preview(fields), grant, [
      {id: 'claim:1', label: 'Name', value: 'An'},
      {id: 'claim:2', label: 'Unapproved', value: 'Must not cross the bridge'},
    ], fields, 150)).toBe(false);
  });
});
