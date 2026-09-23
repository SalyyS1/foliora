import fs from 'node:fs';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const schema = JSON.parse(fs.readFileSync(new URL('./reviewed-bundle-v1.json', import.meta.url)));
const validFixture = JSON.parse(fs.readFileSync(new URL('../../tests/fixtures/reviewed-bundle-v1.json', import.meta.url)));
const ajv = new Ajv2020({allErrors: true, strict: true});
addFormats(ajv);
const validate = ajv.compile(schema);

if (!validate(validFixture)) {
  console.error(validate.errors);
  process.exit(1);
}

const invalidFixture = structuredClone(validFixture);
invalidFixture.claims[0].provenance.source_id = null;
if (validate(invalidFixture)) {
  console.error('Schema accepted provenance without a source or user-entered timestamp.');
  process.exit(1);
}

console.log('Reviewed bundle schema conformance passed.');
