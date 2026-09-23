import assert from 'node:assert/strict';
import { protocolVersion, validateEncryptedObject, validateSignedManifest, validateSignedPairingGrant } from './index.js';

const hex = '0'.repeat(64);
const object = {
  protocolVersion,
  vaultId: 'vault:test',
  epoch: 1,
  objectId: `object:${hex}`,
  nonce: Array(24).fill(0),
  ciphertext: Buffer.alloc(17, 1).toString('base64'),
};
assert.equal(validateEncryptedObject(object), true);
assert.equal(validateEncryptedObject({...object, epoch: 0}), false);
assert.equal(validateEncryptedObject({...object, nonce: [0]}), false);
assert.equal(validateEncryptedObject({...object, ciphertext: 'not base64'}), false);
assert.equal(validateEncryptedObject({
  ...object,
  ciphertext: 'AAAAAAAAAAAAAAAAAAAAAAB=',
}), false);
assert.equal(validateEncryptedObject({...object, ciphertext: Array(17).fill(1)}), true);
assert.equal(validateEncryptedObject({...object, vaultId: 'vault:bad/slash'}), false);

const signed = {
  manifest: {
    protocolVersion,
    revisionId: `revision:${hex}`,
    vaultId: 'vault:test',
    epoch: 1,
    parents: [],
    objectIds: [`object:${hex}`],
    tombstones: [],
    deviceId: `device:${hex}`,
    sequence: 1,
  },
  signature: Array(64).fill(0),
};
assert.equal(validateSignedManifest(signed), true);
assert.equal(validateSignedManifest({...signed, signature: [0]}), false);
assert.equal(validateSignedManifest({
  ...signed,
  manifest: {...signed.manifest, objectIds: [`object:${'1'.repeat(64)}`, `object:${hex}`]},
}), false);
assert.equal(validateSignedManifest({
  ...signed,
  manifest: {...signed.manifest, tombstones: ['bad tombstone']},
}), false);

const pairing = {
  grant: {
    protocolVersion,
    vaultId: 'vault:test',
    epoch: 1,
    authorizingDeviceId: `device:${hex}`,
    recipient: {
      deviceId: `device:${'1'.repeat(64)}`,
      label: 'Phone',
      publicKey: Array(32).fill(1),
      exchangePublicKey: Array(32).fill(2),
    },
    trustedDevices: [{
      deviceId: `device:${hex}`,
      label: 'Owner',
      publicKey: Array(32).fill(6),
      exchangePublicKey: Array(32).fill(7),
    }],
    heads: [`revision:${hex}`],
    nonce: Array(24).fill(3),
    encryptedEpochKey: Array(48).fill(4),
  },
  signature: Array(64).fill(5),
};
assert.equal(validateSignedPairingGrant(pairing), true);
assert.equal(validateSignedPairingGrant({...pairing, signature: []}), false);
assert.equal(validateSignedPairingGrant({
  ...pairing,
  grant: {...pairing.grant, trustedDevices: [...pairing.grant.trustedDevices, pairing.grant.trustedDevices[0]]},
}), false);

console.log('Sync protocol shape conformance passed.');
