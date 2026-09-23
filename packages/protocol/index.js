export const protocolVersion = 1;
export const maxObjectBytes = 25 * 1024 * 1024;
export const maxManifestObjects = 10_000;

const hashId = (prefix, value) => typeof value === 'string'
  && new RegExp(`^${prefix}[0-9a-f]{64}$`).test(value);
const sortedUnique = (values) => values.every((value, index) => index === 0 || values[index - 1] < value);
const opaqueId = (value) => typeof value === 'string'
  && /^[A-Za-z0-9:._-]{1,160}$/.test(value);
const vaultId = (value) => opaqueId(value) && value.startsWith('vault:') && value.length > 6;
const byteArray = (value, length) => Array.isArray(value)
  && value.length === length
  && value.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255);
const base64Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const base64ByteLength = (value) => {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0
      || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    return -1;
  }
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  if ((padding === 2 && (base64Alphabet.indexOf(value.at(-3)) & 15) !== 0)
      || (padding === 1 && (base64Alphabet.indexOf(value.at(-2)) & 3) !== 0)) {
    return -1;
  }
  return (value.length / 4) * 3 - padding;
};
const validCiphertext = (value) => {
  if (Array.isArray(value)) {
    return value.length > 16 && value.length <= maxObjectBytes + 16
      && value.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255);
  }
  const bytes = base64ByteLength(value);
  return bytes > 16 && bytes <= maxObjectBytes + 16;
};
const validDeviceRecord = (value) => hashId('device:', value?.deviceId)
  && typeof value.label === 'string' && value.label.trim().length > 0 && value.label.length <= 80
  && byteArray(value.publicKey, 32)
  && byteArray(value.exchangePublicKey, 32);

export function validateEncryptedObject(value) {
  return value?.protocolVersion === protocolVersion
    && vaultId(value.vaultId)
    && Number.isSafeInteger(value.epoch) && value.epoch > 0
    && hashId('object:', value.objectId)
    && byteArray(value.nonce, 24)
    && validCiphertext(value.ciphertext);
}

export function validateSignedManifest(value) {
  const manifest = value?.manifest;
  return manifest?.protocolVersion === protocolVersion
    && hashId('revision:', manifest.revisionId)
    && vaultId(manifest.vaultId)
    && Number.isSafeInteger(manifest.epoch) && manifest.epoch > 0
    && Number.isSafeInteger(manifest.sequence) && manifest.sequence > 0
    && hashId('device:', manifest.deviceId)
    && Array.isArray(manifest.parents) && manifest.parents.length <= 32
    && manifest.parents.every((id) => hashId('revision:', id)) && sortedUnique(manifest.parents)
    && Array.isArray(manifest.objectIds) && manifest.objectIds.length <= maxManifestObjects
    && manifest.objectIds.every((id) => hashId('object:', id)) && sortedUnique(manifest.objectIds)
    && Array.isArray(manifest.tombstones) && manifest.tombstones.length <= maxManifestObjects
    && manifest.tombstones.every(opaqueId) && sortedUnique(manifest.tombstones)
    && byteArray(value.signature, 64);
}

export function validateSignedPairingGrant(value) {
  const grant = value?.grant;
  const recipient = grant?.recipient;
  const trustedDevices = grant?.trustedDevices ?? [];
  const heads = grant?.heads ?? [];
  const trustedValid = Array.isArray(trustedDevices) && trustedDevices.length <= 64
    && trustedDevices.every(validDeviceRecord)
    && trustedDevices.every((device, index) => index === 0
      || trustedDevices[index - 1].deviceId < device.deviceId)
    && (trustedDevices.length === 0
      || (trustedDevices.some((device) => device.deviceId === grant.authorizingDeviceId)
        && trustedDevices.every((device) => device.deviceId !== recipient?.deviceId)));
  return grant?.protocolVersion === protocolVersion
    && vaultId(grant.vaultId)
    && Number.isSafeInteger(grant.epoch) && grant.epoch > 0
    && hashId('device:', grant.authorizingDeviceId)
    && validDeviceRecord(recipient)
    && grant.authorizingDeviceId !== recipient.deviceId
    && trustedValid
    && Array.isArray(heads) && heads.length <= 32
    && heads.every((id) => hashId('revision:', id)) && sortedUnique(heads)
    && byteArray(grant.nonce, 24)
    && byteArray(grant.encryptedEpochKey, 48)
    && byteArray(value.signature, 64);
}
