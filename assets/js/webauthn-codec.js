/**
 * Decoding helpers for the raw WebAuthn structures: authenticator data,
 * COSE keys, and the DER-wrapped ECDSA signatures that WebCrypto refuses
 * to verify until they are unwrapped into raw r‖s form.
 */

import { b64uEncode, bytes, toHex } from './util.js';
import { decode } from './cbor.js';

export const COSE_ALG = {
  ES256: -7,
  EdDSA: -8,
  RS256: -257,
};

export const ALG_LABELS = {
  '-7': 'ES256 (ECDSA P-256 / SHA-256)',
  '-8': 'EdDSA (Ed25519)',
  '-257': 'RS256 (RSASSA-PKCS1-v1_5 / SHA-256)',
};

/**
 * Authenticator data layout (WebAuthn Level 3, §6.1):
 *   rpIdHash (32) ‖ flags (1) ‖ signCount (4) ‖ [attestedCredentialData] ‖ [extensions]
 */
export function parseAuthenticatorData(input) {
  const data = bytes(input);
  if (data.length < 37) throw new RangeError('authenticatorData is shorter than 37 bytes');

  const rpIdHash = data.subarray(0, 32);
  const flagsByte = data[32];
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const signCount = view.getUint32(33);

  const flags = {
    byte: flagsByte,
    userPresent: Boolean(flagsByte & 0x01),
    userVerified: Boolean(flagsByte & 0x04),
    backupEligible: Boolean(flagsByte & 0x08),
    backupState: Boolean(flagsByte & 0x10),
    attestedCredentialData: Boolean(flagsByte & 0x40),
    extensionData: Boolean(flagsByte & 0x80),
  };

  const result = { rpIdHash, flags, signCount, raw: data };

  if (flags.attestedCredentialData) {
    const aaguid = data.subarray(37, 53);
    const credentialIdLength = view.getUint16(53);
    const credentialId = data.subarray(55, 55 + credentialIdLength);
    const rest = data.subarray(55 + credentialIdLength);
    result.aaguid = aaguid;
    result.aaguidFormatted = formatAaguid(aaguid);
    result.credentialId = credentialId;
    result.coseKey = decode(rest); // trailing extension bytes are ignored
  }

  return result;
}

export function formatAaguid(input) {
  const hex = toHex(input);
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join('-');
}

/** COSE_Key (RFC 8152) -> JWK, for the two key types passkeys actually use. */
export function coseKeyToJwk(coseKey) {
  const map = coseKey instanceof Map ? coseKey : new Map(Object.entries(coseKey));
  const kty = map.get(1);
  const alg = map.get(3);

  if (kty === 2) {
    const crvId = map.get(-1);
    const curves = { 1: 'P-256', 2: 'P-384', 3: 'P-521' };
    const crv = curves[crvId];
    if (!crv) throw new RangeError(`Unsupported COSE EC2 curve ${crvId}`);
    return {
      jwk: { kty: 'EC', crv, x: b64uEncode(map.get(-2)), y: b64uEncode(map.get(-3)), ext: true },
      alg: alg ?? COSE_ALG.ES256,
    };
  }

  if (kty === 3) {
    return {
      jwk: { kty: 'RSA', n: b64uEncode(map.get(-1)), e: b64uEncode(map.get(-2)), ext: true },
      alg: alg ?? COSE_ALG.RS256,
    };
  }

  if (kty === 1) {
    return {
      jwk: { kty: 'OKP', crv: 'Ed25519', x: b64uEncode(map.get(-2)), ext: true },
      alg: alg ?? COSE_ALG.EdDSA,
    };
  }

  throw new RangeError(`Unsupported COSE key type ${kty}`);
}

/** WebCrypto import parameters for a COSE algorithm identifier. */
export function importParamsFor(alg) {
  switch (alg) {
    case COSE_ALG.ES256:
      return { importAlgorithm: { name: 'ECDSA', namedCurve: 'P-256' }, verifyAlgorithm: { name: 'ECDSA', hash: 'SHA-256' } };
    case COSE_ALG.RS256:
      return {
        importAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        verifyAlgorithm: { name: 'RSASSA-PKCS1-v1_5' },
      };
    case COSE_ALG.EdDSA:
      return { importAlgorithm: { name: 'Ed25519' }, verifyAlgorithm: { name: 'Ed25519' } };
    default:
      throw new RangeError(`Unsupported COSE algorithm ${alg}`);
  }
}

/**
 * ECDSA signatures arrive DER-encoded (SEQUENCE of two INTEGERs); WebCrypto
 * expects the fixed-width r‖s concatenation instead.
 */
export function derToRawEcdsaSignature(input, componentLength = 32) {
  const der = bytes(input);
  if (der[0] !== 0x30) throw new RangeError('ECDSA signature is not a DER SEQUENCE');

  let offset = 2;
  if (der[1] & 0x80) offset = 2 + (der[1] & 0x7f); // long-form length

  const readInteger = () => {
    if (der[offset] !== 0x02) throw new RangeError('ECDSA signature: expected DER INTEGER');
    const length = der[offset + 1];
    let value = der.subarray(offset + 2, offset + 2 + length);
    offset += 2 + length;
    while (value.length > componentLength && value[0] === 0x00) value = value.subarray(1);
    if (value.length > componentLength) throw new RangeError('ECDSA signature component too long');
    const padded = new Uint8Array(componentLength);
    padded.set(value, componentLength - value.length);
    return padded;
  };

  const r = readInteger();
  const s = readInteger();
  const raw = new Uint8Array(componentLength * 2);
  raw.set(r, 0);
  raw.set(s, componentLength);
  return raw;
}

export function describeFlags(flags) {
  return [
    { key: 'UP', label: 'User present', value: flags.userPresent },
    { key: 'UV', label: 'User verified', value: flags.userVerified },
    { key: 'BE', label: 'Backup eligible', value: flags.backupEligible },
    { key: 'BS', label: 'Backed up (synced)', value: flags.backupState },
    { key: 'AT', label: 'Attested credential data', value: flags.attestedCredentialData },
    { key: 'ED', label: 'Extension data', value: flags.extensionData },
  ];
}
