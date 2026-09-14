/**
 * Small byte / encoding / formatting helpers shared by the demo.
 * Everything here is plain ES2020 so the site can be served as static files.
 */

export const textEncoder = new TextEncoder();
export const textDecoder = new TextDecoder();

/** Coerce ArrayBuffer | ArrayBufferView | Uint8Array into a Uint8Array view. */
export function bytes(input) {
  if (input instanceof Uint8Array) return input;
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  throw new TypeError('Expected ArrayBuffer or ArrayBufferView');
}

export function concatBytes(...parts) {
  const chunks = parts.map(bytes);
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export function bytesEqual(a, b) {
  const x = bytes(a);
  const y = bytes(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i += 1) diff |= x[i] ^ y[i];
  return diff === 0;
}

export function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function b64uEncode(input) {
  const view = bytes(input);
  let binary = '';
  for (let i = 0; i < view.length; i += 1) binary += String.fromCharCode(view[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64uDecode(value) {
  const normalised = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalised + '='.repeat((4 - (normalised.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

export function toHex(input, { groupsOf = 0 } = {}) {
  const view = bytes(input);
  let out = '';
  for (let i = 0; i < view.length; i += 1) {
    out += view[i].toString(16).padStart(2, '0');
    if (groupsOf && (i + 1) % groupsOf === 0 && i !== view.length - 1) out += ' ';
  }
  return out;
}

export async function sha256(input) {
  const digest = await crypto.subtle.digest('SHA-256', bytes(input));
  return new Uint8Array(digest);
}

/**
 * Deterministic JSON serialisation: object keys are emitted in lexicographic
 * order and no insignificant whitespace is produced. Two parties that hash a
 * transaction must agree byte-for-byte on its encoding, so the ordering rule
 * has to be part of the protocol rather than an accident of insertion order.
 */
export function canonicalJson(value) {
  if (value === null || typeof value === 'number' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  throw new TypeError(`Cannot canonicalise value of type ${typeof value}`);
}

export function prettyJson(value) {
  return JSON.stringify(value, null, 2);
}

export function nowIso() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export function formatMoney(amount, currency) {
  const numeric = Number(amount);
  if (!Number.isFinite(numeric)) return `${amount} ${currency}`;
  try {
    return new Intl.NumberFormat(navigator.language || 'en-IE', {
      style: 'currency',
      currency,
      minimumFractionDigits: 2,
    }).format(numeric);
  } catch {
    return `${numeric.toFixed(2)} ${currency}`;
  }
}

/** Normalise a money input to a fixed 2-decimal string ("150" -> "150.00"). */
export function normaliseAmount(amount) {
  const numeric = Number(amount);
  if (!Number.isFinite(numeric)) throw new RangeError('Amount is not a number');
  return numeric.toFixed(2);
}

export function truncateMiddle(value, keep = 12) {
  if (value.length <= keep * 2 + 1) return value;
  return `${value.slice(0, keep)}…${value.slice(-keep)}`;
}
