/**
 * Minimal CBOR decoder — just enough to read a WebAuthn attestation object
 * and a COSE_Key. WebAuthn only ever hands us definite-length maps, arrays,
 * byte strings, text strings and integers, so the exotic parts of RFC 8949
 * (indefinite lengths, bignums, most tags) are deliberately unsupported.
 */

import { bytes } from './util.js';

class Reader {
  constructor(input) {
    this.view = new DataView(bytes(input).buffer, bytes(input).byteOffset, bytes(input).byteLength);
    this.raw = bytes(input);
    this.offset = 0;
  }

  u8() {
    const value = this.view.getUint8(this.offset);
    this.offset += 1;
    return value;
  }

  take(length) {
    const slice = this.raw.subarray(this.offset, this.offset + length);
    if (slice.length !== length) throw new RangeError('CBOR: unexpected end of input');
    this.offset += length;
    return slice;
  }

  length(additional) {
    if (additional < 24) return additional;
    if (additional === 24) return this.u8();
    if (additional === 25) {
      const value = this.view.getUint16(this.offset);
      this.offset += 2;
      return value;
    }
    if (additional === 26) {
      const value = this.view.getUint32(this.offset);
      this.offset += 4;
      return value;
    }
    if (additional === 27) {
      const value = this.view.getBigUint64(this.offset);
      this.offset += 8;
      return Number(value);
    }
    throw new RangeError(`CBOR: unsupported additional information ${additional}`);
  }

  value() {
    const initial = this.u8();
    const major = initial >> 5;
    const additional = initial & 0x1f;

    switch (major) {
      case 0:
        return this.length(additional);
      case 1:
        return -1 - this.length(additional);
      case 2:
        return this.take(this.length(additional));
      case 3:
        return new TextDecoder().decode(this.take(this.length(additional)));
      case 4: {
        const count = this.length(additional);
        const array = [];
        for (let i = 0; i < count; i += 1) array.push(this.value());
        return array;
      }
      case 5: {
        const count = this.length(additional);
        const map = new Map();
        for (let i = 0; i < count; i += 1) {
          const key = this.value();
          map.set(typeof key === 'number' || typeof key === 'string' ? key : String(key), this.value());
        }
        return map;
      }
      case 6:
        this.length(additional); // tag number — ignored, decode the tagged item
        return this.value();
      case 7: {
        if (additional === 20) return false;
        if (additional === 21) return true;
        if (additional === 22) return null;
        if (additional === 23) return undefined;
        throw new RangeError(`CBOR: unsupported simple value ${additional}`);
      }
      default:
        throw new RangeError(`CBOR: unsupported major type ${major}`);
    }
  }
}

/** Decode one CBOR item; trailing bytes (if any) are returned alongside it. */
export function decodeFirst(input) {
  const reader = new Reader(input);
  const value = reader.value();
  return { value, remaining: reader.raw.subarray(reader.offset) };
}

export function decode(input) {
  return decodeFirst(input).value;
}

/** Turn a decoded Map tree into plain objects, for display purposes. */
export function toPlain(value) {
  if (value instanceof Map) {
    const out = {};
    for (const [key, entry] of value.entries()) out[String(key)] = toPlain(entry);
    return out;
  }
  if (Array.isArray(value)) return value.map(toPlain);
  if (value instanceof Uint8Array) return `<${value.length} bytes>`;
  return value;
}
