/** The restricted deterministic CBOR subset used by space.vault/1 headers. */
export type CanonicalCbor = number | string | Uint8Array | CanonicalCbor[] | Map<number, CanonicalCbor>;

const MAX_BYTES = 16 * 1024 * 1024;
const MAX_STRING_BYTES = 1024 * 1024;
const MAX_DEPTH = 16;
const MAX_MAP_PAIRS = 64;
const MAX_ARRAY_ITEMS = 65536;
const MAX_NODES = 100000;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

function head(major: number, value: number): number[] {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('Invalid CBOR integer');
  if (value < 24) return [(major << 5) | value];
  if (value <= 0xff) return [(major << 5) | 24, value];
  if (value <= 0xffff) return [(major << 5) | 25, value >>> 8, value & 0xff];
  if (value <= 0xffffffff) return [(major << 5) | 26, (value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff];
  const high = Math.floor(value / 0x100000000);
  const low = value >>> 0;
  return [(major << 5) | 27, (high >>> 24) & 0xff, (high >>> 16) & 0xff, (high >>> 8) & 0xff, high & 0xff,
    (low >>> 24) & 0xff, (low >>> 16) & 0xff, (low >>> 8) & 0xff, low & 0xff];
}

export function encodeCanonicalCbor(value: CanonicalCbor): Uint8Array {
  let output = new Uint8Array(256);
  let offset = 0;
  let nodes = 0;
  function append(bytes: ArrayLike<number>): void {
    const required = offset + bytes.length;
    if (required > MAX_BYTES) throw new Error('CBOR size limit exceeded');
    if (required > output.length) {
      const grown = new Uint8Array(Math.min(MAX_BYTES, Math.max(required, output.length * 2)));
      grown.set(output.subarray(0, offset));
      output = grown;
    }
    for (let i = 0; i < bytes.length; i++) output[offset + i] = bytes[i]!;
    offset = required;
  }
  function write(item: CanonicalCbor, depth: number): void {
    if (++nodes > MAX_NODES) throw new Error('CBOR node limit exceeded');
    if (depth > MAX_DEPTH) throw new Error('CBOR nesting limit exceeded');
    if (typeof item === 'number') {
      append(item >= 0 ? head(0, item) : head(1, -1 - item));
    } else if (typeof item === 'string') {
      for (let i = 0; i < item.length; i++) {
        const unit = item.charCodeAt(i);
        if (unit >= 0xd800 && unit <= 0xdbff) {
          const next = item.charCodeAt(++i);
          if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error('Invalid CBOR Unicode string');
        } else if (unit >= 0xdc00 && unit <= 0xdfff) {
          throw new Error('Invalid CBOR Unicode string');
        }
      }
      const bytes = encoder.encode(item);
      if (bytes.length > MAX_STRING_BYTES) throw new Error('CBOR string limit exceeded');
      append(head(3, bytes.length)); append(bytes);
    } else if (item instanceof Uint8Array) {
      if (item.length > MAX_STRING_BYTES) throw new Error('CBOR byte string limit exceeded');
      append(head(2, item.length)); append(item);
    } else if (Array.isArray(item)) {
      if (item.length > MAX_ARRAY_ITEMS) throw new Error('CBOR array limit exceeded');
      append(head(4, item.length));
      for (const entry of item) write(entry, depth + 1);
    } else if (item instanceof Map) {
      if (item.size > MAX_MAP_PAIRS) throw new Error('CBOR map limit exceeded');
      const entries = [...item.entries()].sort(([a], [b]) => a - b);
      append(head(5, entries.length));
      for (const [key, entry] of entries) {
        if (++nodes > MAX_NODES) throw new Error('CBOR node limit exceeded');
        append(head(0, key)); write(entry, depth + 1);
      }
    } else {
      throw new Error('Unsupported CBOR value');
    }
  }
  write(value, 0);
  return output.slice(0, offset);
}

export function decodeCanonicalCbor(input: Uint8Array): CanonicalCbor {
  if (!(input instanceof Uint8Array) || input.length > MAX_BYTES) throw new Error('CBOR size limit exceeded');
  let offset = 0;
  let nodes = 0;
  function take(count: number): Uint8Array {
    if (!Number.isSafeInteger(count) || count < 0 || count > input.length - offset) throw new Error('Truncated CBOR');
    const result = input.subarray(offset, offset + count);
    offset += count;
    return result;
  }
  function argument(additional: number): number {
    if (additional < 24) return additional;
    const length = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : 0;
    if (!length) throw new Error('Unsupported CBOR length');
    let result = 0;
    for (const byte of take(length)) result = result * 256 + byte;
    if (!Number.isSafeInteger(result)) throw new Error('CBOR integer exceeds safe range');
    const minimum = length === 1 ? 24 : length === 2 ? 256 : length === 4 ? 65536 : 0x100000000;
    if (result < minimum) throw new Error('Non-canonical CBOR integer');
    return result;
  }
  function read(depth: number): CanonicalCbor {
    if (++nodes > MAX_NODES) throw new Error('CBOR node limit exceeded');
    if (depth > MAX_DEPTH) throw new Error('CBOR nesting limit exceeded');
    const first = take(1)[0]!;
    const major = first >>> 5;
    const count = argument(first & 31);
    if (major === 0) return count;
    if (major === 1) {
      const negative = -1 - count;
      if (!Number.isSafeInteger(negative)) throw new Error('CBOR integer exceeds safe range');
      return negative;
    }
    if (major === 2 || major === 3) {
      if (count > MAX_STRING_BYTES) throw new Error('CBOR string limit exceeded');
      const bytes = take(count);
      return major === 2 ? bytes.slice() : decoder.decode(bytes);
    }
    if (major === 4) {
      if (count > MAX_ARRAY_ITEMS) throw new Error('CBOR array limit exceeded');
      const array: CanonicalCbor[] = [];
      for (let i = 0; i < count; i++) array.push(read(depth + 1));
      return array;
    }
    if (major === 5) {
      if (count > MAX_MAP_PAIRS) throw new Error('CBOR map limit exceeded');
      const map = new Map<number, CanonicalCbor>();
      let previous = -1;
      for (let i = 0; i < count; i++) {
        const key = read(depth + 1);
        if (typeof key !== 'number' || key < 0 || key <= previous) throw new Error('Invalid or unordered CBOR map key');
        map.set(key, read(depth + 1));
        previous = key;
      }
      return map;
    }
    throw new Error('Unsupported CBOR type');
  }
  const result = read(0);
  if (offset !== input.length) throw new Error('Trailing CBOR bytes');
  return result;
}
