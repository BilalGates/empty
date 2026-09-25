// The narrow CBOR subset used for signed Space headers and authenticated data.
// Maps have unsigned integer keys; floats, tags and indefinite lengths are forbidden.
export type CborValue = null | boolean | number | string | Uint8Array | CborValue[] | Map<number, CborValue>;

const MAX_ARTIFACT = 16 * 1024 * 1024;
const MAX_STRING = 1024 * 1024;
const MAX_DEPTH = 16;
const MAX_MAP_PAIRS = 64;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

function header(major: number, value: number): number[] {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('INVALID_CBOR');
  if (value < 24) return [(major << 5) | value];
  if (value <= 0xff) return [(major << 5) | 24, value];
  if (value <= 0xffff) return [(major << 5) | 25, value >>> 8, value & 0xff];
  if (value <= 0xffffffff) return [(major << 5) | 26, (value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff];
  const high = Math.floor(value / 0x100000000);
  const low = value >>> 0;
  return [(major << 5) | 27, (high >>> 24) & 0xff, (high >>> 16) & 0xff, (high >>> 8) & 0xff, high & 0xff,
    (low >>> 24) & 0xff, (low >>> 16) & 0xff, (low >>> 8) & 0xff, low & 0xff];
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  if (left.length !== right.length) return left.length - right.length;
  for (let index = 0; index < left.length; index++) {
    if (left[index] !== right[index]) return left[index]! - right[index]!;
  }
  return 0;
}

export function encodeDeterministicCbor(value: CborValue, maximumBytes = MAX_ARTIFACT): Uint8Array {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > MAX_ARTIFACT) throw new Error('INVALID_CBOR');
  const output: number[] = [];
  const append = (bytes: Iterable<number>): void => {
    for (const byte of bytes) {
      if (output.length >= maximumBytes) throw new Error('INVALID_CBOR');
      output.push(byte);
    }
  };
  const visit = (item: CborValue, depth: number): void => {
    if (depth > MAX_DEPTH) throw new Error('INVALID_CBOR');
    if (item === null) { append([0xf6]); return; }
    if (typeof item === 'boolean') { append([item ? 0xf5 : 0xf4]); return; }
    if (typeof item === 'number') {
      if (!Number.isSafeInteger(item)) throw new Error('INVALID_CBOR');
      append(item >= 0 ? header(0, item) : header(1, -1 - item)); return;
    }
    if (typeof item === 'string') {
      if (item.length > MAX_STRING || item.length > maximumBytes) throw new Error('INVALID_CBOR');
      const bytes = encoder.encode(item);
      try {
        if (bytes.length > MAX_STRING || bytes.length > maximumBytes || decoder.decode(bytes) !== item) throw new Error('INVALID_CBOR');
        append(header(3, bytes.length)); append(bytes); return;
      } finally { bytes.fill(0); }
    }
    if (item instanceof Uint8Array) {
      if (item.length > MAX_STRING || item.length > maximumBytes) throw new Error('INVALID_CBOR');
      append(header(2, item.length)); append(item); return;
    }
    if (Array.isArray(item)) {
      append(header(4, item.length));
      for (const entry of item) visit(entry, depth + 1);
      return;
    }
    if (item instanceof Map) {
      if (item.size > MAX_MAP_PAIRS) throw new Error('INVALID_CBOR');
      const entries = [...item.entries()].map(([key, entry]) => ({ key: Uint8Array.from(header(0, key)), entry }));
      entries.sort((a, b) => compareBytes(a.key, b.key));
      append(header(5, entries.length));
      for (const { key, entry } of entries) { append(key); visit(entry, depth + 1); }
      return;
    }
    throw new Error('INVALID_CBOR');
  };
  try {
    visit(value, 0);
    return Uint8Array.from(output);
  } finally { output.fill(0); }
}

export function decodeDeterministicCbor(input: Uint8Array): CborValue {
  if (input.length > MAX_ARTIFACT) throw new Error('INVALID_CBOR');
  let offset = 0;
  const take = (length: number): Uint8Array => {
    if (!Number.isSafeInteger(length) || length < 0 || length > input.length - offset) throw new Error('INVALID_CBOR');
    const result = input.subarray(offset, offset + length);
    offset += length;
    return result;
  };
  const lengthFor = (additional: number): number => {
    if (additional < 24) return additional;
    const width = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : 0;
    if (!width) throw new Error('INVALID_CBOR');
    let value = 0;
    for (const byte of take(width)) value = value * 256 + byte;
    if (!Number.isSafeInteger(value) || value < (width === 1 ? 24 : 2 ** (8 * (width / 2)))) throw new Error('INVALID_CBOR');
    return value;
  };
  const parse = (depth: number): CborValue => {
    if (depth > MAX_DEPTH) throw new Error('INVALID_CBOR');
    const initial = take(1)[0]!;
    const major = initial >>> 5;
    const additional = initial & 31;
    if (major === 7) {
      if (initial === 0xf4) return false;
      if (initial === 0xf5) return true;
      if (initial === 0xf6) return null;
      throw new Error('INVALID_CBOR');
    }
    const length = lengthFor(additional);
    if (major === 0) return length;
    if (major === 1) {
      if (length === Number.MAX_SAFE_INTEGER) throw new Error('INVALID_CBOR');
      return -1 - length;
    }
    if (major === 2 || major === 3) {
      if (length > MAX_STRING) throw new Error('INVALID_CBOR');
      const bytes = take(length);
      return major === 2 ? bytes.slice() : decoder.decode(bytes);
    }
    if (major === 4) {
      if (length > input.length - offset) throw new Error('INVALID_CBOR');
      const items: CborValue[] = [];
      for (let index = 0; index < length; index++) items.push(parse(depth + 1));
      return items;
    }
    if (major === 5) {
      if (length > MAX_MAP_PAIRS || length * 2 > input.length - offset) throw new Error('INVALID_CBOR');
      const entries = new Map<number, CborValue>();
      let previous: Uint8Array | undefined;
      for (let index = 0; index < length; index++) {
        const start = offset;
        const key = parse(depth + 1);
        const encodedKey = input.subarray(start, offset);
        if (typeof key !== 'number' || key < 0 || (previous && compareBytes(previous, encodedKey) >= 0)) throw new Error('INVALID_CBOR');
        previous = encodedKey;
        entries.set(key, parse(depth + 1));
      }
      return entries;
    }
    throw new Error('INVALID_CBOR');
  };
  try {
    const value = parse(0);
    if (offset !== input.length) throw new Error('INVALID_CBOR');
    return value;
  } catch {
    // Do not expose decoder-specific errors or malformed-input details.
    throw new Error('INVALID_CBOR');
  }
}
