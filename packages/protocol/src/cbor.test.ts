import { describe, expect, it } from 'vitest';
import { decodeCanonicalCbor, encodeCanonicalCbor } from './cbor.js';

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');
const bytes = (value: string): Uint8Array => Uint8Array.from(Buffer.from(value, 'hex'));

describe('space.vault/1 restricted deterministic CBOR', () => {
  it('encodes standard integer, string, array and map examples byte for byte', () => {
    expect(hex(encodeCanonicalCbor(1000))).toBe('1903e8');
    expect(hex(encodeCanonicalCbor(-1000))).toBe('3903e7');
    expect(hex(encodeCanonicalCbor('IETF'))).toBe('6449455446');
    expect(hex(encodeCanonicalCbor([1, 2, 3]))).toBe('83010203');
    expect(hex(encodeCanonicalCbor(new Map([[2, 'b'], [1, 'a']])))).toBe('a2016161026162');
  });

  it('round trips nested byte-bearing headers', () => {
    const header = new Map<number, number | string | Uint8Array | number[]>([
      [1, 'space.vault/1'], [2, Uint8Array.of(0, 255, 42)], [3, [1, 2]]
    ]);
    const encoded = encodeCanonicalCbor(header);
    expect(decodeCanonicalCbor(encoded)).toEqual(header);
    expect(hex(encodeCanonicalCbor(decodeCanonicalCbor(encoded)))).toBe(hex(encoded));
  });

  it.each([
    '1801', 'a2016161016162', 'a2026162016161', 'a161616178',
    '5f40ff', 'f6', 'c000', '0102', '6261', '62c328', 'a118006161', '9a00010001'
  ])('rejects malformed or noncanonical input %s', (value) => {
    expect(() => decodeCanonicalCbor(bytes(value))).toThrow();
  });

  it('enforces depth, string, map and safe-integer limits on encoding', () => {
    let nested: number | unknown[] = 0;
    for (let i = 0; i < 17; i++) nested = [nested];
    expect(() => encodeCanonicalCbor(nested as number[])).toThrow();
    expect(() => encodeCanonicalCbor('x'.repeat(1024 * 1024 + 1))).toThrow();
    expect(() => encodeCanonicalCbor(new Map(Array.from({ length: 65 }, (_, i) => [i, i])))).toThrow();
    expect(() => encodeCanonicalCbor(Number.MAX_SAFE_INTEGER + 1)).toThrow();
    expect(() => encodeCanonicalCbor('\ud800')).toThrow();
    expect(() => decodeCanonicalCbor(bytes('3b001fffffffffffff'))).toThrow();
  });

  it('bounds total nodes on both encode and decode before a small wire tree expands in memory', () => {
    const children = Array.from({ length: 1000 }, () => Array<number>(101).fill(0));
    expect(() => encodeCanonicalCbor(children)).toThrow('CBOR node limit exceeded');
    const wire = new Uint8Array(3 + 1000 * 103);
    wire.set([0x99, 0x03, 0xe8]);
    for (let i = 0; i < 1000; i++) wire.set([0x98, 101], 3 + i * 103);
    expect(() => decodeCanonicalCbor(wire)).toThrow('CBOR node limit exceeded');
  });
});
