import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { decodePasswordPayload, encodePasswordPayload, type PasswordPayload } from './password-payload.js';
import { decodeDeterministicCbor, encodeDeterministicCbor, type CborValue } from './cbor.js';

const payload: PasswordPayload = {
  title: 'Example', origins: ['https://example.com'], username: 'alice', password: 'demo-only',
  groupId: Uint8Array.from({ length: 16 }, (_, index) => index), notes: '', favorite: false,
  createdAtMs: 1_700_000_000_000, updatedAtMs: 1_700_000_000_001
};
const vector = JSON.parse(readFileSync(new URL('../../../test-vectors/password-payload-v1.json', import.meta.url), 'utf8')) as { cborHex: string };

describe('V1 password payload', () => {
  it('round trips the exact integer-keyed schema', () => {
    const bytes = encodePasswordPayload(payload);
    expect(Buffer.from(bytes).toString('hex')).toBe(vector.cborHex);
    expect(decodePasswordPayload(bytes)).toEqual(payload);
    expect([...((decodeDeterministicCbor(bytes)) as Map<number, CborValue>).keys()]).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);
  });

  it('supports absent optional fields but rejects unknown and missing fields', () => {
    const minimal = { title: payload.title, origins: payload.origins, username: payload.username,
      password: payload.password, favorite: payload.favorite,
      createdAtMs: payload.createdAtMs, updatedAtMs: payload.updatedAtMs };
    const bytes = encodePasswordPayload(minimal);
    expect(decodePasswordPayload(bytes)).toEqual(minimal);
    const map = decodeDeterministicCbor(bytes) as Map<number, CborValue>;
    map.set(10, null);
    expect(() => decodePasswordPayload(encodeDeterministicCbor(map))).toThrow('INVALID_PAYLOAD');
    map.delete(10); map.delete(4);
    expect(() => decodePasswordPayload(encodeDeterministicCbor(map))).toThrow('INVALID_PAYLOAD');
  });

  it('rejects wrong types, duplicate origins, timestamps and oversize fields', () => {
    const bytes = encodePasswordPayload(payload);
    const change = (key: number, value: CborValue): Uint8Array => {
      const map = decodeDeterministicCbor(bytes) as Map<number, CborValue>;
      map.set(key, value);
      return encodeDeterministicCbor(map);
    };
    const invalid: Array<[number, CborValue]> = [[1, ''], [2, ['https://example.com', 'https://example.com']],
      [3, 42], [4, ''], [5, new Uint8Array(15)], [6, null], [7, 1], [8, 0], [9, 1]];
    for (const [key, value] of invalid) {
      expect(() => decodePasswordPayload(change(key, value)), `key ${key}`).toThrow('INVALID_PAYLOAD');
    }
    expect(() => encodePasswordPayload({ ...payload, password: 'x'.repeat(65_537) })).toThrow('INVALID_PAYLOAD');
    expect(() => decodePasswordPayload(Uint8Array.from([0xa1, 0x01, 0x61, 0xff]))).toThrow('INVALID_PAYLOAD');
  });
});
