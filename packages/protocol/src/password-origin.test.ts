import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { isCanonicalPasswordOrigin } from './password-origin.js';
import { encodePasswordPayload, decodePasswordPayload } from './password-payload.js';
import { decodeDeterministicCbor, encodeDeterministicCbor, type CborValue } from './cbor.js';

const vector = JSON.parse(readFileSync(new URL('../../../test-vectors/password-origins-v1.json', import.meta.url), 'utf8')) as {
  valid: string[]; invalid: string[];
};
const base = { title: 'Example', username: 'alice', password: 'demo-only', favorite: false,
  createdAtMs: 1_700_000_000_000, updatedAtMs: 1_700_000_000_001 };

describe('canonical V1 password origins', () => {
  it('agrees with the shared positive and negative corpus', () => {
    for (const origin of vector.valid) expect(isCanonicalPasswordOrigin(origin), origin).toBe(true);
    for (const origin of vector.invalid) expect(isCanonicalPasswordOrigin(origin), origin).toBe(false);
  });

  it('rejects unsafe origins both when writing and reading', () => {
    for (const origin of vector.invalid) {
      expect(() => encodePasswordPayload({ ...base, origins: [origin] }), origin).toThrow('INVALID_PAYLOAD');
    }
    const encoded = encodePasswordPayload({ ...base, origins: ['https://example.com'] });
    expect(decodePasswordPayload(encoded).origins).toEqual(['https://example.com']);
    for (const origin of vector.invalid) {
      const map = decodeDeterministicCbor(encoded) as Map<number, CborValue>;
      map.set(2, [origin]);
      expect(() => decodePasswordPayload(encodeDeterministicCbor(map)), origin).toThrow('INVALID_PAYLOAD');
    }
  });
});
