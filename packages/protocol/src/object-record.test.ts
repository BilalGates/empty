import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { decodeCanonicalCbor, encodeCanonicalCbor, type CanonicalCbor } from './cbor.js';
import { decodeVaultFrame, encodeVaultFrame, VAULT_ARTIFACT_KIND } from './frame.js';
import { decodeObjectRecord, encodeObjectRecord, type UnauthenticatedObjectRecord } from './object-record.js';

function fixture(): UnauthenticatedObjectRecord {
  return {
    aad: {
      vaultId: new Uint8Array(16), objectId: new Uint8Array(16).fill(1), objectType: 'password',
      objectVersion: 1, epoch: 1, keyId: new Uint8Array(16).fill(2),
      createdByDevice: new Uint8Array(16).fill(3)
    },
    wrappedDek: { nonce: new Uint8Array(24).fill(4), ciphertext: new Uint8Array(48).fill(5) },
    payload: { nonce: new Uint8Array(24).fill(6), ciphertext: new Uint8Array(17).fill(7) }
  };
}

describe('space.vault/1 unauthenticated object record parser', () => {
  it('matches the shared record schema bytes', () => {
    const vector = JSON.parse(readFileSync(new URL('../../../test-vectors/object-record-v1.json', import.meta.url), 'utf8')) as {
      suite: string; frameHex: string;
    };
    const sequence = (length: number, start: number): Uint8Array => Uint8Array.from({ length }, (_, i) => start + i);
    const value: UnauthenticatedObjectRecord = {
      aad: {
        vaultId: sequence(16, 0), objectId: sequence(16, 16), objectType: 'password',
        objectVersion: 1, epoch: 2, keyId: sequence(16, 32), createdByDevice: sequence(16, 48)
      },
      wrappedDek: { nonce: sequence(24, 64), ciphertext: sequence(48, 88) },
      payload: { nonce: sequence(24, 136), ciphertext: sequence(17, 160) }
    };
    expect(vector.suite).toBe('space.vault/1');
    expect(Buffer.from(encodeObjectRecord(value)).toString('hex')).toBe(vector.frameHex);
    expect(decodeObjectRecord(Uint8Array.from(Buffer.from(vector.frameHex, 'hex')))).toEqual(value);
  });

  it('round trips the exact framed schema', () => {
    const value = fixture();
    const encoded = encodeObjectRecord(value);
    expect(decodeObjectRecord(encoded)).toEqual(value);
    expect(encoded.slice(0, 7)).toEqual(Uint8Array.of(0x53, 0x50, 0x43, 0x45, 0, 1, 1));
  });

  it('rejects missing, extra, malformed, or wrong-kind fields', () => {
    const source = decodeVaultFrame(encodeObjectRecord(fixture()), VAULT_ARTIFACT_KIND.object);
    const variants: Map<number, CanonicalCbor>[] = [];
    const missing = new Map(source);
    missing.delete(2);
    variants.push(missing);
    const extra = new Map(source);
    extra.set(4, 0);
    variants.push(extra);
    for (const field of [2, 3]) {
      for (const key of [1, 2]) {
        const changed = new Map(source);
        const part = new Map(changed.get(field) as Map<number, CanonicalCbor>);
        part.set(key, new Uint8Array(key === 1 ? 23 : field === 2 ? 47 : 15));
        changed.set(field, part);
        variants.push(changed);
      }
    }
    for (const variant of variants) {
      expect(() => decodeObjectRecord(encodeVaultFrame(VAULT_ARTIFACT_KIND.object, variant))).toThrow();
    }
    expect(() => decodeObjectRecord(encodeVaultFrame(VAULT_ARTIFACT_KIND.keySlot, source))).toThrow();
    const badAad = new Map(source);
    const aad = decodeCanonicalCbor(encodeCanonicalCbor(source.get(1)!)) as Map<number, CanonicalCbor>;
    aad.set(2, 'key-slot');
    badAad.set(1, aad);
    expect(() => decodeObjectRecord(encodeVaultFrame(VAULT_ARTIFACT_KIND.object, badAad))).toThrow();
  });

  it('does not expose views into the encoded input', () => {
    const encoded = encodeObjectRecord(fixture());
    const parsed = decodeObjectRecord(encoded);
    parsed.wrappedDek.ciphertext[0] = 255;
    parsed.aad.vaultId[0] = 255;
    expect(decodeObjectRecord(encoded)).toEqual(fixture());
  });

  it('rejects a payload ciphertext beyond the V1 byte-string limit', () => {
    const value = fixture();
    value.payload.ciphertext = new Uint8Array(1024 * 1024 + 1);
    expect(() => encodeObjectRecord(value)).toThrow('Invalid object ciphertext');
  });
});
