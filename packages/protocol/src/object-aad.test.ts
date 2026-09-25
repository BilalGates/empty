import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { decodeCanonicalCbor, encodeCanonicalCbor, type CanonicalCbor } from './cbor.js';
import { decodeObjectAad, encodeObjectAad, type VaultObjectAad } from './object-aad.js';

const vector = JSON.parse(readFileSync(new URL('../../../test-vectors/object-aad-v1.json', import.meta.url), 'utf8')) as {
  suite: string; vaultIdHex: string; objectIdHex: string; objectType: 'password'; objectVersion: number;
  epoch: number; keyIdHex: string; createdByDeviceHex: string; aadHex: string;
};
const bytes = (hex: string): Uint8Array => Uint8Array.from(Buffer.from(hex, 'hex'));
const hex = (value: Uint8Array): string => Buffer.from(value).toString('hex');
const aad = (): VaultObjectAad => ({
  vaultId: bytes(vector.vaultIdHex), objectId: bytes(vector.objectIdHex),
  objectType: vector.objectType, objectVersion: vector.objectVersion, epoch: vector.epoch,
  keyId: bytes(vector.keyIdHex), createdByDevice: bytes(vector.createdByDeviceHex)
});

describe('space.vault/1 object AAD', () => {
  it('matches the shared byte vector and round trips all bound fields', () => {
    expect(vector.suite).toBe('space.vault/1');
    expect(hex(encodeObjectAad(aad()))).toBe(vector.aadHex);
    expect(decodeObjectAad(bytes(vector.aadHex))).toEqual(aad());
  });

  it('changes bytes when any authenticated context field changes', () => {
    const reference = hex(encodeObjectAad(aad()));
    const variants: VaultObjectAad[] = [
      { ...aad(), vaultId: bytes('ff0102030405060708090a0b0c0d0e0f') },
      { ...aad(), objectId: bytes('ff1112131415161718191a1b1c1d1e1f') },
      { ...aad(), objectType: 'tombstone' },
      { ...aad(), objectVersion: 2 },
      { ...aad(), epoch: 3 },
      { ...aad(), keyId: bytes('ff2122232425262728292a2b2c2d2e2f') },
      { ...aad(), createdByDevice: bytes('ff3132333435363738393a3b3c3d3e3f') }
    ];
    for (const variant of variants) expect(hex(encodeObjectAad(variant))).not.toBe(reference);
  });

  it('rejects changed suite, kind, fields, lengths, versions, and unknown keys', () => {
    const reference = decodeCanonicalCbor(bytes(vector.aadHex)) as Map<number, CanonicalCbor>;
    const bad: Array<[number, CanonicalCbor | undefined]> = [
      [1, 'space.vault/2'], [2, 'key-slot'], [3, new Uint8Array(15)],
      [4, new Uint8Array(17)], [5, 'recovery-code'], [6, 0], [7, -1],
      [8, 'not-an-id'], [9, new Uint8Array(0)], [10, 1], [3, undefined]
    ];
    for (const [key, value] of bad) {
      const changed = new Map(reference);
      if (value === undefined) changed.delete(key);
      else changed.set(key, value);
      expect(() => decodeObjectAad(encodeCanonicalCbor(changed))).toThrow();
    }
    expect(() => decodeObjectAad(new Uint8Array(16 * 1024 + 1))).toThrow();
  });

  it('copies decoded identifiers so callers cannot mutate input bytes through them', () => {
    const original = bytes(vector.aadHex);
    const decoded = decodeObjectAad(original);
    decoded.vaultId[0] = 255;
    expect(hex(original)).toBe(vector.aadHex);
  });
});
