import { readFileSync } from 'node:fs';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import {
  decodeVaultObjectRecord, encodeVaultObjectRecord, MAX_OBJECT_PLAINTEXT_BYTES,
  type VaultObjectAad
} from '@space/protocol';
import { describe, expect, it } from 'vitest';
import { openPasswordVaultObject, openVaultObject, sealVaultObject } from './vault-object.js';

interface Vector {
  vrkHex: string; dekHex: string; aadHex: string; vwkHex: string;
  wrappedNonceHex: string; payloadNonceHex: string; payloadCborHex: string;
  wrappedCiphertextHex: string; payloadCiphertextHex: string; artifactHex: string;
}
const vector = JSON.parse(readFileSync(
  new URL('../../../test-vectors/vault-object-envelope-v1.json', import.meta.url), 'utf8'
)) as Vector;
const aadVector = JSON.parse(readFileSync(
  new URL('../../../test-vectors/vault-object-aad-v1.json', import.meta.url), 'utf8'
)) as { vaultIdHex: string; objectIdHex: string; objectType: 'password'; objectVersion: number; epoch: number; keyIdHex: string; createdByDeviceHex: string };
const bytes = (hex: string): Uint8Array => Uint8Array.from(Buffer.from(hex, 'hex'));
const hex = (value: Uint8Array): string => Buffer.from(value).toString('hex');
const aad: VaultObjectAad = {
  vaultId: bytes(aadVector.vaultIdHex), objectId: bytes(aadVector.objectIdHex),
  objectType: aadVector.objectType, objectVersion: aadVector.objectVersion,
  epoch: aadVector.epoch, keyId: bytes(aadVector.keyIdHex),
  createdByDevice: bytes(aadVector.createdByDeviceHex)
};
const vrk = bytes(vector.vrkHex);
const artifact = bytes(vector.artifactHex);

describe('space.vault/1 per-object envelope', () => {
  it('opens the independent libsodium/HKDF vector and preserves exact framing', () => {
    const derived = hkdf(sha256, vrk, aad.vaultId, new TextEncoder().encode('space/vwk/v1'), 32);
    expect(hex(derived)).toBe(vector.vwkHex);
    const record = decodeVaultObjectRecord(artifact);
    expect(hex(record.aad)).toBe(vector.aadHex);
    expect(hex(record.wrappedDek.nonce)).toBe(vector.wrappedNonceHex);
    expect(hex(record.wrappedDek.ciphertext)).toBe(vector.wrappedCiphertextHex);
    expect(hex(record.payload.nonce)).toBe(vector.payloadNonceHex);
    expect(hex(record.payload.ciphertext)).toBe(vector.payloadCiphertextHex);
    expect(hex(encodeVaultObjectRecord(record))).toBe(vector.artifactHex);
    expect(openVaultObject(vrk, aad, artifact)).toEqual(new Map<number, string | number>([[1, 'fixture'], [2, 42]]));
  });

  it('uses fresh material and round trips a new object', () => {
    const payload = new Map<number, string | number>([[1, 'synthetic record'], [2, 42]]);
    const first = sealVaultObject(vrk, aad, payload);
    const second = sealVaultObject(vrk, aad, payload);
    expect(first).not.toEqual(second);
    expect(decodeVaultObjectRecord(first).wrappedDek.nonce).not.toEqual(decodeVaultObjectRecord(second).wrappedDek.nonce);
    expect(decodeVaultObjectRecord(first).payload.nonce).not.toEqual(decodeVaultObjectRecord(second).payload.nonce);
    expect(openVaultObject(vrk, aad, first)).toEqual(payload);
    expect(Buffer.from(first).includes(Buffer.from('synthetic record'))).toBe(false);
  });

  it('rejects every single-byte fixture mutation and altered trusted routing context', () => {
    for (let index = 0; index < artifact.length; index++) {
      const altered = artifact.slice();
      altered[index]! ^= 1;
      expect(() => openVaultObject(vrk, aad, altered), `byte ${index}`).toThrow('INVALID_ENVELOPE');
    }
    const other = (field: keyof VaultObjectAad): VaultObjectAad => {
      if (field === 'objectType') return { ...aad, objectType: 'tombstone' };
      if (field === 'objectVersion' || field === 'epoch') return { ...aad, [field]: 2 };
      const changed = aad[field].slice();
      changed[0]! ^= 1;
      return { ...aad, [field]: changed };
    };
    for (const field of ['vaultId', 'objectId', 'objectType', 'objectVersion', 'epoch', 'keyId', 'createdByDevice'] as const) {
      expect(() => openVaultObject(vrk, other(field), artifact), field).toThrow('INVALID_ENVELOPE');
    }
    const wrongKey = vrk.slice();
    wrongKey[0]! ^= 1;
    expect(() => openVaultObject(wrongKey, aad, artifact)).toThrow('INVALID_ENVELOPE');
  });

  it('rejects malformed envelopes before decryption', () => {
    const record = decodeVaultObjectRecord(artifact);
    expect(() => encodeVaultObjectRecord({ ...record, wrappedDek: { ...record.wrappedDek, nonce: bytes('00') } })).toThrow('INVALID_ENVELOPE');
    expect(() => decodeVaultObjectRecord(artifact.subarray(0, artifact.length - 1))).toThrow('INVALID_ENVELOPE');
    expect(() => sealVaultObject(bytes('00'), aad, null)).toThrow('INVALID_ENVELOPE');
    expect(() => sealVaultObject(vrk, aad, 'x'.repeat(1024 * 1024))).toThrow('INVALID_ENVELOPE');
  });

  it('enforces the object payload bound at the AEAD tag boundary', () => {
    const payload = new Uint8Array(MAX_OBJECT_PLAINTEXT_BYTES - 5);
    const sealed = sealVaultObject(vrk, aad, payload);
    expect(decodeVaultObjectRecord(sealed).payload.ciphertext.length).toBe(1024 * 1024);
    const opened = openVaultObject(vrk, aad, sealed);
    expect(opened).toBeInstanceOf(Uint8Array);
    expect((opened as Uint8Array).length).toBe(payload.length);
    expect(() => sealVaultObject(vrk, aad, new Uint8Array(payload.length + 1))).toThrow('INVALID_ENVELOPE');
  });

  it('dispatches a typed password payload only from authenticated object type', () => {
    const password = new Map<number, string | number | boolean | string[]>([
      [1, 'Example'], [2, ['https://example.com']], [3, 'alice'], [4, 'demo-only'],
      [7, false], [8, 1_700_000_000_000], [9, 1_700_000_000_001]
    ]);
    const sealed = sealVaultObject(vrk, aad, password);
    expect(openPasswordVaultObject(vrk, aad, sealed).username).toBe('alice');
    expect(() => openPasswordVaultObject(vrk, { ...aad, objectType: 'totp' }, sealed)).toThrow('INVALID_ENVELOPE');
    expect(() => openPasswordVaultObject(vrk, aad, artifact)).toThrow('INVALID_ENVELOPE');
  });
});
