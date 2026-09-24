import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { decodeDeterministicCbor, encodeDeterministicCbor } from './cbor.js';
import { decodeVaultObjectAad, encodeVaultObjectAad } from './vault-aad.js';

const bytes = (hex: string): Uint8Array => Uint8Array.from(Buffer.from(hex, 'hex'));
const hex = (value: Uint8Array): string => Buffer.from(value).toString('hex');

interface AadVector {
  vaultIdHex: string; objectIdHex: string; objectType: 'password'; objectVersion: number;
  epoch: number; keyIdHex: string; createdByDeviceHex: string; aadHex: string;
}
const vectorNames = ['vault-object-aad-v1', 'vault-object-aad-small-boundary-v1', 'vault-object-aad-large-boundary-v1'];
const vectors = vectorNames.map(name => JSON.parse(
  readFileSync(new URL(`../../../test-vectors/${name}.json`, import.meta.url), 'utf8')
) as AadVector);
const vector = vectors[0]!;

describe('deterministic CBOR for space.vault/1', () => {
  it.each(vectors)('matches independently constructed object AAD vector at version $objectVersion and epoch $epoch', current => {
    const aad = encodeVaultObjectAad({
      vaultId: bytes(current.vaultIdHex), objectId: bytes(current.objectIdHex), objectType: current.objectType,
      objectVersion: current.objectVersion, epoch: current.epoch, keyId: bytes(current.keyIdHex),
      createdByDevice: bytes(current.createdByDeviceHex)
    });
    expect(hex(aad)).toBe(current.aadHex);
    expect(hex(encodeDeterministicCbor(decodeDeterministicCbor(aad)))).toBe(current.aadHex);
    expect(decodeVaultObjectAad(aad).objectType).toBe('password');
    for (const offset of [3, 20]) {
      const changed = aad.slice();
      changed[offset]! ^= 1;
      expect(() => decodeVaultObjectAad(changed)).toThrow('INVALID_AAD');
    }
    const changedId = aad.slice();
    changedId[37]! ^= 1;
    expect(hex(decodeVaultObjectAad(changedId).vaultId)).not.toBe(current.vaultIdHex);
  });

  it('sorts integer map keys by encoded length then bytes', () => {
    expect(hex(encodeDeterministicCbor(new Map([[24, true], [1, false], [256, null]])))).toBe('a301f41818f5190100f6');
  });

  it.each([
    '1801', // non-shortest integer
    'a201010102', // duplicate key
    'a202000100', // unsorted keys
    'a12000', // non-shortest map key
    '9f01ff', // indefinite array
    'f90000', // float
    'c0f6', // tag
    '61ff', // invalid UTF-8
    '810001', // trailing data
    '815f', // truncated item
    'a101', // missing map value
    'a12000', // negative map key
    '5a01000000' // oversized byte string before allocation
  ])('rejects malformed or non-canonical input %s', input => {
    expect(() => decodeDeterministicCbor(bytes(input))).toThrow('INVALID_CBOR');
  });

  it('rejects invalid AAD fields and oversized/deep CBOR', () => {
    const valid = { vaultId: bytes(vector.vaultIdHex), objectId: bytes(vector.objectIdHex),
      objectType: 'password' as const, objectVersion: 1, epoch: 1,
      keyId: bytes(vector.keyIdHex), createdByDevice: bytes(vector.createdByDeviceHex) };
    expect(() => encodeVaultObjectAad({ ...valid, vaultId: bytes('00') })).toThrow('INVALID_AAD');
    expect(() => encodeVaultObjectAad({ ...valid, epoch: 0 })).toThrow('INVALID_AAD');
    expect(() => encodeDeterministicCbor('x'.repeat(1024 * 1024 + 1))).toThrow('INVALID_CBOR');
    let nested: unknown = null;
    for (let index = 0; index < 17; index++) nested = [nested];
    expect(() => encodeDeterministicCbor(nested as never)).toThrow('INVALID_CBOR');
    expect(() => encodeDeterministicCbor(-9007199254740992)).toThrow('INVALID_CBOR');
    expect(() => decodeDeterministicCbor(bytes('3b001fffffffffffff'))).toThrow('INVALID_CBOR');
  });
});
