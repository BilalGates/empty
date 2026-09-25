import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { decodeDeterministicCbor, encodeDeterministicCbor, type CborValue } from './cbor.js';
import { decodeOperationHeader, encodeOperationHeader, type OperationHeader } from './operation-header.js';

const vector = JSON.parse(readFileSync(new URL('../../../test-vectors/operation-header-v1.json', import.meta.url), 'utf8')) as {
  vaultIdHex: string; epoch: number; opIdHex: string; deviceIdHex: string; deviceSeq: number;
  parentHeadsHex: string[]; objectIdHex: string; objectVersion: number; ciphertextHashHex: string; headerHex: string;
};
const envelope = JSON.parse(readFileSync(new URL('../../../test-vectors/vault-object-envelope-v1.json', import.meta.url), 'utf8')) as {
  artifactHex: string;
};
const bytes = (hex: string): Uint8Array => Uint8Array.from(Buffer.from(hex, 'hex'));
const header: OperationHeader = {
  vaultId: bytes(vector.vaultIdHex), epoch: vector.epoch, opId: bytes(vector.opIdHex),
  deviceId: bytes(vector.deviceIdHex), deviceSeq: vector.deviceSeq,
  parentHeads: vector.parentHeadsHex.map(bytes), objectId: bytes(vector.objectIdHex),
  objectVersion: vector.objectVersion, ciphertextHash: bytes(vector.ciphertextHashHex)
};

describe('V1 operation header', () => {
  it('matches the shared byte vector and hashes the exact framed object artifact', () => {
    expect(createHash('sha256').update(bytes(envelope.artifactHex)).digest('hex')).toBe(vector.ciphertextHashHex);
    const encoded = encodeOperationHeader(header);
    expect(Buffer.from(encoded).toString('hex')).toBe(vector.headerHex);
    expect(decodeOperationHeader(encoded)).toEqual(header);
  });

  it('allows genesis without parents and rejects unordered, duplicate or excessive parents', () => {
    const genesis = { ...header, parentHeads: [] };
    expect(decodeOperationHeader(encodeOperationHeader(genesis))).toEqual(genesis);
    const backwards = { ...header, parentHeads: [...header.parentHeads].reverse() };
    expect(() => encodeOperationHeader(backwards)).toThrow('INVALID_OPERATION_HEADER');
    expect(() => encodeOperationHeader({ ...header, parentHeads: [header.parentHeads[0]!, header.parentHeads[0]!] })).toThrow('INVALID_OPERATION_HEADER');
    expect(() => encodeOperationHeader({ ...header, parentHeads: Array.from({ length: 65 }, (_, index) => Uint8Array.of(index, ...new Uint8Array(15))) })).toThrow('INVALID_OPERATION_HEADER');
  });

  it('rejects wrong lengths, zero sequence, unknown keys and CBOR type changes', () => {
    expect(() => encodeOperationHeader({ ...header, ciphertextHash: new Uint8Array(31) })).toThrow('INVALID_OPERATION_HEADER');
    expect(() => encodeOperationHeader({ ...header, deviceSeq: 0 })).toThrow('INVALID_OPERATION_HEADER');
    expect(() => encodeOperationHeader({ ...header, epoch: Number.MAX_SAFE_INTEGER + 1 })).toThrow('INVALID_OPERATION_HEADER');
    const map = decodeDeterministicCbor(encodeOperationHeader(header)) as Map<number, CborValue>;
    map.set(12, null);
    expect(() => decodeOperationHeader(encodeDeterministicCbor(map))).toThrow('INVALID_OPERATION_HEADER');
    map.delete(12); map.set(8, [new Uint8Array(16), new Uint8Array(16)]);
    expect(() => decodeOperationHeader(encodeDeterministicCbor(map))).toThrow('INVALID_OPERATION_HEADER');
    map.set(8, []); map.set(7, '2');
    expect(() => decodeOperationHeader(encodeDeterministicCbor(map))).toThrow('INVALID_OPERATION_HEADER');
    expect(() => decodeOperationHeader(Uint8Array.from([0xab, 0x01, 0x6d]))).toThrow('INVALID_OPERATION_HEADER');
  });
});
