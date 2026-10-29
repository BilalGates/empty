import { readFileSync } from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519';
import {
  decodeOperationHeader, decodeSignedOperationRecord, encodeSignedOperationRecord, type VaultObjectAad
} from '@space/protocol';
import { describe, expect, it } from 'vitest';
import { signOperation, verifyOperation } from './signed-operation.js';

const read = <T>(name: string): T => JSON.parse(readFileSync(new URL(`../../../test-vectors/${name}`, import.meta.url), 'utf8')) as T;
const vector = read<{ secretSeedHex: string; publicKeyHex: string; headerHex: string; signatureHex: string; artifactHex: string; negativeCases: Array<{ name: string; publicKeyHex: string; signatureHex: string }> }>('signed-operation-v1.json');
const envelope = read<{ artifactHex: string }>('vault-object-envelope-v1.json');
const aadVector = read<{ vaultIdHex: string; objectIdHex: string; objectType: 'password'; objectVersion: number; epoch: number; keyIdHex: string; createdByDeviceHex: string }>('vault-object-aad-v1.json');
const bytes = (hex: string): Uint8Array => Uint8Array.from(Buffer.from(hex, 'hex'));
const hex = (value: Uint8Array): string => Buffer.from(value).toString('hex');

const secretKey = bytes(vector.secretSeedHex);
const publicKey = bytes(vector.publicKeyHex);
const artifact = bytes(vector.artifactHex);
const objectArtifact = bytes(envelope.artifactHex);
const aad: VaultObjectAad = {
  vaultId: bytes(aadVector.vaultIdHex), objectId: bytes(aadVector.objectIdHex),
  objectType: aadVector.objectType, objectVersion: aadVector.objectVersion,
  epoch: aadVector.epoch, keyId: bytes(aadVector.keyIdHex),
  createdByDevice: bytes(aadVector.createdByDeviceHex)
};
const header = decodeOperationHeader(bytes(vector.headerHex));

describe('V1 signed operation', () => {
  it('matches the independent OpenSSL Ed25519 artifact byte for byte', () => {
    expect(hex(ed25519.getPublicKey(secretKey))).toBe(vector.publicKeyHex);
    expect(hex(signOperation(secretKey, header))).toBe(vector.artifactHex);
    const verified = verifyOperation(publicKey, aad, artifact, objectArtifact);
    expect(verified.header).toEqual(header);
    expect(hex(verified.headerBytes)).toBe(vector.headerHex);
  });

  it('rejects every single-byte mutation of the operation artifact', () => {
    for (let index = 0; index < artifact.length; index++) {
      const mutated = artifact.slice();
      mutated[index]! ^= 0x01;
      expect(() => verifyOperation(publicKey, aad, mutated, objectArtifact), `byte ${index}`).toThrow('INVALID_OPERATION');
    }
    expect(() => verifyOperation(publicKey, aad, Uint8Array.from([...artifact, 0]), objectArtifact)).toThrow('INVALID_OPERATION');
    expect(() => verifyOperation(publicKey, aad, artifact.subarray(0, -1), objectArtifact)).toThrow('INVALID_OPERATION');
  });

  it('rejects a different object artifact, trusted context or signing device', () => {
    const otherObject = objectArtifact.slice();
    otherObject[otherObject.length - 1]! ^= 0x01;
    expect(() => verifyOperation(publicKey, aad, artifact, otherObject)).toThrow('INVALID_OPERATION');
    expect(() => verifyOperation(publicKey, { ...aad, objectVersion: 2 }, artifact, objectArtifact)).toThrow('INVALID_OPERATION');
    expect(() => verifyOperation(ed25519.getPublicKey(ed25519.utils.randomSecretKey()), aad, artifact, objectArtifact)).toThrow('INVALID_OPERATION');
  });

  it('rejects headers whose routing fields disagree with the authenticated object AAD', () => {
    for (const change of [
      { epoch: 2 }, { objectVersion: 2 }, { deviceId: new Uint8Array(16) },
      { vaultId: new Uint8Array(16) }, { objectId: new Uint8Array(16) }
    ]) {
      const signed = signOperation(secretKey, { ...header, ...change });
      expect(() => verifyOperation(publicKey, aad, signed, objectArtifact)).toThrow('INVALID_OPERATION');
    }
  });

  it('rejects small-order keys, non-canonical signatures and malformed records', () => {
    const identity = Uint8Array.of(1, ...new Uint8Array(31));
    expect(() => verifyOperation(identity, aad, artifact, objectArtifact)).toThrow('INVALID_OPERATION');
    expect(() => verifyOperation(publicKey.subarray(1), aad, artifact, objectArtifact)).toThrow('INVALID_OPERATION');
    const record = decodeSignedOperationRecord(artifact);
    const highS = record.signature.slice();
    // S + L, where L is the Ed25519 group order: same scalar mod L, but non-canonical.
    let carry = 0;
    const order = bytes('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010');
    for (let index = 0; index < 32; index++) {
      const sum = highS[32 + index]! + order[index]! + carry;
      highS[32 + index] = sum & 0xff;
      carry = sum >> 8;
    }
    const malleated = encodeSignedOperationRecord({ headerBytes: record.headerBytes, signature: highS });
    expect(() => verifyOperation(publicKey, aad, malleated, objectArtifact)).toThrow('INVALID_OPERATION');
    expect(() => encodeSignedOperationRecord({ headerBytes: record.headerBytes, signature: new Uint8Array(63) })).toThrow('INVALID_OPERATION');
    expect(() => encodeSignedOperationRecord({ headerBytes: Uint8Array.of(0xa0), signature: record.signature })).toThrow('INVALID_OPERATION');
    expect(() => signOperation(new Uint8Array(31), header)).toThrow('INVALID_OPERATION');
  });

  it('rejects shared negative vectors that libsodium also rejects (small-order R, mixed-order key)', () => {
    expect(vector.negativeCases.map(entry => entry.name)).toEqual(['small-order-R', 'mixed-order-public-key']);
    for (const entry of vector.negativeCases) {
      const signed = encodeSignedOperationRecord({ headerBytes: bytes(vector.headerHex), signature: bytes(entry.signatureHex) });
      // Proves the case is meaningful: a cofactored verifier alone would accept it.
      expect(ed25519.verify(bytes(entry.signatureHex), bytes(vector.headerHex), bytes(entry.publicKeyHex), { zip215: false })).toBe(true);
      expect(() => verifyOperation(bytes(entry.publicKeyHex), aad, signed, objectArtifact), entry.name).toThrow('INVALID_OPERATION');
    }
  });
});
