import { readFileSync } from 'node:fs';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import {
  decodeCheckpoint, decodeDeterministicCbor, decodeSealedCheckpointRecord, encodeCheckpoint, encodeDeterministicCbor,
  encodeSealedCheckpointRecord, type CborValue, type Checkpoint
} from '@space/protocol';
import { describe, expect, it } from 'vitest';
import { checkpointCannotBeRollback, openCheckpoint, sealCheckpoint } from './checkpoint.js';

const vector = JSON.parse(readFileSync(new URL('../../../test-vectors/checkpoint-v1.json', import.meta.url), 'utf8')) as {
  vrkHex: string; vaultIdHex: string; epoch: number; headsHex: string[];
  deviceSeqs: Array<{ deviceIdHex: string; deviceSeq: number }>;
  checkpointKeyHex: string; checkpointHex: string; macHex: string; artifactHex: string;
};
const bytes = (hex: string): Uint8Array => Uint8Array.from(Buffer.from(hex, 'hex'));
const hex = (value: Uint8Array): string => Buffer.from(value).toString('hex');
const vrk = bytes(vector.vrkHex);
const vaultId = bytes(vector.vaultIdHex);
const artifact = bytes(vector.artifactHex);
const checkpoint: Checkpoint = {
  vaultId, epoch: vector.epoch, heads: vector.headsHex.map(bytes),
  deviceSeqs: vector.deviceSeqs.map(entry => ({ deviceId: bytes(entry.deviceIdHex), deviceSeq: entry.deviceSeq }))
};
const id = (byte: number): Uint8Array => new Uint8Array(16).fill(byte);

describe('V1 sealed checkpoint', () => {
  it('matches the independent Python HKDF/HMAC artifact byte for byte', () => {
    expect(hex(hkdf(sha256, vrk, vaultId, new TextEncoder().encode('space/checkpoint/v1'), 32))).toBe(vector.checkpointKeyHex);
    expect(hex(encodeCheckpoint(checkpoint))).toBe(vector.checkpointHex);
    expect(hex(sealCheckpoint(vrk, checkpoint))).toBe(vector.artifactHex);
    expect(openCheckpoint(vrk, vaultId, artifact)).toEqual(checkpoint);
  });

  it('rejects every single-byte mutation, truncation, wrong VRK and wrong vault', () => {
    for (let index = 0; index < artifact.length; index++) {
      const mutated = artifact.slice();
      mutated[index]! ^= 0x01;
      expect(() => openCheckpoint(vrk, vaultId, mutated), `byte ${index}`).toThrow('INVALID_CHECKPOINT');
    }
    expect(() => openCheckpoint(vrk, vaultId, Uint8Array.from([...artifact, 0]))).toThrow('INVALID_CHECKPOINT');
    expect(() => openCheckpoint(vrk, vaultId, artifact.subarray(0, -1))).toThrow('INVALID_CHECKPOINT');
    expect(() => openCheckpoint(new Uint8Array(32), vaultId, artifact)).toThrow('INVALID_CHECKPOINT');
    expect(() => openCheckpoint(vrk, id(9), artifact)).toThrow('INVALID_CHECKPOINT');
  });

  it('rejects malformed checkpoint bodies even with a correct MAC shape', () => {
    expect(() => encodeCheckpoint({ ...checkpoint, heads: [] })).toThrow('INVALID_CHECKPOINT');
    expect(() => encodeCheckpoint({ ...checkpoint, heads: [...checkpoint.heads].reverse() })).toThrow('INVALID_CHECKPOINT');
    expect(() => encodeCheckpoint({ ...checkpoint, heads: Array.from({ length: 65 }, (_, index) => id(index)) })).toThrow('INVALID_CHECKPOINT');
    expect(() => encodeCheckpoint({ ...checkpoint, deviceSeqs: [] })).toThrow('INVALID_CHECKPOINT');
    expect(() => encodeCheckpoint({ ...checkpoint, deviceSeqs: [...checkpoint.deviceSeqs].reverse() })).toThrow('INVALID_CHECKPOINT');
    expect(() => encodeCheckpoint({ ...checkpoint, deviceSeqs: [{ deviceId: id(1), deviceSeq: 0 }] })).toThrow('INVALID_CHECKPOINT');
    expect(() => encodeCheckpoint({ ...checkpoint, epoch: Number.MAX_SAFE_INTEGER + 1 })).toThrow('INVALID_CHECKPOINT');
    const map = decodeDeterministicCbor(bytes(vector.checkpointHex)) as Map<number, CborValue>;
    map.set(7, null);
    expect(() => decodeCheckpoint(encodeDeterministicCbor(map))).toThrow('INVALID_CHECKPOINT');
    map.delete(7); map.set(6, [[id(1), 1, 0]]);
    expect(() => decodeCheckpoint(encodeDeterministicCbor(map))).toThrow('INVALID_CHECKPOINT');
    map.set(6, [[id(1), 1]]); map.set(2, 'operation');
    expect(() => decodeCheckpoint(encodeDeterministicCbor(map))).toThrow('INVALID_CHECKPOINT');
    const record = decodeSealedCheckpointRecord(artifact);
    expect(() => encodeSealedCheckpointRecord({ ...record, mac: new Uint8Array(31) })).toThrow('INVALID_CHECKPOINT');
  });

  it('rejects a kind=2 signed-operation frame and other artifact kinds', () => {
    const wrongKind = artifact.slice();
    wrongKind[6] = 2;
    expect(() => openCheckpoint(vrk, vaultId, wrongKind)).toThrow('INVALID_CHECKPOINT');
  });

  it('detects lowered epoch, lowered or forgotten device sequences, and vault changes', () => {
    const [first, second] = checkpoint.deviceSeqs as [Checkpoint['deviceSeqs'][0], Checkpoint['deviceSeqs'][0]];
    const advanced: Checkpoint = {
      ...checkpoint, epoch: 2,
      deviceSeqs: [{ ...first, deviceSeq: 3 }, { deviceId: id(0x50), deviceSeq: 1 }, second]
    };
    expect(checkpointCannotBeRollback(checkpoint, checkpoint)).toBe(true);
    expect(checkpointCannotBeRollback(checkpoint, advanced)).toBe(true);
    expect(checkpointCannotBeRollback(advanced, checkpoint)).toBe(false);
    expect(checkpointCannotBeRollback(checkpoint, { ...checkpoint, deviceSeqs: [{ ...first, deviceSeq: 1 }, second] })).toBe(false);
    expect(checkpointCannotBeRollback(checkpoint, { ...checkpoint, deviceSeqs: [second] })).toBe(false);
    expect(checkpointCannotBeRollback(checkpoint, { ...checkpoint, vaultId: id(9) })).toBe(false);
    expect(checkpointCannotBeRollback({ ...checkpoint, deviceSeqs: [first, first] }, checkpoint)).toBe(false);
    expect(checkpointCannotBeRollback(checkpoint, { ...checkpoint, deviceSeqs: [first, first, second] })).toBe(false);
  });
});
