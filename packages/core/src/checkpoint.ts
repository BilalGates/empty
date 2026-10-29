import { hkdf } from '@noble/hashes/hkdf';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha2';
import {
  compareBytes, decodeCheckpoint, decodeSealedCheckpointRecord, encodeCheckpoint, encodeSealedCheckpointRecord,
  type Checkpoint
} from '@space/protocol';
import { wipe } from './encoding.js';

const CHECKPOINT_INFO = new TextEncoder().encode('space/checkpoint/v1');

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  let difference = left.length ^ right.length;
  for (let index = 0; index < Math.max(left.length, right.length); index++) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function checkpointKey(vrk: Uint8Array, vaultId: Uint8Array): Uint8Array {
  if (!(vrk instanceof Uint8Array) || vrk.length !== 32 || !(vaultId instanceof Uint8Array) || vaultId.length !== 16) {
    throw new Error('INVALID_CHECKPOINT');
  }
  return hkdf(sha256, vrk, vaultId, CHECKPOINT_INFO, 32);
}

export function sealCheckpoint(vrk: Uint8Array, checkpoint: Checkpoint): Uint8Array {
  let key: Uint8Array | undefined;
  try {
    const checkpointBytes = encodeCheckpoint(checkpoint);
    key = checkpointKey(vrk, checkpoint.vaultId);
    return encodeSealedCheckpointRecord({ checkpointBytes, mac: hmac(sha256, key, checkpointBytes) });
  } catch { throw new Error('INVALID_CHECKPOINT'); }
  finally { if (key) wipe(key); }
}

/** Verifies the MAC under the trusted vault ID before parsing the checkpoint body. */
export function openCheckpoint(vrk: Uint8Array, expectedVaultId: Uint8Array, artifact: Uint8Array): Checkpoint {
  let key: Uint8Array | undefined;
  try {
    const record = decodeSealedCheckpointRecord(artifact);
    key = checkpointKey(vrk, expectedVaultId);
    if (!equalBytes(hmac(sha256, key, record.checkpointBytes), record.mac)) throw new Error('INVALID_CHECKPOINT');
    const checkpoint = decodeCheckpoint(record.checkpointBytes);
    if (!equalBytes(checkpoint.vaultId, expectedVaultId)) throw new Error('INVALID_CHECKPOINT');
    return checkpoint;
  } catch { throw new Error('INVALID_CHECKPOINT'); }
  finally { if (key) wipe(key); }
}

/**
 * Necessary (not sufficient) rollback check: `next` must keep the vault, never lower the epoch, and
 * never forget or lower any device sequence. DAG ancestry of `next.heads` from `previous.heads`
 * must still be proven by the caller against authenticated operations.
 */
export function checkpointCannotBeRollback(previous: Checkpoint, next: Checkpoint): boolean {
  // Fail closed on unvalidated input: the merge walk below requires strictly sorted, unique IDs.
  try { encodeCheckpoint(previous); encodeCheckpoint(next); } catch { return false; }
  if (!equalBytes(previous.vaultId, next.vaultId) || next.epoch < previous.epoch) return false;
  let cursor = 0;
  for (const entry of previous.deviceSeqs) {
    while (cursor < next.deviceSeqs.length && compareBytes(next.deviceSeqs[cursor]!.deviceId, entry.deviceId) < 0) cursor++;
    const match = next.deviceSeqs[cursor];
    if (!match || compareBytes(match.deviceId, entry.deviceId) !== 0 || match.deviceSeq < entry.deviceSeq) return false;
  }
  return true;
}
