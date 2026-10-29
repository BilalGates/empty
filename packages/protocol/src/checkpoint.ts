import { decodeDeterministicCbor, encodeDeterministicCbor, type CborValue } from './cbor.js';

export interface DeviceSequence {
  deviceId: Uint8Array;
  deviceSeq: number;
}

export interface Checkpoint {
  vaultId: Uint8Array;
  epoch: number;
  /** Current DAG heads: 1..64 op IDs in strict lexicographic order. */
  heads: Uint8Array[];
  /** Highest accepted sequence per device, strictly ordered by device ID. */
  deviceSeqs: DeviceSequence[];
}

export interface SealedCheckpointRecord {
  checkpointBytes: Uint8Array;
  mac: Uint8Array;
}

const MAGIC = Uint8Array.of(0x53, 0x50, 0x43, 0x45);
const VERSION = 1;
const CHECKPOINT_KIND = 3;
const MAX_CHECKPOINT_BYTES = 16 * 1024;
const MAX_ARTIFACT_BYTES = 32 * 1024;
const MAX_HEADS = 64;
const MAX_DEVICES = 64;

function bytes(value: unknown, length: number): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) throw new Error('INVALID_CHECKPOINT');
  return value.slice();
}

function positive(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) throw new Error('INVALID_CHECKPOINT');
  return value;
}

export function compareBytes(left: Uint8Array, right: Uint8Array): number {
  for (let index = 0; index < Math.min(left.length, right.length); index++) {
    if (left[index] !== right[index]) return left[index]! - right[index]!;
  }
  return left.length - right.length;
}

function strictlySorted(values: Uint8Array[]): void {
  for (let index = 1; index < values.length; index++) {
    if (compareBytes(values[index - 1]!, values[index]!) >= 0) throw new Error('INVALID_CHECKPOINT');
  }
}

function checked(input: Checkpoint): Checkpoint {
  if (!Array.isArray(input.heads) || input.heads.length < 1 || input.heads.length > MAX_HEADS ||
      !Array.isArray(input.deviceSeqs) || input.deviceSeqs.length < 1 || input.deviceSeqs.length > MAX_DEVICES) {
    throw new Error('INVALID_CHECKPOINT');
  }
  const heads = input.heads.map(head => bytes(head, 16));
  strictlySorted(heads);
  const deviceSeqs = input.deviceSeqs.map(entry => {
    if (entry === null || typeof entry !== 'object') throw new Error('INVALID_CHECKPOINT');
    return { deviceId: bytes(entry.deviceId, 16), deviceSeq: positive(entry.deviceSeq) };
  });
  strictlySorted(deviceSeqs.map(entry => entry.deviceId));
  return { vaultId: bytes(input.vaultId, 16), epoch: positive(input.epoch), heads, deviceSeqs };
}

export function encodeCheckpoint(input: Checkpoint): Uint8Array {
  try {
    const value = checked(input);
    return encodeDeterministicCbor(new Map<number, CborValue>([
      [1, 'space.vault/1'], [2, 'checkpoint'], [3, value.vaultId], [4, value.epoch], [5, value.heads],
      [6, value.deviceSeqs.map(entry => [entry.deviceId, entry.deviceSeq])]
    ]), MAX_CHECKPOINT_BYTES);
  } catch { throw new Error('INVALID_CHECKPOINT'); }
}

export function decodeCheckpoint(input: Uint8Array): Checkpoint {
  try {
    if (!(input instanceof Uint8Array) || input.length > MAX_CHECKPOINT_BYTES) throw new Error('INVALID_CHECKPOINT');
    const map = decodeDeterministicCbor(input);
    if (!(map instanceof Map) || map.size !== 6 || [1, 2, 3, 4, 5, 6].some(key => !map.has(key)) ||
        map.get(1) !== 'space.vault/1' || map.get(2) !== 'checkpoint') throw new Error('INVALID_CHECKPOINT');
    const heads = map.get(5);
    const pairs = map.get(6);
    if (!Array.isArray(heads) || !Array.isArray(pairs)) throw new Error('INVALID_CHECKPOINT');
    return checked({
      vaultId: map.get(3) as Uint8Array, epoch: map.get(4) as number, heads: heads as Uint8Array[],
      deviceSeqs: pairs.map(pair => {
        if (!Array.isArray(pair) || pair.length !== 2) throw new Error('INVALID_CHECKPOINT');
        return { deviceId: pair[0] as Uint8Array, deviceSeq: pair[1] as number };
      })
    });
  } catch { throw new Error('INVALID_CHECKPOINT'); }
}

function frame(body: Uint8Array): Uint8Array {
  const framed = new Uint8Array(body.length + 11);
  framed.set(MAGIC);
  framed[5] = VERSION;
  framed[6] = CHECKPOINT_KIND;
  new DataView(framed.buffer).setUint32(7, body.length, false);
  framed.set(body, 11);
  return framed;
}

export function encodeSealedCheckpointRecord(input: SealedCheckpointRecord): Uint8Array {
  try {
    if (!(input.mac instanceof Uint8Array) || input.mac.length !== 32) throw new Error('INVALID_CHECKPOINT');
    decodeCheckpoint(input.checkpointBytes);
    return frame(encodeDeterministicCbor(new Map<number, CborValue>([[1, input.checkpointBytes], [2, input.mac]])));
  } catch { throw new Error('INVALID_CHECKPOINT'); }
}

/** Parses framing only; the checkpoint bytes stay unauthenticated until the caller checks the MAC. */
export function decodeSealedCheckpointRecord(input: Uint8Array): SealedCheckpointRecord {
  try {
    if (!(input instanceof Uint8Array) || input.length < 12 || input.length > MAX_ARTIFACT_BYTES ||
        MAGIC.some((byte, index) => input[index] !== byte) || input[4] !== 0 || input[5] !== VERSION ||
        input[6] !== CHECKPOINT_KIND) throw new Error('INVALID_CHECKPOINT');
    const length = new DataView(input.buffer, input.byteOffset, input.byteLength).getUint32(7, false);
    if (length !== input.length - 11) throw new Error('INVALID_CHECKPOINT');
    const map = decodeDeterministicCbor(input.subarray(11));
    if (!(map instanceof Map) || map.size !== 2 || !map.has(1) || !map.has(2)) throw new Error('INVALID_CHECKPOINT');
    const checkpointBytes = map.get(1);
    const mac = map.get(2);
    if (!(checkpointBytes instanceof Uint8Array) || checkpointBytes.length > MAX_CHECKPOINT_BYTES ||
        !(mac instanceof Uint8Array) || mac.length !== 32) throw new Error('INVALID_CHECKPOINT');
    return { checkpointBytes, mac };
  } catch { throw new Error('INVALID_CHECKPOINT'); }
}
