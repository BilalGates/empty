import { decodeDeterministicCbor, encodeDeterministicCbor, type CborValue } from './cbor.js';

export interface OperationHeader {
  vaultId: Uint8Array;
  epoch: number;
  opId: Uint8Array;
  deviceId: Uint8Array;
  deviceSeq: number;
  parentHeads: Uint8Array[];
  objectId: Uint8Array;
  objectVersion: number;
  ciphertextHash: Uint8Array;
}

const MAX_HEADER_BYTES = 16 * 1024;
const MAX_PARENTS = 64;

function bytes(value: unknown, length: number): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) throw new Error('INVALID_OPERATION_HEADER');
  return value.slice();
}

function positive(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) throw new Error('INVALID_OPERATION_HEADER');
  return value;
}

function compare(left: Uint8Array, right: Uint8Array): number {
  for (let index = 0; index < left.length; index++) {
    if (left[index] !== right[index]) return left[index]! - right[index]!;
  }
  return 0;
}

function checked(input: OperationHeader): OperationHeader {
  if (!Array.isArray(input.parentHeads) || input.parentHeads.length > MAX_PARENTS) {
    throw new Error('INVALID_OPERATION_HEADER');
  }
  const parentHeads = input.parentHeads.map(parent => bytes(parent, 16));
  for (let index = 1; index < parentHeads.length; index++) {
    if (compare(parentHeads[index - 1]!, parentHeads[index]!) >= 0) throw new Error('INVALID_OPERATION_HEADER');
  }
  return {
    vaultId: bytes(input.vaultId, 16), epoch: positive(input.epoch), opId: bytes(input.opId, 16),
    deviceId: bytes(input.deviceId, 16), deviceSeq: positive(input.deviceSeq), parentHeads,
    objectId: bytes(input.objectId, 16), objectVersion: positive(input.objectVersion),
    ciphertextHash: bytes(input.ciphertextHash, 32)
  };
}

export function encodeOperationHeader(input: OperationHeader): Uint8Array {
  try {
    const value = checked(input);
    return encodeDeterministicCbor(new Map<number, CborValue>([
      [1, 'space.vault/1'], [2, 'operation'], [3, value.vaultId], [4, value.epoch],
      [5, value.opId], [6, value.deviceId], [7, value.deviceSeq], [8, value.parentHeads],
      [9, value.objectId], [10, value.objectVersion], [11, value.ciphertextHash]
    ]), MAX_HEADER_BYTES);
  } catch { throw new Error('INVALID_OPERATION_HEADER'); }
}

export function decodeOperationHeader(input: Uint8Array): OperationHeader {
  try {
    if (!(input instanceof Uint8Array) || input.length > MAX_HEADER_BYTES) throw new Error('INVALID_OPERATION_HEADER');
    const map = decodeDeterministicCbor(input);
    if (!(map instanceof Map) || map.size !== 11 ||
        Array.from({ length: 11 }, (_, index) => index + 1).some((key) => !map.has(key)) ||
        map.get(1) !== 'space.vault/1' || map.get(2) !== 'operation') throw new Error('INVALID_OPERATION_HEADER');
    const parents = map.get(8);
    if (!Array.isArray(parents)) throw new Error('INVALID_OPERATION_HEADER');
    return checked({
      vaultId: map.get(3) as Uint8Array, epoch: map.get(4) as number,
      opId: map.get(5) as Uint8Array, deviceId: map.get(6) as Uint8Array,
      deviceSeq: map.get(7) as number, parentHeads: parents as Uint8Array[],
      objectId: map.get(9) as Uint8Array, objectVersion: map.get(10) as number,
      ciphertextHash: map.get(11) as Uint8Array
    });
  } catch { throw new Error('INVALID_OPERATION_HEADER'); }
}
