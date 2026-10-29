import { decodeDeterministicCbor, encodeDeterministicCbor, type CborValue } from './cbor.js';
import { decodeOperationHeader } from './operation-header.js';

export interface SignedOperationRecord {
  headerBytes: Uint8Array;
  signature: Uint8Array;
}

const MAGIC = Uint8Array.of(0x53, 0x50, 0x43, 0x45);
const VERSION = 1;
const OPERATION_KIND = 2;
const MAX_HEADER_BYTES = 16 * 1024;
const MAX_ARTIFACT_BYTES = 32 * 1024;

function checked(record: SignedOperationRecord): SignedOperationRecord {
  if (!(record.headerBytes instanceof Uint8Array) || record.headerBytes.length > MAX_HEADER_BYTES ||
      !(record.signature instanceof Uint8Array) || record.signature.length !== 64) {
    throw new Error('INVALID_OPERATION');
  }
  decodeOperationHeader(record.headerBytes);
  return { headerBytes: record.headerBytes.slice(), signature: record.signature.slice() };
}

/** Frames already-encoded header bytes; it never re-encodes the signed header. */
export function encodeSignedOperationRecord(input: SignedOperationRecord): Uint8Array {
  try {
    const record = checked(input);
    const body = encodeDeterministicCbor(new Map<number, CborValue>([[1, record.headerBytes], [2, record.signature]]));
    const framed = new Uint8Array(body.length + 11);
    framed.set(MAGIC);
    framed[5] = VERSION;
    framed[6] = OPERATION_KIND;
    new DataView(framed.buffer).setUint32(7, body.length, false);
    framed.set(body, 11);
    return framed;
  } catch { throw new Error('INVALID_OPERATION'); }
}

export function decodeSignedOperationRecord(input: Uint8Array): SignedOperationRecord {
  try {
    if (!(input instanceof Uint8Array) || input.length < 12 || input.length > MAX_ARTIFACT_BYTES ||
        MAGIC.some((byte, index) => input[index] !== byte) || input[4] !== 0 || input[5] !== VERSION ||
        input[6] !== OPERATION_KIND) throw new Error('INVALID_OPERATION');
    const length = new DataView(input.buffer, input.byteOffset, input.byteLength).getUint32(7, false);
    if (length !== input.length - 11) throw new Error('INVALID_OPERATION');
    const map = decodeDeterministicCbor(input.subarray(11));
    if (!(map instanceof Map) || map.size !== 2 || !map.has(1) || !map.has(2)) throw new Error('INVALID_OPERATION');
    return checked({ headerBytes: map.get(1) as Uint8Array, signature: map.get(2) as Uint8Array });
  } catch { throw new Error('INVALID_OPERATION'); }
}
