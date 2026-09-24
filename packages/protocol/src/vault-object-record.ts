import { decodeDeterministicCbor, encodeDeterministicCbor, type CborValue } from './cbor.js';
import { decodeVaultObjectAad } from './vault-aad.js';

export interface SealedBytes { nonce: Uint8Array; ciphertext: Uint8Array }
export interface VaultObjectRecord {
  aad: Uint8Array;
  wrappedDek: SealedBytes;
  payload: SealedBytes;
}

const MAGIC = Uint8Array.of(0x53, 0x50, 0x43, 0x45);
const VERSION = 1;
const OBJECT_KIND = 1;
export const MAX_OBJECT_PLAINTEXT_BYTES = 1024 * 1024 - 16;
const MAX_PAYLOAD_CIPHERTEXT_BYTES = 1024 * 1024;
const MAX_ARTIFACT_BYTES = 16 * 1024 * 1024;

function checkedRecord(record: VaultObjectRecord): VaultObjectRecord {
  if (!(record.aad instanceof Uint8Array) || record.aad.length > 16 * 1024) throw new Error('INVALID_ENVELOPE');
  decodeVaultObjectAad(record.aad);
  for (const sealed of [record.wrappedDek, record.payload]) {
    if (!(sealed.nonce instanceof Uint8Array) || sealed.nonce.length !== 24 || !(sealed.ciphertext instanceof Uint8Array)) {
      throw new Error('INVALID_ENVELOPE');
    }
  }
  if (record.wrappedDek.ciphertext.length !== 48 || record.payload.ciphertext.length < 16 ||
      record.payload.ciphertext.length > MAX_PAYLOAD_CIPHERTEXT_BYTES) throw new Error('INVALID_ENVELOPE');
  return record;
}

function sealedMap(sealed: SealedBytes): Map<number, CborValue> {
  return new Map<number, CborValue>([[1, sealed.nonce], [2, sealed.ciphertext]]);
}

export function encodeVaultObjectRecord(input: VaultObjectRecord): Uint8Array {
  const record = checkedRecord(input);
  const body = encodeDeterministicCbor(new Map<number, CborValue>([
    [1, record.aad], [2, sealedMap(record.wrappedDek)], [3, sealedMap(record.payload)]
  ]));
  if (body.length + 11 > MAX_ARTIFACT_BYTES) throw new Error('INVALID_ENVELOPE');
  const framed = new Uint8Array(body.length + 11);
  framed.set(MAGIC);
  framed[4] = 0;
  framed[5] = VERSION;
  framed[6] = OBJECT_KIND;
  new DataView(framed.buffer).setUint32(7, body.length, false);
  framed.set(body, 11);
  return framed;
}

function exactMap(value: CborValue, keys: readonly number[]): Map<number, CborValue> {
  if (!(value instanceof Map) || value.size !== keys.length || keys.some(key => !value.has(key))) throw new Error('INVALID_ENVELOPE');
  return value;
}

function sealedValue(value: CborValue): SealedBytes {
  const map = exactMap(value, [1, 2]);
  const nonce = map.get(1);
  const ciphertext = map.get(2);
  if (!(nonce instanceof Uint8Array) || !(ciphertext instanceof Uint8Array)) throw new Error('INVALID_ENVELOPE');
  return { nonce, ciphertext };
}

export function decodeVaultObjectRecord(input: Uint8Array): VaultObjectRecord {
  try {
    if (!(input instanceof Uint8Array) || input.length < 12 || input.length > MAX_ARTIFACT_BYTES ||
        MAGIC.some((byte, index) => input[index] !== byte) || input[4] !== 0 || input[5] !== VERSION || input[6] !== OBJECT_KIND) {
      throw new Error('INVALID_ENVELOPE');
    }
    const length = new DataView(input.buffer, input.byteOffset, input.byteLength).getUint32(7, false);
    if (length !== input.length - 11) throw new Error('INVALID_ENVELOPE');
    const map = exactMap(decodeDeterministicCbor(input.subarray(11)), [1, 2, 3]);
    const aad = map.get(1);
    if (!(aad instanceof Uint8Array)) throw new Error('INVALID_ENVELOPE');
    return checkedRecord({ aad, wrappedDek: sealedValue(map.get(2)!), payload: sealedValue(map.get(3)!) });
  } catch {
    throw new Error('INVALID_ENVELOPE');
  }
}
