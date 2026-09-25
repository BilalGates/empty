import { decodeCanonicalCbor, encodeCanonicalCbor, type CanonicalCbor } from './cbor.js';
import { decodeVaultFrame, encodeVaultFrame, VAULT_ARTIFACT_KIND } from './frame.js';
import { decodeObjectAad, encodeObjectAad, type VaultObjectAad } from './object-aad.js';

export interface SealedObjectPart {
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

/** Parsed bytes remain unauthenticated until both AEAD tags have been verified. */
export interface UnauthenticatedObjectRecord {
  aad: VaultObjectAad;
  wrappedDek: SealedObjectPart;
  payload: SealedObjectPart;
}

const MAX_CIPHERTEXT_BYTES = 1024 * 1024;
const WRAPPED_DEK_BYTES = 32 + 16;
const MIN_PAYLOAD_BYTES = 16;

function exactMap(value: unknown, keys: readonly number[]): Map<number, CanonicalCbor> {
  if (!(value instanceof Map) || value.size !== keys.length || keys.some(key => !value.has(key))) {
    throw new Error('Invalid object record schema');
  }
  return value as Map<number, CanonicalCbor>;
}

function part(value: unknown, wrapped: boolean): SealedObjectPart {
  const fields = exactMap(value, [1, 2]);
  const nonce = fields.get(1);
  const ciphertext = fields.get(2);
  if (!(nonce instanceof Uint8Array) || nonce.length !== 24 || !(ciphertext instanceof Uint8Array) ||
      (wrapped ? ciphertext.length !== WRAPPED_DEK_BYTES : ciphertext.length < MIN_PAYLOAD_BYTES) ||
      ciphertext.length > MAX_CIPHERTEXT_BYTES) {
    throw new Error('Invalid object ciphertext');
  }
  return { nonce: nonce.slice(), ciphertext: ciphertext.slice() };
}

function partMap(value: SealedObjectPart, wrapped: boolean): Map<number, CanonicalCbor> {
  if (value === null || typeof value !== 'object') throw new Error('Invalid object ciphertext');
  const validated = part(new Map<number, CanonicalCbor>([[1, value.nonce], [2, value.ciphertext]]), wrapped);
  return new Map<number, CanonicalCbor>([[1, validated.nonce], [2, validated.ciphertext]]);
}

export function encodeObjectRecord(value: UnauthenticatedObjectRecord): Uint8Array {
  if (value === null || typeof value !== 'object') throw new Error('Invalid object record');
  const aad = decodeCanonicalCbor(encodeObjectAad(value.aad));
  const record = new Map<number, CanonicalCbor>([
    [1, aad], [2, partMap(value.wrappedDek, true)], [3, partMap(value.payload, false)]
  ]);
  return encodeVaultFrame(VAULT_ARTIFACT_KIND.object, record);
}

export function decodeObjectRecord(input: Uint8Array): UnauthenticatedObjectRecord {
  const record = exactMap(decodeVaultFrame(input, VAULT_ARTIFACT_KIND.object), [1, 2, 3]);
  const aad = record.get(1);
  if (!(aad instanceof Map)) throw new Error('Invalid object AAD schema');
  return {
    aad: decodeObjectAad(encodeCanonicalCbor(aad)),
    wrappedDek: part(record.get(2), true),
    payload: part(record.get(3), false)
  };
}
