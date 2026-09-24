import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import {
  decodeDeterministicCbor, decodeVaultObjectRecord, encodeDeterministicCbor,
  encodeVaultObjectAad, encodeVaultObjectRecord, MAX_OBJECT_PLAINTEXT_BYTES,
  type CborValue, type VaultObjectAad
} from '@space/protocol';
import { wipe } from './encoding.js';

const VWK_INFO = new TextEncoder().encode('space/vwk/v1');
const DEK_SUFFIX = new TextEncoder().encode('\0dek');
const PAYLOAD_SUFFIX = new TextEncoder().encode('\0payload');

function randomBytes(length: number): Uint8Array {
  const result = new Uint8Array(length);
  globalThis.crypto.getRandomValues(result);
  return result;
}

function contextAad(aad: Uint8Array, suffix: Uint8Array): Uint8Array {
  const result = new Uint8Array(aad.length + suffix.length);
  result.set(aad);
  result.set(suffix, aad.length);
  return result;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  let difference = left.length ^ right.length;
  for (let index = 0; index < Math.max(left.length, right.length); index++) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function vaultWrapKey(vrk: Uint8Array, vaultId: Uint8Array): Uint8Array {
  if (!(vrk instanceof Uint8Array) || vrk.length !== 32) throw new Error('INVALID_ENVELOPE');
  return hkdf(sha256, vrk, vaultId, VWK_INFO, 32);
}

/** Produces a new per-version DEK and fresh XChaCha nonces on every call. */
export function sealVaultObject(vrk: Uint8Array, aad: VaultObjectAad, payload: CborValue): Uint8Array {
  const aadBytes = encodeVaultObjectAad(aad);
  let vwk: Uint8Array | undefined;
  let dek: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    vwk = vaultWrapKey(vrk, aad.vaultId);
    plaintext = encodeDeterministicCbor(payload, MAX_OBJECT_PLAINTEXT_BYTES);
    dek = randomBytes(32);
    const dekNonce = randomBytes(24);
    const payloadNonce = randomBytes(24);
    const wrappedDek = xchacha20poly1305(vwk, dekNonce, contextAad(aadBytes, DEK_SUFFIX)).encrypt(dek);
    const ciphertext = xchacha20poly1305(dek, payloadNonce, contextAad(aadBytes, PAYLOAD_SUFFIX)).encrypt(plaintext);
    return encodeVaultObjectRecord({
      aad: aadBytes,
      wrappedDek: { nonce: dekNonce, ciphertext: wrappedDek },
      payload: { nonce: payloadNonce, ciphertext }
    });
  } catch {
    throw new Error('INVALID_ENVELOPE');
  } finally {
    if (plaintext) wipe(plaintext);
    if (vwk) wipe(vwk);
    if (dek) wipe(dek);
  }
}

/** The caller supplies trusted routing metadata; no field from the record substitutes for it. */
export function openVaultObject(vrk: Uint8Array, expected: VaultObjectAad, artifact: Uint8Array): CborValue {
  let vwk: Uint8Array | undefined;
  let dek: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    const expectedBytes = encodeVaultObjectAad(expected);
    const record = decodeVaultObjectRecord(artifact);
    if (!equalBytes(record.aad, expectedBytes)) throw new Error('INVALID_ENVELOPE');
    vwk = vaultWrapKey(vrk, expected.vaultId);
    dek = xchacha20poly1305(vwk, record.wrappedDek.nonce, contextAad(expectedBytes, DEK_SUFFIX)).decrypt(record.wrappedDek.ciphertext);
    if (dek.length !== 32) throw new Error('INVALID_ENVELOPE');
    plaintext = xchacha20poly1305(dek, record.payload.nonce, contextAad(expectedBytes, PAYLOAD_SUFFIX)).decrypt(record.payload.ciphertext);
    if (plaintext.length > MAX_OBJECT_PLAINTEXT_BYTES) throw new Error('INVALID_ENVELOPE');
    return decodeDeterministicCbor(plaintext);
  } catch {
    throw new Error('INVALID_ENVELOPE');
  } finally {
    if (vwk) wipe(vwk);
    if (dek) wipe(dek);
    if (plaintext) wipe(plaintext);
  }
}
