import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { argon2id } from '@noble/hashes/argon2';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import {
  decodeKeySlotAad, decodeKeySlotRecord, encodeKeySlotAad, encodeKeySlotRecord, KEY_SLOT_ARGON2ID, type KeySlotAad
} from '@empty/protocol';
import { wipe } from './encoding.js';

const encoder = new TextEncoder();
const PASSWORD_KEK_INFO = encoder.encode('empty/password-kek/v1');
const RECOVERY_KEK_INFO = encoder.encode('empty/recovery-kek/v1');
const RECOVERY_CHECK_PREFIX = encoder.encode('empty/recovery-check/v1');
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u;

/** Trusted routing context supplied by the caller; artifact fields never substitute for it. */
export interface KeySlotContext {
  vaultId: Uint8Array;
  slotId: Uint8Array;
  epoch: number;
}

function randomBytes(length: number): Uint8Array {
  const result = new Uint8Array(length);
  globalThis.crypto.getRandomValues(result);
  return result;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  let difference = left.length ^ right.length;
  for (let index = 0; index < Math.max(left.length, right.length); index++) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

/** NFC, then UTF-8; no trim or case folding. 1..1024 bytes after normalization. */
export function normalizeMasterPassword(password: string): Uint8Array {
  if (typeof password !== 'string') throw new Error('INVALID_KEY_SLOT');
  const normalized = password.normalize('NFC');
  // Lone surrogates cannot be encoded as valid UTF-8; TextEncoder would silently replace them.
  if (LONE_SURROGATE.test(normalized)) throw new Error('INVALID_KEY_SLOT');
  const bytes = encoder.encode(normalized);
  if (bytes.length < 1 || bytes.length > 1024) throw new Error('INVALID_KEY_SLOT');
  return bytes;
}

function passwordKek(password: string, salt: Uint8Array, context: KeySlotContext): Uint8Array {
  const passwordBytes = normalizeMasterPassword(password);
  let stretched: Uint8Array | undefined;
  try {
    stretched = argon2id(passwordBytes, salt, {
      m: KEY_SLOT_ARGON2ID.memoryKiB, t: KEY_SLOT_ARGON2ID.iterations, p: KEY_SLOT_ARGON2ID.parallelism, dkLen: 32
    });
    return hkdf(sha256, stretched, context.vaultId, concat(PASSWORD_KEK_INFO, context.slotId), 32);
  } finally {
    wipe(passwordBytes);
    if (stretched) wipe(stretched);
  }
}

function recoveryKek(secret: Uint8Array, context: KeySlotContext): Uint8Array {
  if (!(secret instanceof Uint8Array) || secret.length !== 32) throw new Error('INVALID_KEY_SLOT');
  return hkdf(sha256, secret, context.vaultId, concat(RECOVERY_KEK_INFO, context.slotId), 32);
}

function seal(kek: Uint8Array, aad: KeySlotAad, vrk: Uint8Array): Uint8Array {
  if (!(vrk instanceof Uint8Array) || vrk.length !== 32) throw new Error('INVALID_KEY_SLOT');
  const aadBytes = encodeKeySlotAad(aad);
  const nonce = randomBytes(24);
  return encodeKeySlotRecord({ aad: aadBytes, nonce, ciphertext: xchacha20poly1305(kek, nonce, aadBytes).encrypt(vrk) });
}

function expectedAad(record: { aad: Uint8Array }, slotType: KeySlotAad['slotType'], context: KeySlotContext): KeySlotAad {
  const aad = decodeKeySlotAad(record.aad);
  const trusted = encodeKeySlotAad({ ...aad, slotType, vaultId: context.vaultId, slotId: context.slotId, epoch: context.epoch });
  if (!equalBytes(record.aad, trusted)) throw new Error('INVALID_KEY_SLOT');
  return aad;
}

function open(kek: Uint8Array, record: { aad: Uint8Array; nonce: Uint8Array; ciphertext: Uint8Array }): Uint8Array {
  const vrk = xchacha20poly1305(kek, record.nonce, record.aad).decrypt(record.ciphertext);
  if (vrk.length !== 32) throw new Error('INVALID_KEY_SLOT');
  return vrk;
}

/** Fresh salt and nonce on every call. Runs Argon2id at the fixed V1 cost (64 MiB, t=3, p=4). */
export function sealPasswordSlot(vrk: Uint8Array, context: KeySlotContext, password: string): Uint8Array {
  let kek: Uint8Array | undefined;
  try {
    const salt = randomBytes(16);
    kek = passwordKek(password, salt, context);
    return seal(kek, { slotType: 'password', ...context, salt }, vrk);
  } catch { throw new Error('INVALID_KEY_SLOT'); }
  finally { if (kek) wipe(kek); }
}

/** Single external error for wrong password, tampering, or context mismatch. */
export function openPasswordSlot(artifact: Uint8Array, context: KeySlotContext, password: string): Uint8Array {
  let kek: Uint8Array | undefined;
  try {
    const record = decodeKeySlotRecord(artifact);
    const aad = expectedAad(record, 'password', context);
    kek = passwordKek(password, aad.salt!, context);
    return open(kek, record);
  } catch { throw new Error('INVALID_KEY_SLOT'); }
  finally { if (kek) wipe(kek); }
}

export function sealRecoverySlot(vrk: Uint8Array, context: KeySlotContext, secret: Uint8Array): Uint8Array {
  let kek: Uint8Array | undefined;
  try {
    kek = recoveryKek(secret, context);
    return seal(kek, { slotType: 'recovery', ...context }, vrk);
  } catch { throw new Error('INVALID_KEY_SLOT'); }
  finally { if (kek) wipe(kek); }
}

export function openRecoverySlot(artifact: Uint8Array, context: KeySlotContext, encodedRecoveryKey: string): Uint8Array {
  let kek: Uint8Array | undefined;
  let secret: Uint8Array | undefined;
  try {
    const record = decodeKeySlotRecord(artifact);
    expectedAad(record, 'recovery', context);
    secret = decodeRecoveryKey(encodedRecoveryKey);
    kek = recoveryKek(secret, context);
    return open(kek, record);
  } catch { throw new Error('INVALID_KEY_SLOT'); }
  finally {
    if (kek) wipe(kek);
    if (secret) wipe(secret);
  }
}

function base32(bytes: Uint8Array, characters: number): string {
  let output = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5 && output.length < characters) {
      output += BASE32[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
    buffer &= (1 << bits) - 1;
  }
  if (output.length < characters && bits > 0) output += BASE32[(buffer << (5 - bits)) & 31];
  return output.slice(0, characters);
}

function recoveryCheck(secret: Uint8Array): string {
  return base32(sha256(concat(RECOVERY_CHECK_PREFIX, secret)).subarray(0, 3), 4);
}

/** Generates a fresh 256-bit recovery secret. Show `encodeRecoveryKey` once; never persist it in clear. */
export function generateRecoverySecret(): Uint8Array {
  return randomBytes(32);
}

/** 52 unpadded Base32 characters in groups of four, then a four-character checksum group. */
export function encodeRecoveryKey(secret: Uint8Array): string {
  if (!(secret instanceof Uint8Array) || secret.length !== 32) throw new Error('INVALID_KEY_SLOT');
  const data = base32(secret, 52);
  const groups = data.match(/.{4}/gu)!;
  return [...groups, recoveryCheck(secret)].join('-');
}

/** Accepts any case, spaces and hyphens; rejects wrong length, non-zero pad bits and bad checksum. */
export function decodeRecoveryKey(encoded: string): Uint8Array {
  // ASCII Base32 letters/digits plus space, tab, CR, LF and hyphen only, checked before case folding.
  if (typeof encoded !== 'string' || encoded.length > 128 || !/^[A-Za-z2-7 \t\r\n-]*$/u.test(encoded)) {
    throw new Error('INVALID_KEY_SLOT');
  }
  const compact = encoded.toUpperCase().replace(/[ \t\r\n-]/gu, '');
  if (compact.length !== 56) throw new Error('INVALID_KEY_SLOT');
  const secret = new Uint8Array(32);
  let buffer = 0;
  let bits = 0;
  let offset = 0;
  for (const character of compact.slice(0, 52)) {
    const value = BASE32.indexOf(character);
    if (value < 0) throw new Error('INVALID_KEY_SLOT');
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      secret[offset++] = (buffer >>> (bits - 8)) & 0xff;
      bits -= 8;
      buffer &= (1 << bits) - 1;
    }
  }
  if (offset !== 32 || buffer !== 0) { wipe(secret); throw new Error('INVALID_KEY_SLOT'); }
  if (recoveryCheck(secret) !== compact.slice(52)) { wipe(secret); throw new Error('INVALID_KEY_SLOT'); }
  return secret;
}
