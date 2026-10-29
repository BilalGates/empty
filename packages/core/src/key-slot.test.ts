import { readFileSync } from 'node:fs';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import {
  decodeDeterministicCbor, decodeKeySlotAad, decodeKeySlotRecord, encodeDeterministicCbor, encodeKeySlotAad,
  encodeKeySlotRecord, type CborValue
} from '@space/protocol';
import { describe, expect, it } from 'vitest';
import {
  decodeRecoveryKey, encodeRecoveryKey, generateRecoverySecret, normalizeMasterPassword, openPasswordSlot,
  openRecoverySlot, sealPasswordSlot, sealRecoverySlot, type KeySlotContext
} from './key-slot.js';

interface SlotVector { slotIdHex: string; kekHex: string; nonceHex: string; aadHex: string; ciphertextHex: string; artifactHex: string }
const vector = JSON.parse(readFileSync(new URL('../../../test-vectors/key-slot-v1.json', import.meta.url), 'utf8')) as {
  vaultIdHex: string; vrkHex: string; epoch: number;
  password: SlotVector & { passwordUtf8Hex: string; saltHex: string; argonOutputHex: string };
  recovery: SlotVector & { secretHex: string; encoded: string };
  invalidRecoveryEncodings: string[];
  invalidArtifactsHex: Record<string, string>;
};
const bytes = (hex: string): Uint8Array => Uint8Array.from(Buffer.from(hex, 'hex'));
const hex = (value: Uint8Array): string => Buffer.from(value).toString('hex');
const vaultId = bytes(vector.vaultIdHex);
const vrk = bytes(vector.vrkHex);
const password = Buffer.from(vector.password.passwordUtf8Hex, 'hex').toString('utf8');
const passwordContext: KeySlotContext = { vaultId, slotId: bytes(vector.password.slotIdHex), epoch: vector.epoch };
const recoveryContext: KeySlotContext = { vaultId, slotId: bytes(vector.recovery.slotIdHex), epoch: vector.epoch };
const passwordArtifact = bytes(vector.password.artifactHex);
const recoveryArtifact = bytes(vector.recovery.artifactHex);
const enc = new TextEncoder();
const info = (label: string, slotId: string): Uint8Array => Uint8Array.from([...enc.encode(label), ...bytes(slotId)]);

describe('V1 key slots', () => {
  it('reproduce the independent Python AAD, KEK, ciphertext and artifact bytes', () => {
    const passwordAad = encodeKeySlotAad({ slotType: 'password', ...passwordContext, salt: bytes(vector.password.saltHex) });
    expect(hex(passwordAad)).toBe(vector.password.aadHex);
    const passwordKek = hkdf(sha256, bytes(vector.password.argonOutputHex), vaultId, info('space/password-kek/v1', vector.password.slotIdHex), 32);
    expect(hex(passwordKek)).toBe(vector.password.kekHex);
    const recoveryAad = encodeKeySlotAad({ slotType: 'recovery', ...recoveryContext });
    expect(hex(recoveryAad)).toBe(vector.recovery.aadHex);
    const recoveryKek = hkdf(sha256, bytes(vector.recovery.secretHex), vaultId, info('space/recovery-kek/v1', vector.recovery.slotIdHex), 32);
    expect(hex(recoveryKek)).toBe(vector.recovery.kekHex);
    for (const [slot, aad, kek] of [[vector.password, passwordAad, passwordKek], [vector.recovery, recoveryAad, recoveryKek]] as const) {
      const ciphertext = xchacha20poly1305(kek, bytes(slot.nonceHex), aad).encrypt(vrk);
      expect(hex(ciphertext)).toBe(slot.ciphertextHex);
      expect(hex(encodeKeySlotRecord({ aad, nonce: bytes(slot.nonceHex), ciphertext }))).toBe(slot.artifactHex);
    }
  });

  it('opens the vector password slot with Argon2id and rejects a wrong password', () => {
    expect(hex(openPasswordSlot(passwordArtifact, passwordContext, password))).toBe(vector.vrkHex);
    expect(() => openPasswordSlot(passwordArtifact, passwordContext, `${password}!`)).toThrow('INVALID_KEY_SLOT');
  }, 60_000);

  it('round-trips a fresh password slot with NFC-equivalent input', () => {
    const composed = 'contraseña-Ünïcode-2026';
    const decomposed = composed.normalize('NFD');
    expect(decomposed).not.toBe(composed);
    expect(normalizeMasterPassword(decomposed)).toEqual(normalizeMasterPassword(composed));
    const sealed = sealPasswordSlot(vrk, passwordContext, composed);
    expect(hex(openPasswordSlot(sealed, passwordContext, decomposed))).toBe(vector.vrkHex);
    expect(hex(sealPasswordSlot(vrk, passwordContext, composed))).not.toBe(hex(sealed));
  }, 60_000);

  it('rejects empty, oversized and ill-formed master passwords', () => {
    expect(() => normalizeMasterPassword('')).toThrow('INVALID_KEY_SLOT');
    expect(() => normalizeMasterPassword('a'.repeat(1025))).toThrow('INVALID_KEY_SLOT');
    expect(() => normalizeMasterPassword('abc\uD800')).toThrow('INVALID_KEY_SLOT');
    expect(normalizeMasterPassword(' a ').length).toBe(3);
  });

  it('opens and round-trips recovery slots; rejects wrong context, kind or key', () => {
    expect(encodeRecoveryKey(bytes(vector.recovery.secretHex))).toBe(vector.recovery.encoded);
    expect(hex(openRecoverySlot(recoveryArtifact, recoveryContext, vector.recovery.encoded))).toBe(vector.vrkHex);
    expect(hex(openRecoverySlot(recoveryArtifact, recoveryContext, vector.recovery.encoded.toLowerCase().replaceAll('-', ' ')))).toBe(vector.vrkHex);
    const secret = generateRecoverySecret();
    const sealed = sealRecoverySlot(vrk, recoveryContext, secret);
    expect(hex(openRecoverySlot(sealed, recoveryContext, encodeRecoveryKey(secret)))).toBe(vector.vrkHex);
    expect(() => openRecoverySlot(sealed, recoveryContext, vector.recovery.encoded)).toThrow('INVALID_KEY_SLOT');
    expect(() => openRecoverySlot(recoveryArtifact, { ...recoveryContext, epoch: 2 }, vector.recovery.encoded)).toThrow('INVALID_KEY_SLOT');
    expect(() => openRecoverySlot(recoveryArtifact, { ...recoveryContext, slotId: passwordContext.slotId }, vector.recovery.encoded)).toThrow('INVALID_KEY_SLOT');
    expect(() => openRecoverySlot(recoveryArtifact, { ...recoveryContext, vaultId: new Uint8Array(16) }, vector.recovery.encoded)).toThrow('INVALID_KEY_SLOT');
    expect(() => openRecoverySlot(passwordArtifact, passwordContext, vector.recovery.encoded)).toThrow('INVALID_KEY_SLOT');
  });

  it('rejects every single-byte mutation of the recovery artifact', () => {
    for (let index = 0; index < recoveryArtifact.length; index++) {
      const mutated = recoveryArtifact.slice();
      mutated[index]! ^= 0x01;
      expect(() => openRecoverySlot(mutated, recoveryContext, vector.recovery.encoded), `byte ${index}`).toThrow('INVALID_KEY_SLOT');
    }
    expect(() => openRecoverySlot(Uint8Array.from([...recoveryArtifact, 0]), recoveryContext, vector.recovery.encoded)).toThrow('INVALID_KEY_SLOT');
  });

  it('rejects shared invalid recovery encodings', () => {
    for (const encoded of vector.invalidRecoveryEncodings) {
      expect(() => decodeRecoveryKey(encoded), encoded).toThrow('INVALID_KEY_SLOT');
    }
    expect(() => decodeRecoveryKey(vector.recovery.encoded.replace('M', '1'))).toThrow('INVALID_KEY_SLOT');
    for (const [name, artifactHex] of Object.entries(vector.invalidArtifactsHex)) {
      expect(() => openRecoverySlot(bytes(artifactHex), recoveryContext, vector.recovery.encoded), name).toThrow('INVALID_KEY_SLOT');
    }
  });

  it('rejects non-V1 KDF parameters, unknown slot types and extra fields', () => {
    const map = decodeDeterministicCbor(bytes(vector.password.aadHex)) as Map<number, CborValue>;
    const kdf = map.get(7) as Map<number, CborValue>;
    for (const [key, value] of [[3, 32768], [4, 2], [5, 1], [2, 16], [1, 'argon2i']] as const) {
      const changed = new Map(kdf); changed.set(key, value);
      const aad = new Map(map); aad.set(7, changed);
      expect(() => decodeKeySlotAad(encodeDeterministicCbor(aad)), `kdf ${key}`).toThrow('INVALID_KEY_SLOT');
    }
    const extra = new Map(map); extra.set(8, null);
    expect(() => decodeKeySlotAad(encodeDeterministicCbor(extra))).toThrow('INVALID_KEY_SLOT');
    const recoveryWithKdf = new Map(map); recoveryWithKdf.set(3, 'recovery');
    expect(() => decodeKeySlotAad(encodeDeterministicCbor(recoveryWithKdf))).toThrow('INVALID_KEY_SLOT');
    const unknown = new Map(map); unknown.set(3, 'webauthn-prf');
    expect(() => decodeKeySlotAad(encodeDeterministicCbor(unknown))).toThrow('INVALID_KEY_SLOT');
    const record = decodeKeySlotRecord(recoveryArtifact);
    expect(() => encodeKeySlotRecord({ ...record, ciphertext: new Uint8Array(47) })).toThrow('INVALID_KEY_SLOT');
    const wrongKind = recoveryArtifact.slice(); wrongKind[6] = 1;
    expect(() => decodeKeySlotRecord(wrongKind)).toThrow('INVALID_KEY_SLOT');
  });
});
