import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { argon2id } from '@noble/hashes/argon2';
import type { Argon2idParameters, EncryptedVault, KeyEnvelope, VaultDocument } from '@space/protocol';
import { assertVaultDocument, canonicalJson, ENVELOPE_VERSION, VAULT_FORMAT_VERSION } from '@space/protocol';
import { fromBase64Url, fromUtf8, toBase64Url, utf8, wipe } from './encoding.js';

export const DEFAULT_KDF = Object.freeze({ memoryKiB: 64 * 1024, iterations: 3, parallelism: 1 });

export interface KdfCost { memoryKiB: number; iterations: number; parallelism: number }

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

function passwordAad(vaultId: string, kdf: Argon2idParameters): Uint8Array {
  return utf8(canonicalJson({ context: 'space/vault-key-envelope', vaultId, envelopeVersion: 1, kind: 'master-password', kdf }));
}

function recoveryAad(vaultId: string): Uint8Array {
  return utf8(canonicalJson({ context: 'space/vault-key-envelope', vaultId, envelopeVersion: 1, kind: 'recovery-key' }));
}

function payloadAad(vaultId: string, revision: number): Uint8Array {
  return utf8(canonicalJson({ context: 'space/vault-payload', vaultId, formatVersion: 1, revision }));
}

function derivePasswordKey(password: string, kdf: Argon2idParameters): Uint8Array {
  const normalizedPassword = password.normalize('NFC');
  if (normalizedPassword.length < 12) throw new Error('Master password must contain at least 12 characters');
  if (kdf.memoryKiB < 19 * 1024 || kdf.iterations < 2 || kdf.parallelism < 1) throw new Error('KDF parameters below policy');
  return argon2id(utf8(normalizedPassword), fromBase64Url(kdf.salt), {
    m: kdf.memoryKiB,
    t: kdf.iterations,
    p: kdf.parallelism,
    dkLen: 32
  });
}

function encrypt(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): { nonce: string; ciphertext: string } {
  const nonce = randomBytes(24);
  const ciphertext = xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
  return { nonce: toBase64Url(nonce), ciphertext: toBase64Url(ciphertext) };
}

function decrypt(key: Uint8Array, nonce: string, ciphertext: string, aad: Uint8Array): Uint8Array {
  return xchacha20poly1305(key, fromBase64Url(nonce), aad).decrypt(fromBase64Url(ciphertext));
}

function makePasswordEnvelope(vaultKey: Uint8Array, vaultId: string, password: string, cost: KdfCost): KeyEnvelope {
  const kdf: Argon2idParameters = {
    algorithm: 'argon2id', version: 1, ...cost, salt: toBase64Url(randomBytes(16))
  };
  const key = derivePasswordKey(password, kdf);
  try {
    return { envelopeVersion: ENVELOPE_VERSION, kind: 'master-password', algorithm: 'xchacha20-poly1305', ...encrypt(key, vaultKey, passwordAad(vaultId, kdf)), kdf };
  } finally { wipe(key); }
}

function makeRecoveryEnvelope(vaultKey: Uint8Array, vaultId: string, recoveryKey: Uint8Array): KeyEnvelope {
  return { envelopeVersion: ENVELOPE_VERSION, kind: 'recovery-key', algorithm: 'xchacha20-poly1305', ...encrypt(recoveryKey, vaultKey, recoveryAad(vaultId)) };
}

export function createEncryptedVault(document: VaultDocument, password: string, cost: KdfCost = DEFAULT_KDF): { vault: EncryptedVault; recoveryKey: string } {
  assertVaultDocument(document);
  const vaultKey = randomBytes(32);
  const recoveryKey = randomBytes(32);
  try {
    const encrypted = encrypt(vaultKey, utf8(canonicalJson(document)), payloadAad(document.vaultId, document.revision));
    return {
      vault: {
        formatVersion: VAULT_FORMAT_VERSION,
        vaultId: document.vaultId,
        revision: document.revision,
        algorithm: 'xchacha20-poly1305',
        ...encrypted,
        envelopes: [makePasswordEnvelope(vaultKey, document.vaultId, password, cost), makeRecoveryEnvelope(vaultKey, document.vaultId, recoveryKey)]
      },
      recoveryKey: toBase64Url(recoveryKey)
    };
  } finally { wipe(vaultKey, recoveryKey); }
}

function openWithKey(vault: EncryptedVault, vaultKey: Uint8Array): VaultDocument {
  const plaintext = decrypt(vaultKey, vault.nonce, vault.ciphertext, payloadAad(vault.vaultId, vault.revision));
  try {
    const document: unknown = JSON.parse(fromUtf8(plaintext));
    assertVaultDocument(document);
    if (document.vaultId !== vault.vaultId || document.revision !== vault.revision) throw new Error('Vault context mismatch');
    return document;
  } finally { wipe(plaintext); }
}

export function unlockWithPassword(vault: EncryptedVault, password: string): VaultDocument {
  const envelope = vault.envelopes.find(candidate => candidate.kind === 'master-password');
  if (!envelope?.kdf) throw new Error('Master-password envelope unavailable');
  const key = derivePasswordKey(password, envelope.kdf);
  let vaultKey: Uint8Array | undefined;
  try {
    vaultKey = decrypt(key, envelope.nonce, envelope.ciphertext, passwordAad(vault.vaultId, envelope.kdf));
    return openWithKey(vault, vaultKey);
  } catch { throw new Error('Unable to unlock vault'); }
  finally { wipe(key); if (vaultKey) wipe(vaultKey); }
}

export function unlockWithRecoveryKey(vault: EncryptedVault, encodedRecoveryKey: string): VaultDocument {
  const envelope = vault.envelopes.find(candidate => candidate.kind === 'recovery-key');
  if (!envelope) throw new Error('Recovery envelope unavailable');
  const recoveryKey = fromBase64Url(encodedRecoveryKey);
  if (recoveryKey.length !== 32) throw new Error('Invalid recovery key');
  let vaultKey: Uint8Array | undefined;
  try {
    vaultKey = decrypt(recoveryKey, envelope.nonce, envelope.ciphertext, recoveryAad(vault.vaultId));
    return openWithKey(vault, vaultKey);
  } catch { throw new Error('Unable to recover vault'); }
  finally { wipe(recoveryKey); if (vaultKey) wipe(vaultKey); }
}

export function changeMasterPassword(vault: EncryptedVault, oldPassword: string, newPassword: string, cost: KdfCost = DEFAULT_KDF): EncryptedVault {
  const envelope = vault.envelopes.find(candidate => candidate.kind === 'master-password');
  if (!envelope?.kdf) throw new Error('Master-password envelope unavailable');
  const oldKey = derivePasswordKey(oldPassword, envelope.kdf);
  let vaultKey: Uint8Array | undefined;
  try {
    vaultKey = decrypt(oldKey, envelope.nonce, envelope.ciphertext, passwordAad(vault.vaultId, envelope.kdf));
    const replacement = makePasswordEnvelope(vaultKey, vault.vaultId, newPassword, cost);
    return { ...vault, envelopes: [replacement, ...vault.envelopes.filter(candidate => candidate.kind !== 'master-password')] };
  } catch { throw new Error('Unable to change master password'); }
  finally { wipe(oldKey); if (vaultKey) wipe(vaultKey); }
}
