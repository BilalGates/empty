import { describe, expect, it } from 'vitest';
import type { VaultDocument } from '@space/protocol';
import { changeMasterPassword, createEncryptedVault, generatePassword, importChromeCsv, matchesOrigin, openEncryptedVaultWithSessionKey, unlockVaultSessionWithPassword, unlockWithPassword, unlockWithRecoveryKey, updateEncryptedVault, updateEncryptedVaultWithSessionKey } from './index.js';

const testCost = { memoryKiB: 64 * 1024, iterations: 3, parallelism: 1 };
const yieldWorker = (): Promise<void> => new Promise(resolve => setImmediate(resolve));
const document: VaultDocument = {
  formatVersion: 1, vaultId: 'vault-test-0001', revision: 0,
  createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', groups: [],
  items: [{ id: 'item-0001', kind: 'password', title: 'Example', origins: ['https://example.com'], username: 'a@example.com', password: 'secret', favorite: false, createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', version: 1 }]
};

describe('vault cryptography', { timeout: 60_000 }, () => {
  it('round trips with password and recovery key', async () => {
    const created = createEncryptedVault(document, 'correct horse battery staple', testCost);
    await yieldWorker();
    expect(unlockWithPassword(created.vault, 'correct horse battery staple')).toEqual(document);
    await yieldWorker();
    expect(unlockWithRecoveryKey(created.vault, created.recoveryKey)).toEqual(document);
    expect(() => unlockWithPassword(created.vault, 'wrong password value')).toThrow('Unable to unlock');
    await yieldWorker();
  });

  it('rewraps without changing ciphertext', async () => {
    const created = createEncryptedVault(document, 'correct horse battery staple', testCost);
    await yieldWorker();
    const changed = changeMasterPassword(created.vault, 'correct horse battery staple', 'another long master password', testCost);
    await yieldWorker();
    expect(changed.ciphertext).toBe(created.vault.ciphertext);
    expect(unlockWithPassword(changed, 'another long master password')).toEqual(document);
    await yieldWorker();
  });

  it('rejects contextual tampering', async () => {
    const created = createEncryptedVault(document, 'correct horse battery staple', testCost);
    await yieldWorker();
    expect(() => unlockWithPassword({ ...created.vault, revision: 1 }, 'correct horse battery staple')).toThrow();
    await yieldWorker();
    expect(() => unlockWithPassword({ ...created.vault, nonce: 'AA' }, 'correct horse battery staple')).toThrow('Unable to unlock');
    await yieldWorker();
    const passwordEnvelope = created.vault.envelopes.find(candidate => candidate.kind === 'master-password')!;
    expect(() => unlockWithPassword({ ...created.vault, envelopes: [{ ...passwordEnvelope, algorithm: 'invalid' as never }] }, 'correct horse battery staple')).toThrow('Unable to unlock');
  });

  it('normalizes canonically equivalent master passwords', async () => {
    const composed = 'mot-de-passe-tr\u00e8s-solide';
    const decomposed = 'mot-de-passe-tre\u0300s-solide';
    const created = createEncryptedVault(document, composed, testCost);
    await yieldWorker();
    expect(unlockWithPassword(created.vault, decomposed)).toEqual(document);
    await yieldWorker();
  });

  it('updates payload with a new nonce while preserving recovery envelopes', async () => {
    const created = createEncryptedVault(document, 'correct horse battery staple', testCost);
    await yieldWorker();
    const updatedDocument = { ...document, revision: 1, updatedAt: '2026-01-02T00:00:00.000Z' };
    const updated = updateEncryptedVault(created.vault, 'correct horse battery staple', updatedDocument);
    await yieldWorker();
    expect(updated.nonce).not.toBe(created.vault.nonce);
    expect(updated.envelopes).toEqual(created.vault.envelopes);
    expect(unlockWithPassword(updated, 'correct horse battery staple')).toEqual(updatedDocument);
    await yieldWorker();
    expect(unlockWithRecoveryKey(updated, created.recoveryKey)).toEqual(updatedDocument);
    expect(() => updateEncryptedVault(created.vault, 'wrong password value', updatedDocument)).toThrow('Unable to update');
    await yieldWorker();
    expect(() => updateEncryptedVault(created.vault, 'correct horse battery staple', document)).toThrow('revision');
  });

  it('reuses only a validated vault session key for unlocked mutations', async () => {
    const created = createEncryptedVault(document, 'correct horse battery staple', testCost);
    await yieldWorker();
    const unlocked = unlockVaultSessionWithPassword(created.vault, 'correct horse battery staple');
    expect(unlocked.document).toEqual(document);
    expect(unlocked.vaultKey).not.toContain('correct horse battery staple');
    expect(openEncryptedVaultWithSessionKey(created.vault, unlocked.vaultKey)).toEqual(document);
    const updatedDocument = { ...document, revision: 1, updatedAt: '2026-01-03T00:00:00.000Z' };
    const updated = updateEncryptedVaultWithSessionKey(created.vault, unlocked.vaultKey, updatedDocument);
    expect(unlockWithPassword(updated, 'correct horse battery staple')).toEqual(updatedDocument);
    await yieldWorker();
    expect(() => openEncryptedVaultWithSessionKey(created.vault, 'AA')).toThrow('Unable to unlock');
    expect(() => openEncryptedVaultWithSessionKey(created.vault, '!')).toThrow('Unable to unlock');
    expect(() => updateEncryptedVaultWithSessionKey(created.vault, 'AA', updatedDocument)).toThrow();
  });

  it('rejects KDF downgrade, oversized cost, invalid salt, and oversized passwords before derivation', async () => {
    const created = createEncryptedVault(document, 'correct horse battery staple', testCost);
    await yieldWorker();
    const passwordEnvelope = created.vault.envelopes.find(candidate => candidate.kind === 'master-password')!;
    const replaceKdf = (kdf: NonNullable<typeof passwordEnvelope.kdf>) => ({
      ...created.vault,
      envelopes: [{ ...passwordEnvelope, kdf }, ...created.vault.envelopes.filter(candidate => candidate.kind !== 'master-password')]
    });
    expect(() => unlockWithPassword(replaceKdf({ ...passwordEnvelope.kdf!, memoryKiB: 63 * 1024 }), 'correct horse battery staple')).toThrow('policy');
    expect(() => unlockWithPassword(replaceKdf({ ...passwordEnvelope.kdf!, memoryKiB: 1024 * 1024 + 1 }), 'correct horse battery staple')).toThrow('policy');
    expect(() => unlockWithPassword(replaceKdf({ ...passwordEnvelope.kdf!, salt: 'AA' }), 'correct horse battery staple')).toThrow('salt');
    expect(() => createEncryptedVault(document, 'x'.repeat(1025), testCost)).toThrow('byte limit');
  });
});

describe('utilities', () => {
  it('matches exact origins only', () => {
    expect(matchesOrigin('https://example.com/login', ['https://example.com'])).toBe(true);
    expect(matchesOrigin('https://example.com.evil.test', ['https://example.com'])).toBe(false);
    expect(matchesOrigin('https://sub.example.com', ['https://example.com'])).toBe(false);
  });

  it('generates passwords with every selected class', () => {
    const value = generatePassword({ length: 32, uppercase: true, lowercase: true, numbers: true, symbols: true });
    expect(value).toHaveLength(32); expect(value).toMatch(/[A-Z]/u); expect(value).toMatch(/[a-z]/u); expect(value).toMatch(/[0-9]/u); expect(value).toMatch(/[^A-Za-z0-9]/u);
  });

  it('parses Chrome CSV locally and deduplicates exact entries', () => {
    const csv = 'name,url,username,password,note\nExample,https://example.com,user,pw,"hello, world"\nExample,https://example.com,user,pw,"hello, world"';
    const result = importChromeCsv(csv);
    expect(result.accepted).toHaveLength(1); expect(result.duplicates).toHaveLength(1); expect(result.accepted[0]?.note).toBe('hello, world');
  });
});
