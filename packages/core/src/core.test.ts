import { describe, expect, it } from 'vitest';
import type { VaultDocument } from '@space/protocol';
import { changeMasterPassword, createEncryptedVault, generatePassword, importChromeCsv, matchesOrigin, unlockWithPassword, unlockWithRecoveryKey } from './index.js';

const testCost = { memoryKiB: 19 * 1024, iterations: 2, parallelism: 1 };
const document: VaultDocument = {
  formatVersion: 1, vaultId: 'vault-test-0001', revision: 0,
  createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', groups: [],
  items: [{ id: 'item-0001', kind: 'password', title: 'Example', origins: ['https://example.com'], username: 'a@example.com', password: 'secret', favorite: false, createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', version: 1 }]
};

describe('vault cryptography', () => {
  it('round trips with password and recovery key', () => {
    const created = createEncryptedVault(document, 'correct horse battery staple', testCost);
    expect(unlockWithPassword(created.vault, 'correct horse battery staple')).toEqual(document);
    expect(unlockWithRecoveryKey(created.vault, created.recoveryKey)).toEqual(document);
    expect(() => unlockWithPassword(created.vault, 'wrong password value')).toThrow('Unable to unlock');
  });

  it('rewraps without changing ciphertext', () => {
    const created = createEncryptedVault(document, 'correct horse battery staple', testCost);
    const changed = changeMasterPassword(created.vault, 'correct horse battery staple', 'another long master password', testCost);
    expect(changed.ciphertext).toBe(created.vault.ciphertext);
    expect(unlockWithPassword(changed, 'another long master password')).toEqual(document);
  });

  it('rejects contextual tampering', () => {
    const created = createEncryptedVault(document, 'correct horse battery staple', testCost);
    expect(() => unlockWithPassword({ ...created.vault, revision: 1 }, 'correct horse battery staple')).toThrow();
  });

  it('normalizes canonically equivalent master passwords', () => {
    const composed = 'mot-de-passe-tr\u00e8s-solide';
    const decomposed = 'mot-de-passe-tre\u0300s-solide';
    const created = createEncryptedVault(document, composed, testCost);
    expect(unlockWithPassword(created.vault, decomposed)).toEqual(document);
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
