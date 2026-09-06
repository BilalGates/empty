export const VAULT_FORMAT_VERSION = 1 as const;
export const ENVELOPE_VERSION = 1 as const;

export type CredentialKind = 'password' | 'passkey' | 'totp' | 'recovery-code' | 'secure-note';

export interface Group {
  id: string;
  name: string;
  createdAt: string;
  updatedAt: string;
}

interface ItemBase {
  id: string;
  kind: CredentialKind;
  title: string;
  groupId?: string;
  favorite: boolean;
  notes?: string;
  createdAt: string;
  updatedAt: string;
  version: number;
  deletedAt?: string;
}

export interface PasswordCredential extends ItemBase {
  kind: 'password';
  origins: string[];
  username: string;
  password: string;
  customFields?: Array<{ label: string; value: string; concealed: boolean }>;
}

export interface TotpCredential extends ItemBase {
  kind: 'totp';
  secret: string;
  issuer?: string;
  account?: string;
  algorithm: 'SHA1' | 'SHA256' | 'SHA512';
  digits: 6 | 8;
  period: number;
}

export interface RecoveryCodeItem extends ItemBase {
  kind: 'recovery-code';
  codes: Array<{ value: string; usedAt?: string }>;
}

export interface SecureNote extends ItemBase {
  kind: 'secure-note';
  content: string;
}

export interface PasskeyReference extends ItemBase {
  kind: 'passkey';
  rpId: string;
  credentialId: string;
  userHandle: string;
  transports?: string[];
}

export type VaultItem = PasswordCredential | TotpCredential | RecoveryCodeItem | SecureNote | PasskeyReference;

export interface VaultDocument {
  formatVersion: typeof VAULT_FORMAT_VERSION;
  vaultId: string;
  revision: number;
  createdAt: string;
  updatedAt: string;
  groups: Group[];
  items: VaultItem[];
}

export interface Argon2idParameters {
  algorithm: 'argon2id';
  version: 1;
  memoryKiB: number;
  iterations: number;
  parallelism: number;
  salt: string;
}

export interface KeyEnvelope {
  envelopeVersion: typeof ENVELOPE_VERSION;
  kind: 'master-password' | 'recovery-key' | 'device';
  algorithm: 'xchacha20-poly1305';
  nonce: string;
  ciphertext: string;
  kdf?: Argon2idParameters;
}

export interface EncryptedVault {
  formatVersion: typeof VAULT_FORMAT_VERSION;
  vaultId: string;
  revision: number;
  algorithm: 'xchacha20-poly1305';
  nonce: string;
  ciphertext: string;
  envelopes: KeyEnvelope[];
}

export interface SyncMutation {
  mutationId: string;
  deviceId: string;
  itemId: string;
  baseItemVersion: number;
  encryptedItem: string | null;
  occurredAt: string;
}

export interface SyncRecord {
  vaultId: string;
  itemId: string;
  itemVersion: number;
  serverRevision: number;
  encryptedItem: string | null;
  updatedAt: string;
}

export interface SyncConflict {
  mutation: SyncMutation;
  current: SyncRecord;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(sort(value));
}

function sort(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sort);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, entry]) => entry !== undefined)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, entry]) => [key, sort(entry)])
    );
  }
  return value;
}

export function assertVaultDocument(value: unknown): asserts value is VaultDocument {
  if (value === null || typeof value !== 'object') throw new Error('Vault document must be an object');
  const document = value as Partial<VaultDocument>;
  if (document.formatVersion !== VAULT_FORMAT_VERSION) throw new Error('Unsupported vault format');
  if (typeof document.vaultId !== 'string' || document.vaultId.length < 8) throw new Error('Invalid vault id');
  if (!Number.isSafeInteger(document.revision) || (document.revision ?? -1) < 0) throw new Error('Invalid revision');
  if (!Array.isArray(document.items) || !Array.isArray(document.groups)) throw new Error('Invalid vault collections');
}

