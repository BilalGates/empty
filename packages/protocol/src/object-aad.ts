import { decodeCanonicalCbor, encodeCanonicalCbor, type CanonicalCbor } from './cbor.js';

export type VaultObjectType = 'password' | 'passkey' | 'totp' | 'secure-item' | 'tombstone';

/** Authenticated context for one immutable space.vault/1 object version. */
export interface VaultObjectAad {
  vaultId: Uint8Array;
  objectId: Uint8Array;
  objectType: VaultObjectType;
  objectVersion: number;
  epoch: number;
  keyId: Uint8Array;
  createdByDevice: Uint8Array;
}

const MAX_AAD_BYTES = 16 * 1024;
const OBJECT_TYPES = new Set<string>(['password', 'passkey', 'totp', 'secure-item', 'tombstone']);
const KEYS = [1, 2, 3, 4, 5, 6, 7, 8, 9] as const;

function id(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 16) throw new Error('Invalid object AAD identifier');
  return value;
}

function positiveInteger(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    throw new Error('Invalid object AAD version');
  }
  return value;
}

function objectType(value: unknown): VaultObjectType {
  if (typeof value !== 'string' || !OBJECT_TYPES.has(value)) throw new Error('Invalid object AAD type');
  return value as VaultObjectType;
}

function checked(value: VaultObjectAad): VaultObjectAad {
  if (value === null || typeof value !== 'object') throw new Error('Invalid object AAD');
  return {
    vaultId: id(value.vaultId),
    objectId: id(value.objectId),
    objectType: objectType(value.objectType),
    objectVersion: positiveInteger(value.objectVersion),
    epoch: positiveInteger(value.epoch),
    keyId: id(value.keyId),
    createdByDevice: id(value.createdByDevice)
  };
}

export function encodeObjectAad(value: VaultObjectAad): Uint8Array {
  const fields = checked(value);
  const map = new Map<number, CanonicalCbor>([
    [1, 'space.vault/1'], [2, 'vault-object'], [3, fields.vaultId], [4, fields.objectId],
    [5, fields.objectType], [6, fields.objectVersion], [7, fields.epoch],
    [8, fields.keyId], [9, fields.createdByDevice]
  ]);
  const bytes = encodeCanonicalCbor(map);
  if (bytes.length > MAX_AAD_BYTES) throw new Error('Object AAD size limit exceeded');
  return bytes;
}

export function decodeObjectAad(bytes: Uint8Array): VaultObjectAad {
  if (!(bytes instanceof Uint8Array) || bytes.length > MAX_AAD_BYTES) throw new Error('Object AAD size limit exceeded');
  const value = decodeCanonicalCbor(bytes);
  if (!(value instanceof Map) || value.size !== KEYS.length || KEYS.some(key => !value.has(key)) ||
      value.get(1) !== 'space.vault/1' || value.get(2) !== 'vault-object') {
    throw new Error('Invalid object AAD schema');
  }
  const fields = checked({
    vaultId: value.get(3) as Uint8Array,
    objectId: value.get(4) as Uint8Array,
    objectType: value.get(5) as VaultObjectType,
    objectVersion: value.get(6) as number,
    epoch: value.get(7) as number,
    keyId: value.get(8) as Uint8Array,
    createdByDevice: value.get(9) as Uint8Array
  });
  return {
    ...fields,
    vaultId: fields.vaultId.slice(),
    objectId: fields.objectId.slice(),
    keyId: fields.keyId.slice(),
    createdByDevice: fields.createdByDevice.slice()
  };
}
