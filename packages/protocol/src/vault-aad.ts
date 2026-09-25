import { decodeDeterministicCbor, encodeDeterministicCbor, type CborValue } from './cbor.js';

export interface VaultObjectAad {
  vaultId: Uint8Array;
  objectId: Uint8Array;
  objectType: 'password' | 'passkey' | 'totp' | 'secure-item' | 'tombstone';
  objectVersion: number;
  epoch: number;
  keyId: Uint8Array;
  createdByDevice: Uint8Array;
}

function id(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 16) throw new Error('INVALID_AAD');
  return value;
}

function positive(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error('INVALID_AAD');
  return value;
}

export function encodeVaultObjectAad(aad: VaultObjectAad): Uint8Array {
  if (!['password', 'passkey', 'totp', 'secure-item', 'tombstone'].includes(aad.objectType)) throw new Error('INVALID_AAD');
  const encoded = encodeDeterministicCbor(new Map<number, CborValue>([
    [1, 'space.vault/1'],
    [2, 'vault-object'],
    [3, id(aad.vaultId)],
    [4, id(aad.objectId)],
    [5, aad.objectType],
    [6, positive(aad.objectVersion)],
    [7, positive(aad.epoch)],
    [8, id(aad.keyId)],
    [9, id(aad.createdByDevice)]
  ]));
  if (encoded.length > 16 * 1024) throw new Error('INVALID_AAD');
  return encoded;
}

export function decodeVaultObjectAad(bytes: Uint8Array): VaultObjectAad {
  try {
    if (bytes.length > 16 * 1024) throw new Error('INVALID_AAD');
    const value = decodeDeterministicCbor(bytes);
    if (!(value instanceof Map) || value.size !== 9 || value.get(1) !== 'space.vault/1' || value.get(2) !== 'vault-object') {
      throw new Error('INVALID_AAD');
    }
    const objectType = value.get(5);
    if (typeof objectType !== 'string' || !['password', 'passkey', 'totp', 'secure-item', 'tombstone'].includes(objectType)) {
      throw new Error('INVALID_AAD');
    }
    return {
      vaultId: id(value.get(3) as Uint8Array).slice(),
      objectId: id(value.get(4) as Uint8Array).slice(),
      objectType: objectType as VaultObjectAad['objectType'],
      objectVersion: positive(value.get(6) as number),
      epoch: positive(value.get(7) as number),
      keyId: id(value.get(8) as Uint8Array).slice(),
      createdByDevice: id(value.get(9) as Uint8Array).slice()
    };
  } catch {
    throw new Error('INVALID_AAD');
  }
}
