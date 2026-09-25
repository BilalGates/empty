import { decodeCanonicalCbor, encodeCanonicalCbor, type CanonicalCbor } from './cbor.js';

/** Stable space.vault/1 wire kind numbers. Unknown kinds fail closed. */
export const VAULT_ARTIFACT_KIND = {
  object: 1,
  keySlot: 2,
  operation: 3,
  checkpoint: 4,
  deviceTransfer: 5
} as const;

export type VaultArtifactKind = typeof VAULT_ARTIFACT_KIND[keyof typeof VAULT_ARTIFACT_KIND];

const HEADER_BYTES = 11;
const MAX_ARTIFACT_BYTES = 16 * 1024 * 1024;
const knownKinds = new Set<number>(Object.values(VAULT_ARTIFACT_KIND));

function validKind(kind: number): kind is VaultArtifactKind {
  return knownKinds.has(kind);
}

export function encodeVaultFrame(kind: VaultArtifactKind, value: Map<number, CanonicalCbor>): Uint8Array {
  if (!validKind(kind) || !(value instanceof Map)) throw new Error('Invalid vault artifact');
  const payload = encodeCanonicalCbor(value);
  if (payload.length + HEADER_BYTES > MAX_ARTIFACT_BYTES) throw new Error('Vault artifact size limit exceeded');
  const result = new Uint8Array(HEADER_BYTES + payload.length);
  result.set([0x53, 0x50, 0x43, 0x45, 0, 1, kind], 0);
  new DataView(result.buffer).setUint32(7, payload.length, false);
  result.set(payload, HEADER_BYTES);
  return result;
}

export function decodeVaultFrame(input: Uint8Array, expectedKind: VaultArtifactKind): Map<number, CanonicalCbor> {
  if (!(input instanceof Uint8Array) || input.length < HEADER_BYTES || input.length > MAX_ARTIFACT_BYTES) {
    throw new Error('Invalid vault artifact length');
  }
  if (!validKind(expectedKind) || input[0] !== 0x53 || input[1] !== 0x50 || input[2] !== 0x43 || input[3] !== 0x45 ||
      input[4] !== 0 || input[5] !== 1 || input[6] !== expectedKind) {
    throw new Error('Unsupported vault artifact');
  }
  const length = new DataView(input.buffer, input.byteOffset, input.byteLength).getUint32(7, false);
  if (length !== input.length - HEADER_BYTES) throw new Error('Invalid vault artifact length');
  const value = decodeCanonicalCbor(input.subarray(HEADER_BYTES));
  if (!(value instanceof Map)) throw new Error('Vault artifact must be a map');
  return value;
}
