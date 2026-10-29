import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2';
import {
  decodeOperationHeader, decodeSignedOperationRecord, decodeVaultObjectAad, decodeVaultObjectRecord,
  encodeOperationHeader, encodeSignedOperationRecord, encodeVaultObjectAad,
  type OperationHeader, type VaultObjectAad
} from '@space/protocol';

/** RFC 8032 strict verification: canonical encodings only, no ZIP-215 relaxation. */
const VERIFY_OPTIONS = { zip215: false } as const;

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  let difference = left.length ^ right.length;
  for (let index = 0; index < Math.max(left.length, right.length); index++) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function key(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 32) throw new Error('INVALID_OPERATION');
  return value;
}

/**
 * Requires a canonical point of prime order (not identity, small or mixed order). Applied to both
 * the public key and R so the accepted set never exceeds libsodium's cofactorless verifier on iOS.
 */
function primeOrderPoint(value: Uint8Array): Uint8Array {
  const point = ed25519.Point.fromHex(key(value), false);
  if (point.is0() || !point.isTorsionFree()) throw new Error('INVALID_OPERATION');
  return value;
}

export function signOperation(secretKey: Uint8Array, header: OperationHeader): Uint8Array {
  try {
    const headerBytes = encodeOperationHeader(header);
    return encodeSignedOperationRecord({ headerBytes, signature: ed25519.sign(headerBytes, key(secretKey)) });
  } catch { throw new Error('INVALID_OPERATION'); }
}

export interface VerifiedOperation {
  header: OperationHeader;
  /** Exact signed bytes; persist these instead of re-encoding the header. */
  headerBytes: Uint8Array;
}

/**
 * Authenticates one operation against a trusted device key and the exact framed object artifact.
 * The caller still owns device revocation, monotonic sequence, DAG ancestry and checkpoint checks.
 */
export function verifyOperation(
  devicePublicKey: Uint8Array, expectedObject: VaultObjectAad, operationArtifact: Uint8Array, objectArtifact: Uint8Array
): VerifiedOperation {
  try {
    const record = decodeSignedOperationRecord(operationArtifact);
    primeOrderPoint(record.signature.subarray(0, 32));
    if (!ed25519.verify(record.signature, record.headerBytes, primeOrderPoint(devicePublicKey), VERIFY_OPTIONS)) {
      throw new Error('INVALID_OPERATION');
    }
    const header = decodeOperationHeader(record.headerBytes);
    const object = decodeVaultObjectRecord(objectArtifact);
    if (!equalBytes(object.aad, encodeVaultObjectAad(expectedObject))) throw new Error('INVALID_OPERATION');
    const aad = decodeVaultObjectAad(object.aad);
    if (!equalBytes(sha256(objectArtifact), header.ciphertextHash) ||
        !equalBytes(header.vaultId, aad.vaultId) || header.epoch !== aad.epoch ||
        !equalBytes(header.objectId, aad.objectId) || header.objectVersion !== aad.objectVersion ||
        !equalBytes(header.deviceId, aad.createdByDevice)) throw new Error('INVALID_OPERATION');
    return { header, headerBytes: record.headerBytes };
  } catch { throw new Error('INVALID_OPERATION'); }
}
