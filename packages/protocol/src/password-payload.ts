import { decodeDeterministicCbor, encodeDeterministicCbor, type CborValue } from './cbor.js';
import { MAX_OBJECT_PLAINTEXT_BYTES } from './vault-object-record.js';
import { isCanonicalPasswordOrigin } from './password-origin.js';

/** The first typed V1 payload. Other object types remain unavailable to V1 callers. */
export interface PasswordPayload {
  title: string;
  origins: string[];
  username: string;
  password: string;
  favorite: boolean;
  createdAtMs: number;
  updatedAtMs: number;
  groupId?: Uint8Array;
  notes?: string;
}

const encoder = new TextEncoder();
const MAX_TIME = Number.MAX_SAFE_INTEGER;

function text(value: unknown, maximum: number, allowEmpty = false): string {
  if (typeof value !== 'string' || (!allowEmpty && value.length === 0) || encoder.encode(value).length > maximum) {
    throw new Error('INVALID_PAYLOAD');
  }
  return value;
}

function timestamp(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > MAX_TIME) {
    throw new Error('INVALID_PAYLOAD');
  }
  return value;
}

function validate(value: PasswordPayload): PasswordPayload {
  const title = text(value.title, 256);
  const username = text(value.username, 1024, true);
  const password = text(value.password, 65_536);
  if (!Array.isArray(value.origins) || value.origins.length < 1 || value.origins.length > 16) {
    throw new Error('INVALID_PAYLOAD');
  }
  const origins = value.origins.map(origin => text(origin, 2048));
  if (origins.some(origin => !isCanonicalPasswordOrigin(origin)) ||
      new Set(origins).size !== origins.length || typeof value.favorite !== 'boolean') {
    throw new Error('INVALID_PAYLOAD');
  }
  const createdAtMs = timestamp(value.createdAtMs);
  const updatedAtMs = timestamp(value.updatedAtMs);
  if (updatedAtMs < createdAtMs) throw new Error('INVALID_PAYLOAD');
  const groupId = value.groupId;
  if (groupId !== undefined && (!(groupId instanceof Uint8Array) || groupId.length !== 16)) {
    throw new Error('INVALID_PAYLOAD');
  }
  const notes = value.notes === undefined ? undefined : text(value.notes, 65_536, true);
  return { title, origins, username, password, favorite: value.favorite, createdAtMs, updatedAtMs,
    ...(groupId === undefined ? {} : { groupId: groupId.slice() }), ...(notes === undefined ? {} : { notes }) };
}

export function encodePasswordPayload(input: PasswordPayload): Uint8Array {
  try {
    const value = validate(input);
    const map = new Map<number, CborValue>([
      [1, value.title], [2, value.origins], [3, value.username], [4, value.password],
      [7, value.favorite], [8, value.createdAtMs], [9, value.updatedAtMs]
    ]);
    if (value.groupId) map.set(5, value.groupId);
    if (value.notes !== undefined) map.set(6, value.notes);
    return encodeDeterministicCbor(map, MAX_OBJECT_PLAINTEXT_BYTES);
  } catch { throw new Error('INVALID_PAYLOAD'); }
}

export function decodePasswordPayload(bytes: Uint8Array): PasswordPayload {
  try {
    if (bytes.length > MAX_OBJECT_PLAINTEXT_BYTES) throw new Error('INVALID_PAYLOAD');
    const value = decodeDeterministicCbor(bytes);
    if (!(value instanceof Map)) throw new Error('INVALID_PAYLOAD');
    const required = [1, 2, 3, 4, 7, 8, 9];
    if (value.size < 7 || value.size > 9 || required.some(key => !value.has(key)) ||
        [...value.keys()].some(key => key < 1 || key > 9)) throw new Error('INVALID_PAYLOAD');
    const origins = value.get(2);
    if (!Array.isArray(origins) || origins.some(origin => typeof origin !== 'string')) throw new Error('INVALID_PAYLOAD');
    const groupId = value.get(5);
    const notes = value.get(6);
    return validate({
      title: value.get(1) as string, origins: origins as string[], username: value.get(3) as string,
      password: value.get(4) as string, favorite: value.get(7) as boolean,
      createdAtMs: value.get(8) as number, updatedAtMs: value.get(9) as number,
      ...(value.has(5) ? { groupId: groupId as Uint8Array } : {}),
      ...(value.has(6) ? { notes: notes as string } : {})
    });
  } catch { throw new Error('INVALID_PAYLOAD'); }
}
