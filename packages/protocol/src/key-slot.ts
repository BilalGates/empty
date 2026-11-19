import { decodeDeterministicCbor, encodeDeterministicCbor, type CborValue } from './cbor.js';

export type KeySlotType = 'password' | 'recovery';

/** V1 fixes these exact Argon2id parameters; another cost profile needs a new reviewed slot version. */
export const KEY_SLOT_ARGON2ID = Object.freeze({ version: 19, memoryKiB: 65536, iterations: 3, parallelism: 4 });

export interface KeySlotAad {
  slotType: KeySlotType;
  vaultId: Uint8Array;
  slotId: Uint8Array;
  epoch: number;
  /** Present exactly when `slotType === 'password'`. */
  salt?: Uint8Array;
}

export interface KeySlotRecord {
  aad: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

const MAGIC = Uint8Array.of(0x53, 0x50, 0x43, 0x45);
const VERSION = 1;
const KEY_SLOT_KIND = 4;
const MAX_AAD_BYTES = 16 * 1024;
const MAX_ARTIFACT_BYTES = 32 * 1024;

function bytes(value: unknown, length: number): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) throw new Error('INVALID_KEY_SLOT');
  return value.slice();
}

function checked(input: KeySlotAad): KeySlotAad {
  if (input.slotType !== 'password' && input.slotType !== 'recovery') throw new Error('INVALID_KEY_SLOT');
  if (typeof input.epoch !== 'number' || !Number.isSafeInteger(input.epoch) || input.epoch < 1) throw new Error('INVALID_KEY_SLOT');
  const base = { slotType: input.slotType, vaultId: bytes(input.vaultId, 16), slotId: bytes(input.slotId, 16), epoch: input.epoch };
  if (input.slotType === 'password') return { ...base, salt: bytes(input.salt, 16) };
  if (input.salt !== undefined) throw new Error('INVALID_KEY_SLOT');
  return base;
}

export function encodeKeySlotAad(input: KeySlotAad): Uint8Array {
  try {
    const value = checked(input);
    const entries: Array<[number, CborValue]> = [
      [1, 'empty.vault/1'], [2, 'key-slot'], [3, value.slotType], [4, value.vaultId], [5, value.slotId], [6, value.epoch]
    ];
    if (value.salt) {
      entries.push([7, new Map<number, CborValue>([
        [1, 'argon2id'], [2, KEY_SLOT_ARGON2ID.version], [3, KEY_SLOT_ARGON2ID.memoryKiB],
        [4, KEY_SLOT_ARGON2ID.iterations], [5, KEY_SLOT_ARGON2ID.parallelism], [6, value.salt]
      ])]);
    }
    return encodeDeterministicCbor(new Map(entries), MAX_AAD_BYTES);
  } catch { throw new Error('INVALID_KEY_SLOT'); }
}

export function decodeKeySlotAad(input: Uint8Array): KeySlotAad {
  try {
    if (!(input instanceof Uint8Array) || input.length > MAX_AAD_BYTES) throw new Error('INVALID_KEY_SLOT');
    const map = decodeDeterministicCbor(input);
    if (!(map instanceof Map) || map.get(1) !== 'empty.vault/1' || map.get(2) !== 'key-slot') throw new Error('INVALID_KEY_SLOT');
    const slotType = map.get(3);
    const size = slotType === 'password' ? 7 : slotType === 'recovery' ? 6 : 0;
    if (map.size !== size || Array.from({ length: size }, (_, index) => index + 1).some(key => !map.has(key))) {
      throw new Error('INVALID_KEY_SLOT');
    }
    let salt: Uint8Array | undefined;
    if (slotType === 'password') {
      const kdf = map.get(7);
      if (!(kdf instanceof Map) || kdf.size !== 6 || kdf.get(1) !== 'argon2id' ||
          kdf.get(2) !== KEY_SLOT_ARGON2ID.version || kdf.get(3) !== KEY_SLOT_ARGON2ID.memoryKiB ||
          kdf.get(4) !== KEY_SLOT_ARGON2ID.iterations || kdf.get(5) !== KEY_SLOT_ARGON2ID.parallelism) {
        throw new Error('INVALID_KEY_SLOT');
      }
      salt = kdf.get(6) as Uint8Array;
    }
    const value = checked({
      slotType: slotType as KeySlotType, vaultId: map.get(4) as Uint8Array, slotId: map.get(5) as Uint8Array,
      epoch: map.get(6) as number, ...(salt === undefined ? {} : { salt })
    });
    if (encodeKeySlotAad(value).some((byte, index) => byte !== input[index])) throw new Error('INVALID_KEY_SLOT');
    return value;
  } catch { throw new Error('INVALID_KEY_SLOT'); }
}

export function encodeKeySlotRecord(input: KeySlotRecord): Uint8Array {
  try {
    decodeKeySlotAad(input.aad);
    const body = encodeDeterministicCbor(new Map<number, CborValue>([
      [1, input.aad], [2, bytes(input.nonce, 24)], [3, bytes(input.ciphertext, 48)]
    ]));
    const framed = new Uint8Array(body.length + 11);
    framed.set(MAGIC);
    framed[5] = VERSION;
    framed[6] = KEY_SLOT_KIND;
    new DataView(framed.buffer).setUint32(7, body.length, false);
    framed.set(body, 11);
    return framed;
  } catch { throw new Error('INVALID_KEY_SLOT'); }
}

/** Parses framing and AAD shape only; nothing is authenticated until the AEAD tag verifies. */
export function decodeKeySlotRecord(input: Uint8Array): KeySlotRecord {
  try {
    if (!(input instanceof Uint8Array) || input.length < 12 || input.length > MAX_ARTIFACT_BYTES ||
        MAGIC.some((byte, index) => input[index] !== byte) || input[4] !== 0 || input[5] !== VERSION ||
        input[6] !== KEY_SLOT_KIND) throw new Error('INVALID_KEY_SLOT');
    const length = new DataView(input.buffer, input.byteOffset, input.byteLength).getUint32(7, false);
    if (length !== input.length - 11) throw new Error('INVALID_KEY_SLOT');
    const map = decodeDeterministicCbor(input.subarray(11));
    if (!(map instanceof Map) || map.size !== 3 || [1, 2, 3].some(key => !map.has(key))) throw new Error('INVALID_KEY_SLOT');
    const aad = map.get(1);
    if (!(aad instanceof Uint8Array)) throw new Error('INVALID_KEY_SLOT');
    decodeKeySlotAad(aad);
    return { aad: aad.slice(), nonce: bytes(map.get(2), 24), ciphertext: bytes(map.get(3), 48) };
  } catch { throw new Error('INVALID_KEY_SLOT'); }
}
