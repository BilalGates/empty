import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { decodeVaultFrame, encodeVaultFrame, VAULT_ARTIFACT_KIND, type VaultArtifactKind } from './frame.js';

const vectors = JSON.parse(readFileSync(new URL('../../../test-vectors/cbor-frame-v1.json', import.meta.url), 'utf8')) as {
  suite: string;
  positive: Array<{ name: string; kind: VaultArtifactKind; fields: Array<[number, string]>; hex: string }>;
  negative: string[];
};
const bytes = (hex: string): Uint8Array => Uint8Array.from(Buffer.from(hex, 'hex'));
const hex = (value: Uint8Array): string => Buffer.from(value).toString('hex');

describe('space.vault/1 deterministic frame vectors', () => {
  it('uses the stable suite identifier', () => {
    expect(vectors.suite).toBe('space.vault/1');
  });

  it.each(vectors.positive)('matches $name byte for byte', ({ kind, fields, hex: expected }) => {
    const value = new Map(fields);
    expect(hex(encodeVaultFrame(kind, value))).toBe(expected);
    expect(decodeVaultFrame(bytes(expected), kind)).toEqual(value);
  });

  it.each(vectors.negative)('rejects invalid frame %s', (invalid) => {
    expect(() => decodeVaultFrame(bytes(invalid), VAULT_ARTIFACT_KIND.keySlot)).toThrow();
  });

  it('rejects a valid frame under the wrong expected kind and ignores no trailing bytes', () => {
    const frame = encodeVaultFrame(VAULT_ARTIFACT_KIND.object, new Map());
    expect(() => decodeVaultFrame(frame, VAULT_ARTIFACT_KIND.operation)).toThrow();
    const padded = new Uint8Array(frame.length + 1);
    padded.set(frame);
    expect(() => decodeVaultFrame(padded, VAULT_ARTIFACT_KIND.object)).toThrow();
  });

  it('decodes a byte-offset view without assuming a zero-offset buffer', () => {
    const frame = encodeVaultFrame(VAULT_ARTIFACT_KIND.checkpoint, new Map([[1, 42]]));
    const larger = new Uint8Array(frame.length + 2);
    larger.set(frame, 1);
    expect(decodeVaultFrame(larger.subarray(1, -1), VAULT_ARTIFACT_KIND.checkpoint)).toEqual(new Map([[1, 42]]));
  });
});
