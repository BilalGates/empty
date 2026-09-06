import { readFileSync } from 'node:fs';
import { argon2id } from '@noble/hashes/argon2';
import { describe, expect, it } from 'vitest';

interface ArgonVector {
  suite: string;
  purpose: string;
  inputUtf8Hex: string;
  saltHex: string;
  parameters: { memoryKiB: number; iterations: number; parallelism: number; outputBytes: number };
  outputHex: string;
}

const vector = JSON.parse(
  readFileSync(new URL('../test-vectors/argon2id-v1.json', import.meta.url), 'utf8')
) as ArgonVector;

const bytes = (hex: string): Uint8Array => Uint8Array.from(Buffer.from(hex, 'hex'));

describe('space.vault/1 cross-platform vectors', { timeout: 20_000 }, () => {
  it('matches the normative Argon2id password-slot vector', () => {
    expect(vector.suite).toBe('space.vault/1');
    expect(vector.purpose).toBe('password-slot-argon2id');
    const output = argon2id(bytes(vector.inputUtf8Hex), bytes(vector.saltHex), {
      m: vector.parameters.memoryKiB,
      t: vector.parameters.iterations,
      p: vector.parameters.parallelism,
      dkLen: vector.parameters.outputBytes
    });
    expect(Buffer.from(output).toString('hex')).toBe(vector.outputHex);
  });
});
