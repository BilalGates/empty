import { readFileSync } from 'node:fs';
import { argon2id } from '@noble/hashes/argon2';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { describe, expect, it } from 'vitest';

interface ArgonVector {
  suite: string;
  purpose: string;
  inputUtf8Hex: string;
  saltHex: string;
  parameters: { memoryKiB: number; iterations: number; parallelism: number; outputBytes: number };
  outputHex: string;
}

const argonVector = JSON.parse(
  readFileSync(new URL('../../../test-vectors/argon2id-v1.json', import.meta.url), 'utf8')
) as ArgonVector;
const hkdfVector = JSON.parse(
  readFileSync(new URL('../../../test-vectors/hkdf-vwk-v1.json', import.meta.url), 'utf8')
) as { ikmHex: string; saltHex: string; infoHex: string; outputBytes: number; outputHex: string };
const xchachaVector = JSON.parse(
  readFileSync(new URL('../../../test-vectors/xchacha20-poly1305-v1.json', import.meta.url), 'utf8')
) as { keyHex: string; nonceHex: string; aadHex: string; plaintextHex: string; ciphertextHex: string };

const bytes = (hex: string): Uint8Array => Uint8Array.from(Buffer.from(hex, 'hex'));

describe('space.vault/1 cross-platform vectors', { timeout: 20_000 }, () => {
  it('matches the normative Argon2id password-slot vector', () => {
    expect(argonVector.suite).toBe('space.vault/1');
    expect(argonVector.purpose).toBe('password-slot-argon2id');
    const output = argon2id(bytes(argonVector.inputUtf8Hex), bytes(argonVector.saltHex), {
      m: argonVector.parameters.memoryKiB,
      t: argonVector.parameters.iterations,
      p: argonVector.parameters.parallelism,
      dkLen: argonVector.parameters.outputBytes
    });
    expect(Buffer.from(output).toString('hex')).toBe(argonVector.outputHex);
  });

  it('matches the shared HKDF-SHA-256 vault-wrap-key vector', () => {
    const output = hkdf(sha256, bytes(hkdfVector.ikmHex), bytes(hkdfVector.saltHex), bytes(hkdfVector.infoHex), hkdfVector.outputBytes);
    expect(Buffer.from(output).toString('hex')).toBe(hkdfVector.outputHex);
  });

  it('matches the shared XChaCha20-Poly1305-IETF vector and rejects mutation', () => {
    const cipher = xchacha20poly1305(bytes(xchachaVector.keyHex), bytes(xchachaVector.nonceHex), bytes(xchachaVector.aadHex));
    const sealed = cipher.encrypt(bytes(xchachaVector.plaintextHex));
    expect(Buffer.from(sealed).toString('hex')).toBe(xchachaVector.ciphertextHex);
    expect(Buffer.from(cipher.decrypt(sealed)).toString('hex')).toBe(xchachaVector.plaintextHex);
    const mutated = sealed.slice();
    mutated[0]! ^= 1;
    expect(() => cipher.decrypt(mutated)).toThrow();
  });
});
