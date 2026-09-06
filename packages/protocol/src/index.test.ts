import { describe, expect, it } from 'vitest';
import { canonicalJson } from './index.js';

describe('canonicalJson', () => {
  it('sorts nested object keys and removes undefined values', () => {
    expect(canonicalJson({ z: 1, a: { d: undefined, c: 2 } })).toBe('{"a":{"c":2},"z":1}');
  });
});

