import test from "node:test";
import assert from "node:assert/strict";
import { generatePassword } from "../src/generator.js";

test("generates passwords with every required character class", () => {
  for (let index = 0; index < 32; index += 1) {
    const value = generatePassword(24);
    assert.equal(value.length, 24);
    assert.match(value, /[A-Z]/);
    assert.match(value, /[a-z]/);
    assert.match(value, /[0-9]/);
    assert.match(value, /[!@#$%^&*_+=-]/);
  }
});

test("rejects out-of-policy lengths", () => {
  assert.throws(() => generatePassword(11), RangeError);
  assert.throws(() => generatePassword(129), RangeError);
});
