import test from "node:test";
import assert from "node:assert/strict";
import { classifyFields } from "../src/detection.js";

const field = (properties) => ({ type: "text", autocomplete: "", hint: "", disabled: false, readOnly: false, visible: true, ...properties });

test("recognizes a traditional login", () => {
  assert.deepEqual(classifyFields([field({ autocomplete: "username" }), field({ type: "password", autocomplete: "current-password" })]),
    { kind: "login", usernameCount: 1, passwordCount: 1 });
});

test("requires confirmation for signup and password change", () => {
  assert.equal(classifyFields([field({ type: "email" }), field({ type: "password", autocomplete: "new-password" })]).kind, "signup");
  assert.equal(classifyFields([field({ type: "password", autocomplete: "current-password" }), field({ type: "password", autocomplete: "new-password" })]).kind, "password-change");
});

test("ignores disabled and hidden fields", () => {
  assert.deepEqual(classifyFields([field({ type: "password", disabled: true }), field({ type: "password", visible: false })]),
    { kind: "none", usernameCount: 0, passwordCount: 0 });
});
