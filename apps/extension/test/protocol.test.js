import test from "node:test";
import assert from "node:assert/strict";
import { isMessage } from "../src/protocol.js";

test("accepts the bounded protocol and rejects unknown or oversized payloads", () => {
  assert.equal(isMessage({ type: "SPACE_GET_STATE", tabId: 4, origin: "https://example.com" }), true);
  assert.equal(isMessage({ type: "SPACE_FILL", tabId: 4, origin: "https://example.com", credentialId: "x" }), true);
  assert.equal(isMessage({ type: "SPACE_FILL", tabId: 4, origin: "https://example.com", credentialId: "" }), false);
  assert.equal(isMessage({ type: "SPACE_CONTENT_FILL", requestId: "x", origin: "https://example.com", credential: { username: "u", password: "p" } }), true);
  assert.equal(isMessage({ type: "DO_ANYTHING", payload: {} }), false);
});
