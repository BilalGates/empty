import test from "node:test";
import assert from "node:assert/strict";
import { isMessage } from "../src/protocol.js";

test("accepts the bounded protocol and rejects unknown or oversized payloads", () => {
  assert.equal(isMessage({ type: "SPACE_GET_STATE", tabId: 4, origin: "https://example.com" }), true);
  assert.equal(isMessage({ type: "SPACE_UNLOCK", password: "secure phrase" }), true);
  assert.equal(isMessage({ type: "SPACE_UNLOCK", password: "short" }), false);
  assert.equal(isMessage({ type: "SPACE_ADD_CREDENTIAL", tabId: 4, origin: "https://example.com", title: "Example", username: "person", password: "value" }), true);
  assert.equal(isMessage({ type: "SPACE_UPDATE_CREDENTIAL", tabId: 4, origin: "https://example.com", credentialId: "id", title: "Example", website: "https://example.com", username: "person", password: "value" }), true);
  assert.equal(isMessage({ type: "SPACE_DELETE_CREDENTIAL", tabId: 4, origin: "https://example.com", credentialId: "id" }), true);
  assert.equal(isMessage({ type: "SPACE_EXPORT_BACKUP", tabId: 4, origin: "https://example.com", password: "secure phrase" }), true);
  assert.equal(isMessage({ type: "SPACE_RESTORE_BACKUP", tabId: 4, origin: "https://example.com", password: "secure phrase", content: "{}", replaceConfirmed: true }), true);
  assert.equal(isMessage({ type: "SPACE_RESTORE_BACKUP", tabId: 4, origin: "https://example.com", password: "secure phrase", content: "x".repeat(20_000_001), replaceConfirmed: true }), false);
  assert.equal(isMessage({ type: "SPACE_FILL", tabId: 4, origin: "https://example.com", credentialId: "x" }), true);
  assert.equal(isMessage({ type: "SPACE_GET_SECRET", tabId: 7, origin: "https://example.com", credentialId: "item" }), true);
  assert.equal(isMessage({ type: "SPACE_PREVIEW_IMPORT", tabId: 4, origin: "https://example.com", csv: "url,username,password" }), true);
  assert.equal(isMessage({ type: "SPACE_PREVIEW_IMPORT", tabId: 4, origin: "https://example.com", csv: "x".repeat(5_000_001) }), false);
  assert.equal(isMessage({ type: "SPACE_COMMIT_IMPORT", tabId: 4, origin: "https://example.com", token: "preview" }), true);
  assert.equal(isMessage({ type: "SPACE_FILL", tabId: 4, origin: "https://example.com", credentialId: "" }), false);
  assert.equal(isMessage({ type: "SPACE_CONTENT_FILL", requestId: "x", origin: "https://example.com", credential: { username: "u", password: "p" } }), true);
  assert.equal(isMessage({ type: "DO_ANYTHING", payload: {} }), false);
});
