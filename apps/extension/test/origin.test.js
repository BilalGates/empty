import test from "node:test";
import assert from "node:assert/strict";
import { isAutofillAllowed, normalizeOrigin, originsMatch } from "../src/origin.js";

test("normalizes scheme, host, default port and discards paths", () => {
  assert.equal(normalizeOrigin("HTTPS://Example.COM:443/login?q=1"), "https://example.com");
});

test("matches only exact normalized origins", () => {
  assert.equal(originsMatch("https://example.com/a", "https://example.com/b"), true);
  assert.equal(originsMatch("https://example.com", "https://login.example.com"), false);
  assert.equal(originsMatch("https://example.com", "https://example.com.evil.test"), false);
  assert.equal(originsMatch("http://example.com", "https://example.com"), false);
  assert.equal(originsMatch("https://example.com:444", "https://example.com"), false);
});

test("allows secure pages and localhost development only", () => {
  assert.equal(isAutofillAllowed("https://example.com"), true);
  assert.equal(isAutofillAllowed("http://localhost:4173"), true);
  assert.equal(isAutofillAllowed("http://example.com"), false);
  assert.equal(isAutofillAllowed("file:///tmp/login.html"), false);
});
