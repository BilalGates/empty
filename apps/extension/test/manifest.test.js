import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const manifest = JSON.parse(await readFile(new URL("../manifest.json", import.meta.url), "utf8"));

test("uses Manifest V3 with the minimum explicit permissions", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual(manifest.permissions, ["activeTab", "alarms", "scripting", "storage"]);
  assert.equal("host_permissions" in manifest, false);
  assert.equal("content_scripts" in manifest, false);
  assert.equal(manifest.background.type, "module");
});

test("allows extension-owned scripts only", () => {
  assert.match(manifest.content_security_policy.extension_pages, /script-src 'self'/);
  assert.doesNotMatch(JSON.stringify(manifest), /https?:\/\//);
});
