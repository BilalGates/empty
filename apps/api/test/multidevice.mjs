import { deepStrictEqual } from "node:assert";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { Pool } from "pg";
import { z } from "zod";
import { createApp } from "../dist/app.js";
import { hashDeviceToken } from "../dist/auth.js";
import { createLogger } from "../dist/logger.js";

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error("DATABASE_URL is required");
const pepper = process.env.DEVICE_TOKEN_PEPPER ?? "integration-only-device-token-pepper";
const tokenA = `space_dt_${"a".repeat(43)}`;
const ids = { user: randomUUID(), vault: randomUUID(), deviceA: randomUUID(), item: randomUUID() };
const pool = new Pool({ connectionString: databaseUrl, ssl: false });
let server;

const cleanup = async () => {
  if (server) await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  await pool.query("DELETE FROM audit_events WHERE user_id=$1", [ids.user]);
  await pool.query("DELETE FROM mutation_receipts WHERE vault_id=$1", [ids.vault]);
  await pool.query("DELETE FROM sync_records WHERE vault_id=$1", [ids.vault]);
  await pool.query("DELETE FROM devices WHERE user_id=$1", [ids.user]);
  await pool.query("DELETE FROM vaults WHERE id=$1", [ids.vault]);
  await pool.query("DELETE FROM users WHERE id=$1", [ids.user]);
  await pool.end();
};

try {
  const hashA = hashDeviceToken(tokenA, pepper);
  await pool.query("INSERT INTO users(id) VALUES($1)", [ids.user]);
  await pool.query("INSERT INTO vaults(id,user_id) VALUES($1,$2)", [ids.vault, ids.user]);
  await pool.query("INSERT INTO devices(id,user_id,vault_id,label,token_fingerprint,token_hash) VALUES($1,$2,$3,'device-a',$4,$5)", [ids.deviceA, ids.user, ids.vault, hashA.subarray(0, 16), hashA]);

  server = createApp({ pool, pepper, logger: createLogger("silent") }).listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("API did not bind a TCP port");
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const request = (token, path, init = {}) => fetch(`${baseUrl}${path}`, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...init.headers } });
  const expectStatus = (response, expected, label) => { if (response.status !== expected) throw new Error(`${label}: expected ${expected}, got ${response.status}`); };

  const bootstrapA = await request(tokenA, "/v1/bootstrap");
  expectStatus(bootstrapA, 200, "bootstrap A");
  deepStrictEqual(await bootstrapA.json(), { protocolVersion: 1, accountId: ids.user, vaultId: ids.vault, vaultEpoch: 1, deviceId: ids.deviceA, serverRevision: 0 });

  const deviceB = { deviceId: randomUUID(), token: `space_dt_${"b".repeat(43)}` };
  const hashB = hashDeviceToken(deviceB.token, pepper);
  await pool.query("INSERT INTO devices(id,user_id,vault_id,label,token_fingerprint,token_hash) VALUES($1,$2,$3,'device-b',$4,$5)", [deviceB.deviceId, ids.user, ids.vault, hashB.subarray(0, 16), hashB]);
  const bootstrapB = await request(deviceB.token, "/v1/bootstrap/bind", { method: "POST", body: JSON.stringify({ expectedVaultId: ids.vault }) });
  expectStatus(bootstrapB, 200, "bootstrap B");
  const bootstrapBodyB = z.object({ vaultId: z.uuid(), deviceId: z.uuid() }).parse(await bootstrapB.json());
  deepStrictEqual(bootstrapBodyB, { vaultId: ids.vault, deviceId: deviceB.deviceId });
  expectStatus(await request(deviceB.token, "/v1/bootstrap/bind", { method: "POST", body: JSON.stringify({ expectedVaultId: randomUUID() }) }), 409, "reject mismatched vault binding");

  const mutationA = { mutationId: randomUUID(), itemId: ids.item, baseItemVersion: 0, ciphertext: "opaque-a", nonce: "nonce-a", wrappedKey: "wrapped-a", aad: "aad-a" };
  expectStatus(await request(tokenA, `/v1/vaults/${ids.vault}/sync/push`, { method: "POST", body: JSON.stringify({ mutations: [mutationA] }) }), 200, "push A");
  const pullB = await request(deviceB.token, `/v1/vaults/${ids.vault}/sync/pull?cursor=0`);
  expectStatus(pullB, 200, "pull B");
  const pageB = z.object({ changes: z.array(z.object({ ciphertext: z.string().nullable(), itemVersion: z.number() })) }).passthrough().parse(await pullB.json());
  if (pageB.changes.length !== 1 || pageB.changes[0].ciphertext !== "opaque-a" || pageB.changes[0].itemVersion !== 1) throw new Error("B did not observe A exactly once");

  const mutationB = { ...mutationA, mutationId: randomUUID(), baseItemVersion: 1, ciphertext: "opaque-b" };
  expectStatus(await request(deviceB.token, `/v1/vaults/${ids.vault}/sync/push`, { method: "POST", body: JSON.stringify({ mutations: [mutationB] }) }), 200, "push B");
  const pullA = await request(tokenA, `/v1/vaults/${ids.vault}/sync/pull?cursor=1`);
  expectStatus(pullA, 200, "pull A");
  const pageA = z.object({ changes: z.array(z.object({ ciphertext: z.string().nullable() })) }).parse(await pullA.json());
  if (pageA.changes.length !== 1 || pageA.changes[0].ciphertext !== "opaque-b") throw new Error("A did not observe B exactly once");

  const conflictB = { ...mutationB, mutationId: randomUUID(), ciphertext: "stale-b" };
  expectStatus(await request(deviceB.token, `/v1/vaults/${ids.vault}/sync/push`, { method: "POST", body: JSON.stringify({ mutations: [conflictB] }) }), 409, "stale B conflict");
  expectStatus(await request(tokenA, `/v1/vaults/${randomUUID()}/sync/pull?cursor=0`), 404, "cross-vault scope");
  expectStatus(await request(tokenA, `/v1/devices/${deviceB.deviceId}`, { method: "DELETE" }), 204, "revoke B");
  expectStatus(await request(deviceB.token, "/v1/bootstrap"), 401, "revoked B bootstrap");
  expectStatus(await request(deviceB.token, `/v1/vaults/${ids.vault}/sync/pull?cursor=0`), 401, "revoked B sync");
  console.log("API multi-device integration passed: bootstrap binding, A→B, B→A, conflict, vault scope, revocation");
} finally { await cleanup(); }
