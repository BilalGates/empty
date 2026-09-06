import { randomUUID } from 'node:crypto';
import { deepStrictEqual } from 'node:assert';
import { once } from 'node:events';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { Pool } from 'pg';
import { z } from 'zod';

const defaultDist = fileURLToPath(new URL('../apps/api/dist/', import.meta.url));
const dist = process.env.SPACE_API_DIST_DIR ?? defaultDist;
const { createApp } = await import(pathToFileURL(resolve(dist, 'app.js')).href);
const { hashDeviceToken } = await import(pathToFileURL(resolve(dist, 'auth.js')).href);
const { createLogger } = await import(pathToFileURL(resolve(dist, 'logger.js')).href);

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error('DATABASE_URL is required');
const pepper = 'integration-only-device-token-pepper';
const token = `space_dt_${'a'.repeat(43)}`;
const ids = { user: randomUUID(), vault: randomUUID(), device: randomUUID(), item: randomUUID() };
const pool = new Pool({ connectionString: databaseUrl });
let server;

const cleanup = async () => {
  if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  await pool.query('DELETE FROM audit_events WHERE user_id=$1', [ids.user]);
  await pool.query('DELETE FROM mutation_receipts WHERE vault_id=$1', [ids.vault]);
  await pool.query('DELETE FROM sync_records WHERE vault_id=$1', [ids.vault]);
  await pool.query('DELETE FROM devices WHERE user_id=$1', [ids.user]);
  await pool.query('DELETE FROM vaults WHERE id=$1', [ids.vault]);
  await pool.query('DELETE FROM users WHERE id=$1', [ids.user]);
  await pool.end();
};

try {
  const hash = hashDeviceToken(token, pepper);
  await pool.query('INSERT INTO users(id) VALUES ($1)', [ids.user]);
  await pool.query('INSERT INTO vaults(id,user_id) VALUES ($1,$2)', [ids.vault, ids.user]);
  await pool.query('INSERT INTO devices(id,user_id,vault_id,label,token_fingerprint,token_hash) VALUES ($1,$2,$3,$4,$5,$6)', [ids.device, ids.user, ids.vault, 'integration', hash.subarray(0, 16), hash]);
  server = createApp({ pool, pepper, logger: createLogger('silent') }).listen(0, '127.0.0.1');
  await once(server, 'listening');
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  const request = (path, init = {}) => fetch(`${baseUrl}${path}`, { ...init, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', ...init.headers } });
  const assertStatus = (response, expected, label) => {
    if (response.status !== expected) throw new Error(`${label}: expected ${expected}, received ${response.status}`);
  };

  const session = await request('/v1/session');
  assertStatus(session, 200, 'session');
  if (session.headers.get('cache-control') !== 'no-store') throw new Error('authenticated responses must be no-store');

  const mutationId = randomUUID();
  const mutation = { mutationId, itemId: ids.item, baseItemVersion: 0, ciphertext: 'ciphertext', nonce: 'nonce', wrappedKey: 'wrapped', aad: 'aad' };
  const pushed = await request('/v1/sync/push', { method: 'POST', body: JSON.stringify({ mutations: [mutation] }) });
  assertStatus(pushed, 200, 'initial push');
  const firstBody = z.unknown().parse(await pushed.json());
  const replayed = await request('/v1/sync/push', { method: 'POST', body: JSON.stringify({ mutations: [mutation] }) });
  assertStatus(replayed, 200, 'idempotent replay');
  deepStrictEqual(z.unknown().parse(await replayed.json()), firstBody, 'replay response changed');

  const before = await pool.query('SELECT current_revision FROM vaults WHERE id=$1', [ids.vault]);
  const duplicate = await request('/v1/sync/push', { method: 'POST', body: JSON.stringify({ mutations: [
    { ...mutation, mutationId: randomUUID() }, { ...mutation, mutationId: randomUUID() }
  ] }) });
  assertStatus(duplicate, 400, 'duplicate item batch');
  const after = await pool.query('SELECT current_revision FROM vaults WHERE id=$1', [ids.vault]);
  if (after.rows[0].current_revision !== before.rows[0].current_revision) throw new Error('invalid batch mutated revision');

  const conflict = await request('/v1/sync/push', { method: 'POST', body: JSON.stringify({ mutations: [{ ...mutation, mutationId: randomUUID() }] }) });
  assertStatus(conflict, 409, 'conflict');
  const pull = await request('/v1/sync/pull?cursor=0');
  const pullBody = z.object({ changes: z.array(z.unknown()) }).parse(await pull.json());
  if (pullBody.changes.length !== 1) throw new Error('pull did not return the accepted mutation');

  const created = await request('/v1/devices', { method: 'POST', body: JSON.stringify({ label: 'revocable' }) });
  assertStatus(created, 201, 'create device');
  const createdBody = z.object({ deviceId: z.uuid(), token: z.string() }).parse(await created.json());
  assertStatus(await request(`/v1/devices/${createdBody.deviceId}`, { method: 'DELETE' }), 204, 'revoke device');
  assertStatus(await fetch(`${baseUrl}/v1/session`, { headers: { authorization: `Bearer ${createdBody.token}` } }), 401, 'revoked device');

  await pool.query('UPDATE users SET disabled_at=now() WHERE id=$1', [ids.user]);
  assertStatus(await request('/v1/session'), 401, 'disabled user');
  console.log('API PostgreSQL E2E passed: auth, no-store, idempotency, atomic validation, conflict, pull, revocation, disabled user');
} finally {
  await cleanup();
}
