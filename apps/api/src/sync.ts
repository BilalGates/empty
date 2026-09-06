import { createHash } from "node:crypto";
import { Router } from "express";
import type pg from "pg";
import { z } from "zod";

const opaque = z.string().min(1);
const mutationSchema = z.object({
  mutationId: z.uuid(),
  itemId: z.uuid(),
  baseItemVersion: z.number().int().min(0),
  ciphertext: z.string().max(1_048_576).nullable(),
  nonce: opaque.max(256).nullable(),
  wrappedKey: opaque.max(8192).nullable(),
  aad: z.string().max(8192).nullable().default(null)
}).superRefine((value, ctx) => {
  const tombstone = value.ciphertext === null;
  if (tombstone !== (value.nonce === null && value.wrappedKey === null && value.aad === null)) ctx.addIssue({ code: "custom", message: "tombstones must have a fully null envelope" });
});
const pushSchema = z.object({ mutations: z.array(mutationSchema).min(1).max(100) }).superRefine((value, ctx) => {
  const mutationIds = new Set<string>();
  const itemIds = new Set<string>();
  value.mutations.forEach((mutation, index) => {
    if (mutationIds.has(mutation.mutationId)) ctx.addIssue({ code: "custom", path: ["mutations", index, "mutationId"], message: "duplicate mutationId" });
    if (itemIds.has(mutation.itemId)) ctx.addIssue({ code: "custom", path: ["mutations", index, "itemId"], message: "duplicate itemId" });
    mutationIds.add(mutation.mutationId);
    itemIds.add(mutation.itemId);
  });
});
const pullSchema = z.object({ cursor: z.coerce.number().int().min(0).default(0), limit: z.coerce.number().int().min(1).max(500).default(200) });

type Client = pg.PoolClient;
async function tx<T>(pool: pg.Pool, fn: (client: Client) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
    const value = await fn(client);
    await client.query("COMMIT");
    return value;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally { client.release(); }
}

const payloadHash = (value: unknown): Buffer => createHash("sha256").update(JSON.stringify(value)).digest();

export function syncRouter(pool: pg.Pool): Router {
  const router = Router();

  router.post("/push", async (req, res, next) => {
    const parsed = pushSchema.safeParse(req.body);
    if (!parsed.success) return void res.status(400).json({ error: "invalid_request", issues: parsed.error.issues });
    const identity = req.device!;
    try {
      const result = await tx(pool, async (client) => {
        const active = await client.query("SELECT 1 FROM devices WHERE id = $1 AND vault_id = $2 AND revoked_at IS NULL", [identity.deviceId, identity.vaultId]);
        if (!active.rowCount) return { status: 401, body: { error: "unauthorized" } };
        await client.query("SELECT current_revision FROM vaults WHERE id = $1 FOR UPDATE", [identity.vaultId]);

        const hashes = parsed.data.mutations.map(payloadHash);
        const receipts = await client.query<{ mutation_id: string; payload_hash: Buffer; http_status: number; response: unknown }>(
          "SELECT mutation_id, payload_hash, http_status, response FROM mutation_receipts WHERE vault_id = $1 AND mutation_id = ANY($2::uuid[])",
          [identity.vaultId, parsed.data.mutations.map((m) => m.mutationId)]
        );
        if (receipts.rowCount) {
          if (receipts.rowCount !== parsed.data.mutations.length) return { status: 409, body: { error: "partial_replay", message: "do not mix processed and new mutation ids" } };
          const byId = new Map(receipts.rows.map((row) => [row.mutation_id, row]));
          const matches = parsed.data.mutations.every((m, i) => byId.get(m.mutationId)?.payload_hash.equals(hashes[i]!));
          if (!matches) return { status: 409, body: { error: "mutation_id_reused" } };
          const first = receipts.rows[0]!;
          return { status: first.http_status, body: first.response };
        }

        const itemIds = parsed.data.mutations.map((m) => m.itemId);
        const heads = await client.query<{ item_id: string; item_version: string }>(
          `SELECT DISTINCT ON (item_id) item_id, item_version
             FROM sync_records WHERE vault_id = $1 AND item_id = ANY($2::uuid[])
            ORDER BY item_id, item_version DESC`,
          [identity.vaultId, itemIds]
        );
        const versions = new Map(heads.rows.map((row) => [row.item_id, Number(row.item_version)]));
        const conflicts = parsed.data.mutations.flatMap((m) => {
          const current = versions.get(m.itemId) ?? 0;
          return current === m.baseItemVersion ? [] : [{ mutationId: m.mutationId, itemId: m.itemId, expectedVersion: m.baseItemVersion, currentVersion: current }];
        });
        if (conflicts.length) {
          const body = { error: "version_conflict", conflicts };
          for (let i = 0; i < parsed.data.mutations.length; i++) await client.query(
            "INSERT INTO mutation_receipts(vault_id, mutation_id, device_id, payload_hash, http_status, response) VALUES ($1,$2,$3,$4,409,$5)",
            [identity.vaultId, parsed.data.mutations[i]!.mutationId, identity.deviceId, hashes[i], body]
          );
          await client.query("INSERT INTO audit_events(user_id,vault_id,device_id,event_type) VALUES ($1,$2,$3,'sync_conflict')", [identity.accountId, identity.vaultId, identity.deviceId]);
          return { status: 409, body };
        }

        const accepted: Array<{ mutationId: string; itemId: string; itemVersion: number; revision: number }> = [];
        for (const mutation of parsed.data.mutations) {
          const revisionResult = await client.query<{ current_revision: string }>("UPDATE vaults SET current_revision = current_revision + 1 WHERE id = $1 RETURNING current_revision", [identity.vaultId]);
          const revision = Number(revisionResult.rows[0]!.current_revision);
          const itemVersion = mutation.baseItemVersion + 1;
          await client.query(
            `INSERT INTO sync_records(vault_id,item_id,item_version,revision,mutation_id,author_device_id,ciphertext,nonce,wrapped_key,aad)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
            [identity.vaultId, mutation.itemId, itemVersion, revision, mutation.mutationId, identity.deviceId, mutation.ciphertext, mutation.nonce, mutation.wrappedKey, mutation.aad]
          );
          accepted.push({ mutationId: mutation.mutationId, itemId: mutation.itemId, itemVersion, revision });
        }
        const body = { accepted, cursor: accepted.at(-1)!.revision };
        for (let i = 0; i < parsed.data.mutations.length; i++) await client.query(
          "INSERT INTO mutation_receipts(vault_id,mutation_id,device_id,payload_hash,http_status,response) VALUES ($1,$2,$3,$4,200,$5)",
          [identity.vaultId, parsed.data.mutations[i]!.mutationId, identity.deviceId, hashes[i], body]
        );
        await client.query("INSERT INTO audit_events(user_id,vault_id,device_id,event_type) VALUES ($1,$2,$3,'sync_push')", [identity.accountId, identity.vaultId, identity.deviceId]);
        return { status: 200, body };
      });
      res.status(result.status).json(result.body);
    } catch (error) { next(error); }
  });

  router.get("/pull", async (req, res, next) => {
    const parsed = pullSchema.safeParse(req.query);
    if (!parsed.success) return void res.status(400).json({ error: "invalid_request", issues: parsed.error.issues });
    const identity = req.device!;
    try {
      const active = await pool.query("SELECT 1 FROM devices WHERE id=$1 AND vault_id=$2 AND revoked_at IS NULL", [identity.deviceId, identity.vaultId]);
      if (!active.rowCount) return void res.status(401).json({ error: "unauthorized" });
      const result = await pool.query<{
        item_id: string; item_version: string; revision: string; mutation_id: string; ciphertext: string | null; nonce: string | null; wrapped_key: string | null; aad: string | null;
      }>(`SELECT item_id,item_version,revision,mutation_id,ciphertext,nonce,wrapped_key,aad
           FROM sync_records WHERE vault_id=$1 AND revision>$2 ORDER BY revision ASC LIMIT $3`, [identity.vaultId, parsed.data.cursor, parsed.data.limit + 1]);
      const hasMore = result.rows.length > parsed.data.limit;
      const rows = result.rows.slice(0, parsed.data.limit);
      const changes = rows.map((r) => ({ itemId: r.item_id, itemVersion: Number(r.item_version), revision: Number(r.revision), mutationId: r.mutation_id, ciphertext: r.ciphertext, nonce: r.nonce, wrappedKey: r.wrapped_key, aad: r.aad }));
      res.json({ changes, cursor: changes.at(-1)?.revision ?? parsed.data.cursor, hasMore });
    } catch (error) { next(error); }
  });
  return router;
}
