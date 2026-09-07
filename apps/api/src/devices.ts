import { Router } from "express";
import type pg from "pg";
import { z } from "zod";
interface DeviceRow { id: string; label: string; created_at: Date; last_seen_at: Date | null; revoked_at: Date | null }

export function devicesRouter(pool: pg.Pool): Router {
  const router = Router();

  router.get("/", async (req, res, next) => {
    const identity = req.device!;
    try {
      const result = await pool.query<DeviceRow>(
        `SELECT d.id,d.label,d.created_at,d.last_seen_at,d.revoked_at
           FROM devices d JOIN users u ON u.id=d.user_id
          WHERE d.user_id=$1 AND d.vault_id=$2 AND u.disabled_at IS NULL
            AND EXISTS (SELECT 1 FROM devices actor WHERE actor.id=$3 AND actor.user_id=$1 AND actor.vault_id=$2 AND actor.revoked_at IS NULL)
          ORDER BY d.created_at`,
        [identity.accountId, identity.vaultId, identity.deviceId]
      );
      if (!result.rowCount) return void res.status(401).json({ error: "unauthorized" });
      res.json({ devices: result.rows.map((row) => ({ id: row.id, label: row.label, createdAt: row.created_at, lastSeenAt: row.last_seen_at, revokedAt: row.revoked_at })) });
    } catch (error) { next(error); }
  });

  router.delete("/:deviceId", async (req, res, next) => {
    const target = z.uuid().safeParse(req.params.deviceId);
    if (!target.success) return void res.status(400).json({ error: "invalid_device_id" });
    const identity = req.device!;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const actor = await client.query(
        "SELECT 1 FROM devices d JOIN users u ON u.id=d.user_id WHERE d.id=$1 AND d.user_id=$2 AND d.vault_id=$3 AND d.revoked_at IS NULL AND u.disabled_at IS NULL FOR UPDATE OF d",
        [identity.deviceId, identity.accountId, identity.vaultId]
      );
      if (!actor.rowCount) { await client.query("ROLLBACK"); return void res.status(401).json({ error: "unauthorized" }); }
      const result = await client.query("UPDATE devices SET revoked_at=COALESCE(revoked_at,now()) WHERE id=$1 AND user_id=$2 AND vault_id=$3 RETURNING id", [target.data, identity.accountId, identity.vaultId]);
      if (!result.rowCount) { await client.query("ROLLBACK"); return void res.status(404).json({ error: "device_not_found" }); }
      await client.query("INSERT INTO audit_events(user_id,vault_id,device_id,event_type) VALUES ($1,$2,$3,'device_revoked')", [identity.accountId, identity.vaultId, identity.deviceId]);
      await client.query("COMMIT");
      res.status(204).end();
    } catch (error) { await client.query("ROLLBACK").catch(() => undefined); next(error); }
    finally { client.release(); }
  });
  return router;
}
