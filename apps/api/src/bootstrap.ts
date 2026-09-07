import { Router, type NextFunction, type Request, type Response } from "express";
import type pg from "pg";
import { z } from "zod";

interface BootstrapRow {
  user_id: string;
  vault_id: string;
  device_id: string;
  current_revision: string;
}

export function bootstrapRouter(pool: pg.Pool): Router {
  const router = Router();
  const readBootstrap = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const identity = req.device!;
    try {
      const result = await pool.query<BootstrapRow>(
        `SELECT d.user_id, d.vault_id, d.id AS device_id, v.current_revision
           FROM devices d
           JOIN users u ON u.id = d.user_id
           JOIN vaults v ON v.id = d.vault_id AND v.user_id = d.user_id
          WHERE d.id = $1
            AND d.user_id = $2
            AND d.vault_id = $3
            AND d.revoked_at IS NULL
            AND u.disabled_at IS NULL`,
        [identity.deviceId, identity.accountId, identity.vaultId]
      );
      const row = result.rows[0];
      if (!row) { res.status(401).json({ error: "unauthorized" }); return; }
      res.json({
        protocolVersion: 1,
        accountId: row.user_id,
        vaultId: row.vault_id,
        vaultEpoch: 1,
        deviceId: row.device_id,
        serverRevision: Number(row.current_revision)
      });
    } catch (error) { next(error); }
  };
  router.get("/", readBootstrap);
  router.post("/bind", async (req, res, next) => {
    const parsed = z.object({ expectedVaultId: z.uuid() }).safeParse(req.body);
    if (!parsed.success) return void res.status(400).json({ error: "invalid_request", issues: parsed.error.issues });
    if (parsed.data.expectedVaultId !== req.device!.vaultId) return void res.status(409).json({ error: "vault_mismatch" });
    return readBootstrap(req, res, next);
  });
  return router;
}
