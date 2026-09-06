import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import type pg from "pg";

export interface DeviceIdentity { accountId: string; deviceId: string; vaultId: string }
declare module "express-serve-static-core" {
  interface Request { device?: DeviceIdentity }
}

export const hashDeviceToken = (token: string, pepper: string): Buffer => createHmac("sha256", pepper).update(token, "utf8").digest();
export const generateDeviceToken = (): string => `space_dt_${randomBytes(32).toString("base64url")}`;
export const DEVICE_LOOKUP_SQL = `SELECT d.user_id, d.id AS device_id, d.vault_id, d.token_hash
   FROM devices d
   JOIN users u ON u.id = d.user_id
  WHERE d.token_fingerprint = $1
    AND d.revoked_at IS NULL
    AND u.disabled_at IS NULL`;

function readBearer(req: Request): string | undefined {
  const value = req.header("authorization");
  if (!value?.startsWith("Bearer ")) return undefined;
  const token = value.slice(7);
  return token.length >= 32 && token.length <= 256 ? token : undefined;
}

export function deviceAuth(pool: pg.Pool, pepper: string) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const token = readBearer(req);
      if (!token) return void res.status(401).json({ error: "unauthorized" });
      const candidate = hashDeviceToken(token, pepper);
      const result = await pool.query<{ user_id: string; device_id: string; vault_id: string; token_hash: Buffer }>(
        DEVICE_LOOKUP_SQL,
        [candidate.subarray(0, 16)]
      );
      const row = result.rows[0];
      if (!row || row.token_hash.length !== candidate.length || !timingSafeEqual(row.token_hash, candidate)) return void res.status(401).json({ error: "unauthorized" });
      await pool.query("UPDATE devices SET last_seen_at = now() WHERE id = $1 AND revoked_at IS NULL", [row.device_id]);
      req.device = { accountId: row.user_id, deviceId: row.device_id, vaultId: row.vault_id };
      next();
    } catch (error) { next(error); }
  };
}
