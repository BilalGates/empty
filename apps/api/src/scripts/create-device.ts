import { z } from "zod";
import { generateDeviceToken, hashDeviceToken } from "../auth.js";
import { loadConfig } from "../config.js";
import { createPool } from "../db.js";

const input = z.object({ USER_ID: z.uuid(), VAULT_ID: z.uuid(), DEVICE_LABEL: z.string().min(1).max(120) }).parse(process.env);
const config = loadConfig();
const token = generateDeviceToken();
const hash = hashDeviceToken(token, config.DEVICE_TOKEN_PEPPER);
const pool = createPool(config.DATABASE_URL, config.DATABASE_SSL_MODE);
try {
  const result = await pool.query<{ id: string }>("INSERT INTO devices(user_id,vault_id,label,token_fingerprint,token_hash) VALUES($1,$2,$3,$4,$5) RETURNING id", [input.USER_ID, input.VAULT_ID, input.DEVICE_LABEL, hash.subarray(0,16), hash]);
  // Deliberate one-time credential output for an interactive administrator; never sent to application logs.
  process.stdout.write(JSON.stringify({ deviceId: result.rows[0]!.id, token }) + "\n");
} finally { await pool.end(); }
