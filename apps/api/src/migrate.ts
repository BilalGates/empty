import { readdir, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfig } from "./config.js";
import { createPool } from "./db.js";

const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = resolve(here, "../migrations");
const config = loadConfig();
const pool = createPool(config.DATABASE_URL, config.DATABASE_SSL_MODE);

try {
  await pool.query("SELECT pg_advisory_lock(hashtext('space_schema_migrations'))");
  await pool.query("CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())");
  const files = (await readdir(migrationsDir)).filter((name) => name.endsWith(".sql")).sort();
  for (const file of files) {
    const version = file.replace(/\.sql$/, "");
    const exists = await pool.query("SELECT 1 FROM schema_migrations WHERE version = $1", [version]);
    if (exists.rowCount) continue;
    // Each migration owns its transaction and records its version.
    await pool.query(await readFile(resolve(migrationsDir, file), "utf8"));
  }
} finally {
  await pool.query("SELECT pg_advisory_unlock(hashtext('space_schema_migrations'))").catch(() => undefined);
  await pool.end();
}
