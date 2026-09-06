import { access, readFile } from "node:fs/promises";
const failures = [];
async function exists(path) { try { await access(new URL(path, import.meta.url)); return true; } catch { return false; } }
const dockerfile = await readFile(new URL("../apps/api/Dockerfile", import.meta.url), "utf8");
if (/\bRUN\s+npm install\b/.test(dockerfile)) failures.push("API Dockerfile uses npm install; release images must use npm ci with a committed lockfile");
if (!(await exists("../package-lock.json")) && !(await exists("../apps/api/package-lock.json"))) failures.push("no npm lockfile is available to the API container build");
const bootstrap = await readFile(new URL("../apps/api/migrations/000_bootstrap.sql", import.meta.url), "utf8").catch(() => "");
if (/schema_migrations[\s\S]*001_initial/i.test(bootstrap)) failures.push("000_bootstrap marks 001_initial as applied; replace the temporary migration workaround with a single canonical baseline");
if (failures.length) { for (const failure of failures) console.error(`BLOCKED: ${failure}`); process.exitCode = 1; }
else console.log("release reproducibility policy passed");
