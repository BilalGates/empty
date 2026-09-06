import { readdir, readFile } from "node:fs/promises";
const directory = new URL("../apps/api/migrations/", import.meta.url);
const files = (await readdir(directory)).filter((file) => file.endsWith(".sql")).sort();
if (!files.length) throw new Error("no API migrations found");
const versions = new Set();
for (const file of files) {
  const match = /^(\d{3})_[a-z0-9_]+\.sql$/.exec(file);
  if (!match) throw new Error(`invalid migration filename: ${file}`);
  if (versions.has(match[1])) throw new Error(`duplicate migration version: ${match[1]}`);
  versions.add(match[1]);
  const sql = (await readFile(new URL(file, directory), "utf8")).trim();
  if (!/^BEGIN;/i.test(sql) || !/COMMIT;$/i.test(sql)) throw new Error(`${file} must own one explicit transaction`);
  if (/\b(DROP\s+(TABLE|COLUMN)|TRUNCATE)\b/i.test(sql)) throw new Error(`${file} contains a destructive operation requiring an expand/contract plan`);
}
console.log(`validated ${files.length} ordered migration(s)`);
