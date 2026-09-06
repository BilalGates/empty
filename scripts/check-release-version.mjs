import { readFile } from "node:fs/promises";
const requested = process.argv[2]?.replace(/^v/, "");
if (!requested || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(requested)) throw new Error("release requires a SemVer tag");
const root = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const api = JSON.parse(await readFile(new URL("../apps/api/package.json", import.meta.url), "utf8"));
for (const [name, version] of [["root", root.version], ["API", api.version]]) if (version !== requested) throw new Error(`${name} version ${version ?? "missing"} does not match ${requested}`);
console.log(`release version ${requested} is consistent`);
