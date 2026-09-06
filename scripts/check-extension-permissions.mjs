import { readFile } from 'node:fs/promises';

const manifest = JSON.parse(await readFile(new URL('../apps/extension/manifest.json', import.meta.url), 'utf8'));
const forbidden = new Set(['<all_urls>', 'tabs', 'webRequest', 'webRequestBlocking', 'nativeMessaging', 'debugger']);
const declared = [...(manifest.permissions ?? []), ...(manifest.host_permissions ?? [])];
const found = declared.filter(permission => forbidden.has(permission));
if (manifest.manifest_version !== 3) throw new Error('Extension must use Manifest V3');
if (found.length) throw new Error(`Forbidden broad permissions: ${found.join(', ')}`);
if (manifest.content_security_policy?.extension_pages?.includes('unsafe-eval')) throw new Error('unsafe-eval is forbidden');
console.log(`Extension permission gate passed: ${declared.join(', ') || 'none'}`);

