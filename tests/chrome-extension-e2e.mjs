import { createServer } from 'node:http';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { chromium } from 'playwright';

const extensionPath = resolve('apps/extension/dist');
const fixturePath = resolve('tests/fixtures/chrome');
const allowedFixtures = new Set(['traditional-login.html', 'dynamic-login.html', 'spa-login.html', 'signup.html']);
const server = createServer(async (request, response) => {
  const file = basename(new URL(request.url ?? '/', 'http://fixture').pathname);
  if (!allowedFixtures.has(file)) { response.writeHead(404).end(); return; }
  response.setHeader('content-type', 'text/html; charset=utf-8');
  response.end(await readFile(join(fixturePath, file)));
});
await new Promise((resolveListen) => server.listen(0, '127.0.0.1', resolveListen));
const address = server.address();
if (!address || typeof address === 'string') throw new Error('Fixture server did not start');
const baseUrl = `http://127.0.0.1:${address.port}`;
const profile = await mkdtemp(join(tmpdir(), 'space-chrome-e2e-'));
const testExtensionPath = await mkdtemp(join(tmpdir(), 'space-extension-e2e-'));
await cp(extensionPath, testExtensionPath, { recursive: true });
const testManifestPath = join(testExtensionPath, 'manifest.json');
const testManifest = JSON.parse(await readFile(testManifestPath, 'utf8'));
testManifest.host_permissions = [`${baseUrl}/*`];
await writeFile(testManifestPath, `${JSON.stringify(testManifest, null, 2)}\n`);
let context;

async function command(worker, page, message) {
  return worker.evaluate(async ({ contentMessage }) => {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tabId = tabs[0]?.id;
    if (!tabId) throw new Error('Fixture tab not found');
    try {
      await chrome.tabs.sendMessage(tabId, { type: 'SPACE_CONTENT_SCAN' });
    } catch {
      await chrome.scripting.executeScript({ target: { tabId }, files: ['content.js'] });
    }
    return chrome.tabs.sendMessage(tabId, contentMessage);
  }, { contentMessage: message });
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

try {
  context = await chromium.launchPersistentContext(profile, {
    channel: 'chromium',
    headless: true,
    args: [`--disable-extensions-except=${testExtensionPath}`, `--load-extension=${testExtensionPath}`]
  });
  const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');
  assert(worker.url().startsWith('chrome-extension://'), 'MV3 service worker did not load');
  const extensionId = new URL(worker.url()).hostname;
  const control = await context.newPage();
  await control.goto(`chrome-extension://${extensionId}/popup.html`);
  const master = ['correct', 'horse', 'battery', 'staple'].join(' ');
  const createdVault = await control.evaluate((password) => chrome.runtime.sendMessage({ type: 'SPACE_CREATE_VAULT', password }), master);
  assert(createdVault.ok && typeof createdVault.recoveryKey === 'string', 'Encrypted vault creation failed');
  const stored = await control.evaluate(() => chrome.storage.local.get('encryptedVault'));
  assert(JSON.stringify(stored).includes('ciphertext'), 'Ciphertext was not persisted');
  assert(!JSON.stringify(stored).includes(master), 'Master password leaked to extension storage');
  await control.evaluate(() => chrome.runtime.sendMessage({ type: 'SPACE_LOCK' }));
  const wrongMaster = ['wrong', 'master', 'value'].join('-');
  const rejectedUnlock = await control.evaluate((password) => chrome.runtime.sendMessage({ type: 'SPACE_UNLOCK', password }), wrongMaster);
  assert(!rejectedUnlock.ok, 'Wrong master password unlocked the vault');
  const unlocked = await control.evaluate((password) => chrome.runtime.sendMessage({ type: 'SPACE_UNLOCK', password }), master);
  assert(unlocked.ok, 'Correct master password did not unlock the vault');
  const page = await context.newPage();

  await page.goto(`${baseUrl}/traditional-login.html`);
  await page.bringToFront();
  const traditional = await command(worker, page, { type: 'SPACE_CONTENT_SCAN' });
  assert(traditional.kind === 'login', 'Traditional login was not detected');
  const origin = new URL(page.url()).origin;
  const added = await control.evaluate(async ({ origin: currentOrigin }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return chrome.runtime.sendMessage({ type: 'SPACE_ADD_CREDENTIAL', tabId: tab.id, origin: currentOrigin, title: 'Fixture', username: 'person@example.com', password: 'test-value' });
  }, { origin });
  assert(added.ok, 'Credential was not encrypted and saved');
  const state = await control.evaluate(async ({ origin: currentOrigin }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return chrome.runtime.sendMessage({ type: 'SPACE_GET_STATE', tabId: tab.id, origin: currentOrigin });
  }, { origin });
  assert(state.state === 'populated' && state.credentials.length === 1, 'Saved credential was not indexed');
  assert(!('password' in state.credentials[0]), 'Credential list exposed a password');
  assert(state.allCredentials.length === 1 && !('password' in state.allCredentials[0]), 'Search index exposed a password');
  const explicitSecret = await control.evaluate(async ({ origin: currentOrigin, credentialId }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return chrome.runtime.sendMessage({ type: 'SPACE_GET_SECRET', tabId: tab.id, origin: currentOrigin, credentialId });
  }, { origin, credentialId: state.credentials[0].id });
  assert(explicitSecret.ok && explicitSecret.password === 'test-value', 'Explicit trusted-context secret access failed');
  const fill = await control.evaluate(async ({ origin: currentOrigin, credentialId }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return chrome.runtime.sendMessage({ type: 'SPACE_FILL', tabId: tab.id, origin: currentOrigin, credentialId });
  }, { origin, credentialId: state.credentials[0].id });
  assert(fill.ok, 'Traditional login was not filled');
  assert(await page.locator('input[type=email]').inputValue() === 'person@example.com', 'Username fill failed');
  assert(await page.locator('input[type=password]').inputValue() === 'test-value', 'Password fill failed');
  const rejected = await command(worker, page, {
    type: 'SPACE_CONTENT_FILL', requestId: crypto.randomUUID(), origin: 'https://lookalike.example',
    credential: { username: 'attacker', password: 'attacker' }
  });
  assert(rejected.error === 'origin-mismatch', 'Origin confusion did not fail closed');

  await page.goto(`${baseUrl}/dynamic-login.html`);
  await page.locator('#add').click();
  const dynamic = await command(worker, page, { type: 'SPACE_CONTENT_SCAN' });
  assert(dynamic.kind === 'login', 'Dynamic form was not detected');

  await page.goto(`${baseUrl}/spa-login.html`);
  await page.locator('#navigate').click();
  const spa = await command(worker, page, { type: 'SPACE_CONTENT_SCAN' });
  assert(spa.kind === 'login', 'SPA form was not detected');

  await page.goto(`${baseUrl}/signup.html`);
  const signup = await command(worker, page, { type: 'SPACE_CONTENT_SCAN' });
  assert(signup.kind === 'signup', 'Signup was not classified');
  const guarded = await command(worker, page, {
    type: 'SPACE_CONTENT_FILL', requestId: crypto.randomUUID(), origin: new URL(page.url()).origin,
    credential: { username: '', password: 'test-value' }
  });
  assert(guarded.error === 'confirmation-required', 'Signup fill did not require confirmation');
  console.log('Chrome MV3 E2E passed: encrypted vault, public search index, explicit secret access, fill, dynamic, SPA, signup guard, exact-origin rejection.');
} finally {
  if (context) await context.close();
  await new Promise((resolveClose) => server.close(resolveClose));
  await rm(profile, { recursive: true, force: true });
  await rm(testExtensionPath, { recursive: true, force: true });
}
