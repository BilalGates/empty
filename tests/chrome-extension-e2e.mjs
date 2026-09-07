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
  const wrongRecovery = ['invalid', 'recovery', 'value'].join('-');
  const rejectedUnlock = await control.evaluate((password) => chrome.runtime.sendMessage({ type: 'SPACE_UNLOCK', password }), wrongMaster);
  assert(!rejectedUnlock.ok, 'Wrong master password unlocked the vault');
  const unlocked = await control.evaluate((password) => chrome.runtime.sendMessage({ type: 'SPACE_UNLOCK', password }), master);
  assert(unlocked.ok, 'Correct master password did not unlock the vault');
  const unlockedStorage = await control.evaluate(() => chrome.storage.session.get('unlockedSession'));
  assert(typeof unlockedStorage.unlockedSession?.vaultKey === 'string', 'Unlocked session did not retain the vault key');
  assert(!JSON.stringify(unlockedStorage).includes(master) && !('password' in unlockedStorage.unlockedSession) && !('document' in unlockedStorage.unlockedSession), 'Unlocked session retained master password or plaintext document');
  const page = await context.newPage();

  await page.goto(`${baseUrl}/traditional-login.html`);
  await page.bringToFront();
  const cdp = await context.newCDPSession(control);
  const targets = await cdp.send('Target.getTargets');
  const workerTarget = targets.targetInfos.find((target) => target.type === 'service_worker' && target.url.startsWith(`chrome-extension://${extensionId}/`));
  assert(workerTarget, 'Extension service-worker target was not found');
  await cdp.send('Target.closeTarget', { targetId: workerTarget.targetId });
  const restoredState = await control.evaluate(async ({ origin: currentOrigin }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return chrome.runtime.sendMessage({ type: 'SPACE_GET_STATE', tabId: tab.id, origin: currentOrigin });
  }, { origin: new URL(page.url()).origin });
  assert(restoredState.ok && restoredState.state === 'empty', 'Memory-only unlocked session did not survive normal MV3 worker termination');
  const contentCanReadSession = await control.evaluate(async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => new Promise((resolve) => {
        const timeout = setTimeout(() => resolve(false), 1_000);
        try {
          chrome.storage.session.get('unlockedSession', (stored) => {
            clearTimeout(timeout);
            resolve(Boolean(stored?.unlockedSession));
          });
        } catch {
          clearTimeout(timeout);
          resolve(false);
        }
      })
    });
    return result.result;
  });
  assert(contentCanReadSession === false, 'Content-script context could read the unlocked session');
  const traditional = await command(control, page, { type: 'SPACE_CONTENT_SCAN' });
  assert(traditional.kind === 'login', 'Traditional login was not detected');
  const origin = new URL(page.url()).origin;
  const importedPassword = ['imported', 'fixture', 'value'].join('-');
  const preview = await control.evaluate(async ({ origin: currentOrigin, csv }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return chrome.runtime.sendMessage({ type: 'SPACE_PREVIEW_IMPORT', tabId: tab.id, origin: currentOrigin, csv });
  }, { origin, csv: `name,url,username,password\nOther,https://other.example,other@example.com,${importedPassword}\nUnsafe,http://other.example,user,unsafe-value` });
  assert(preview.ok && preview.accepted === 1 && preview.duplicates === 0 && preview.issueCount === 1, `CSV import preview failed: ${JSON.stringify(preview)}`);
  const committedImport = await control.evaluate(async ({ origin: currentOrigin, token }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return chrome.runtime.sendMessage({ type: 'SPACE_COMMIT_IMPORT', tabId: tab.id, origin: currentOrigin, token });
  }, { origin, token: preview.token });
  assert(committedImport.ok && committedImport.imported === 1, 'CSV import commit failed');
  const afterImportStorage = await control.evaluate(() => chrome.storage.local.get('encryptedVault'));
  assert(!JSON.stringify(afterImportStorage).includes(importedPassword), 'Imported plaintext leaked to extension storage');
  const added = await control.evaluate(async ({ origin: currentOrigin }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const startedAt = performance.now();
    const response = await chrome.runtime.sendMessage({ type: 'SPACE_ADD_CREDENTIAL', tabId: tab.id, origin: currentOrigin, title: 'Fixture', username: 'person@example.com', password: 'test-value' });
    return { ...response, elapsedMs: performance.now() - startedAt };
  }, { origin });
  assert(added.ok && added.elapsedMs < 5_000, `Credential save was not fast after unlock: ${added.elapsedMs}ms`);
  const state = await control.evaluate(async ({ origin: currentOrigin }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return chrome.runtime.sendMessage({ type: 'SPACE_GET_STATE', tabId: tab.id, origin: currentOrigin });
  }, { origin });
  assert(state.state === 'populated' && state.credentials.length === 1 && state.allCredentials.length === 2, 'Saved/imported credentials were not indexed correctly');
  assert(!('password' in state.credentials[0]), 'Credential list exposed a password');
  assert(state.allCredentials.every((credential) => !('password' in credential)), 'Search index exposed a password');
  const explicitSecret = await control.evaluate(async ({ origin: currentOrigin, credentialId }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return chrome.runtime.sendMessage({ type: 'SPACE_GET_SECRET', tabId: tab.id, origin: currentOrigin, credentialId });
  }, { origin, credentialId: state.credentials[0].id });
  assert(explicitSecret.ok && explicitSecret.password === 'test-value', 'Explicit trusted-context secret access failed');
  const activeWorker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');
  const delayInstalled = await activeWorker.evaluate(() => {
    const original = chrome.tabs.sendMessage.bind(chrome.tabs);
    globalThis.__spaceOriginalSendMessage = original;
    const delayed = async (tabId, message, ...rest) => {
      if (message?.type === 'SPACE_CONTENT_SCAN') await new Promise((resolveDelay) => setTimeout(resolveDelay, 400));
      return original(tabId, message, ...rest);
    };
    chrome.tabs.sendMessage = delayed;
    return chrome.tabs.sendMessage === delayed;
  });
  assert(delayInstalled, 'Could not install the deterministic fill-race delay');
  const racingFill = control.evaluate(async ({ origin: currentOrigin, credentialId }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return chrome.runtime.sendMessage({ type: 'SPACE_FILL', tabId: tab.id, origin: currentOrigin, credentialId });
  }, { origin, credentialId: state.credentials[0].id });
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 100));
  const lockedDuringFill = await control.evaluate(() => chrome.runtime.sendMessage({ type: 'SPACE_LOCK' }));
  const racedFillResult = await racingFill;
  assert(lockedDuringFill.ok && !racedFillResult.ok && racedFillResult.error === 'locked', 'Lock did not cancel a fill already in flight');
  assert(await page.locator('input[type=email]').inputValue() === '' && await page.locator('input[type=password]').inputValue() === '', 'A secret was filled after lock');
  await activeWorker.evaluate(() => { chrome.tabs.sendMessage = globalThis.__spaceOriginalSendMessage; });
  const unlockedAfterRace = await control.evaluate((password) => chrome.runtime.sendMessage({ type: 'SPACE_UNLOCK', password }), master);
  assert(unlockedAfterRace.ok, 'Vault did not unlock after the fill-race check');
  const fill = await control.evaluate(async ({ origin: currentOrigin, credentialId }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return chrome.runtime.sendMessage({ type: 'SPACE_FILL', tabId: tab.id, origin: currentOrigin, credentialId });
  }, { origin, credentialId: state.credentials[0].id });
  assert(fill.ok, 'Traditional login was not filled');
  assert(await page.locator('input[type=email]').inputValue() === 'person@example.com', 'Username fill failed');
  assert(await page.locator('input[type=password]').inputValue() === 'test-value', 'Password fill failed');
  const rejected = await command(control, page, {
    type: 'SPACE_CONTENT_FILL', requestId: crypto.randomUUID(), origin: 'https://lookalike.example',
    credential: { username: 'attacker', password: 'attacker' }
  });
  assert(rejected.error === 'origin-mismatch', 'Origin confusion did not fail closed');
  const rejectedBackup = await control.evaluate(async ({ origin: currentOrigin, password }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return chrome.runtime.sendMessage({ type: 'SPACE_EXPORT_BACKUP', tabId: tab.id, origin: currentOrigin, password });
  }, { origin, password: wrongMaster });
  assert(!rejectedBackup.ok && rejectedBackup.error === 'invalid-credentials', 'Backup export skipped reauthentication');
  const backup = await control.evaluate(async ({ origin: currentOrigin, password }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return chrome.runtime.sendMessage({ type: 'SPACE_EXPORT_BACKUP', tabId: tab.id, origin: currentOrigin, password });
  }, { origin, password: master });
  assert(backup.ok && backup.filename === 'space-backup.json', 'Encrypted backup export failed');
  assert(JSON.parse(backup.content).ciphertext && !backup.content.includes('test-value'), 'Backup was not ciphertext-only');
  const updatedPassword = ['updated', 'test', 'value'].join('-');
  const updated = await control.evaluate(async ({ origin: currentOrigin, credentialId, password }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const startedAt = performance.now();
    const response = await chrome.runtime.sendMessage({ type: 'SPACE_UPDATE_CREDENTIAL', tabId: tab.id, origin: currentOrigin, credentialId, title: 'Updated fixture', website: currentOrigin, username: 'updated@example.com', password });
    return { ...response, elapsedMs: performance.now() - startedAt };
  }, { origin, credentialId: state.credentials[0].id, password: updatedPassword });
  assert(updated.ok && updated.elapsedMs < 5_000, `Credential update was not fast after unlock: ${updated.elapsedMs}ms`);
  const updatedSecret = await control.evaluate(async ({ origin: currentOrigin, credentialId }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return chrome.runtime.sendMessage({ type: 'SPACE_GET_SECRET', tabId: tab.id, origin: currentOrigin, credentialId });
  }, { origin, credentialId: state.credentials[0].id });
  assert(updatedSecret.ok && updatedSecret.username === 'updated@example.com' && updatedSecret.password === updatedPassword, 'Updated secret was not available');
  const afterUpdateStorage = await control.evaluate(() => chrome.storage.local.get('encryptedVault'));
  assert(!JSON.stringify(afterUpdateStorage).includes(updatedPassword), 'Updated plaintext leaked to persistent storage');
  const deleted = await control.evaluate(async ({ origin: currentOrigin, credentialId }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return chrome.runtime.sendMessage({ type: 'SPACE_DELETE_CREDENTIAL', tabId: tab.id, origin: currentOrigin, credentialId });
  }, { origin, credentialId: state.credentials[0].id });
  assert(deleted.ok, 'Credential deletion failed');
  const afterDelete = await control.evaluate(async ({ origin: currentOrigin }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return chrome.runtime.sendMessage({ type: 'SPACE_GET_STATE', tabId: tab.id, origin: currentOrigin });
  }, { origin });
  assert(afterDelete.state === 'empty' && afterDelete.credentials.length === 0 && afterDelete.allCredentials.length === 1, 'Deleted credential remained indexed');
  const rejectedRestore = await control.evaluate(async ({ origin: currentOrigin, content, recoveryKey }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return chrome.runtime.sendMessage({ type: 'SPACE_RESTORE_BACKUP', tabId: tab.id, origin: currentOrigin, content, method: 'recovery-key', secret: recoveryKey, replaceConfirmed: true });
  }, { origin, content: backup.content, recoveryKey: wrongRecovery });
  assert(!rejectedRestore.ok && rejectedRestore.error === 'invalid-backup', 'Backup restore accepted an incorrect recovery key');
  const stateAfterRejectedRestore = await control.evaluate(async ({ origin: currentOrigin }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return chrome.runtime.sendMessage({ type: 'SPACE_GET_STATE', tabId: tab.id, origin: currentOrigin });
  }, { origin });
  assert(stateAfterRejectedRestore.state === 'empty', 'Rejected restore changed the current vault');
  const restoredBackup = await control.evaluate(async ({ origin: currentOrigin, content, recoveryKey }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return chrome.runtime.sendMessage({ type: 'SPACE_RESTORE_BACKUP', tabId: tab.id, origin: currentOrigin, content, method: 'recovery-key', secret: recoveryKey, replaceConfirmed: true });
  }, { origin, content: backup.content, recoveryKey: createdVault.recoveryKey });
  assert(restoredBackup.ok && restoredBackup.restored === 2, 'Encrypted backup restore failed');
  const stateAfterRestore = await control.evaluate(async ({ origin: currentOrigin }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return chrome.runtime.sendMessage({ type: 'SPACE_GET_STATE', tabId: tab.id, origin: currentOrigin });
  }, { origin });
  assert(stateAfterRestore.state === 'populated' && stateAfterRestore.allCredentials.length === 2, 'Restored credentials were not available');

  await page.goto(`${baseUrl}/dynamic-login.html`);
  await page.locator('#add').click();
  const dynamic = await command(control, page, { type: 'SPACE_CONTENT_SCAN' });
  assert(dynamic.kind === 'login', 'Dynamic form was not detected');

  await page.goto(`${baseUrl}/spa-login.html`);
  await page.locator('#navigate').click();
  const spa = await command(control, page, { type: 'SPACE_CONTENT_SCAN' });
  assert(spa.kind === 'login', 'SPA form was not detected');

  await page.goto(`${baseUrl}/signup.html`);
  const signup = await command(control, page, { type: 'SPACE_CONTENT_SCAN' });
  assert(signup.kind === 'signup', 'Signup was not classified');
  const guarded = await command(control, page, {
    type: 'SPACE_CONTENT_FILL', requestId: crypto.randomUUID(), origin: new URL(page.url()).origin,
    credential: { username: '', password: 'test-value' }
  });
  assert(guarded.error === 'confirmation-required', 'Signup fill did not require confirmation');
  console.log('Chrome MV3 E2E passed: encrypted vault, key-only session, session restore, local import, backup reauth/restore, edit/delete, plaintext guards, fill, dynamic, SPA, signup guard, exact-origin rejection.');
} finally {
  if (context) await context.close();
  await new Promise((resolveClose) => server.close(resolveClose));
  await rm(profile, { recursive: true, force: true });
  await rm(testExtensionPath, { recursive: true, force: true });
}
