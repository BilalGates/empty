import { isAutofillAllowed, normalizeOrigin, originsMatch } from "./origin.js";
import { isMessage } from "./protocol.js";
import { createEncryptedVault, importChromeCsv, unlockWithPassword, updateEncryptedVault } from "@space/core";

const SESSION_TTL_MS = 5 * 60_000;
const STORAGE_KEY = "encryptedVault";
const SESSION_KEY = "unlockedSession";
const SESSION_EXPIRY_ALARM = "unlocked-session-expiry";
let session = null;
let formStates = new Map();
let pendingImport = null;
let pendingImportTimer = null;
let operationQueue = Promise.resolve();
let sessionInvalidation = Promise.resolve();
let sessionGeneration = 0;

function clearPendingImport() {
  pendingImport = null;
  if (pendingImportTimer !== null) clearTimeout(pendingImportTimer);
  pendingImportTimer = null;
}

function extensionSender(sender) {
  return typeof sender.url === "string" && sender.url.startsWith(chrome.runtime.getURL(""));
}

const restrictSessionAccess = chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });

async function expireSession() {
  sessionGeneration += 1;
  session = null;
  clearPendingImport();
  await Promise.all([
    chrome.storage.session.remove(SESSION_KEY),
    chrome.alarms.clear(SESSION_EXPIRY_ALARM)
  ]);
}

function sessionIsActive(candidate = session) {
  return Boolean(candidate) && performance.now() < candidate.deadline;
}

async function restoreSession() {
  if (session) {
    if (sessionIsActive()) return;
    await expireSession();
    return;
  }
  const stored = (await chrome.storage.session.get(SESSION_KEY))[SESSION_KEY];
  const now = Date.now();
  const remaining = stored?.expiresAt - now;
  if (!stored || typeof stored !== "object" || !Number.isSafeInteger(stored.issuedAt) || !Number.isSafeInteger(stored.expiresAt) || now < stored.issuedAt || remaining <= 0 || remaining > SESSION_TTL_MS || typeof stored.password !== "string" || !stored.document) {
    await expireSession(); return;
  }
  sessionGeneration += 1;
  session = { document: stored.document, password: stored.password, credentials: credentialIndex(stored.document), issuedAt: stored.issuedAt, expiresAt: stored.expiresAt, deadline: performance.now() + remaining, generation: sessionGeneration };
  await chrome.alarms.create(SESSION_EXPIRY_ALARM, { when: session.expiresAt });
}

async function persistSession() {
  if (!session) { await expireSession(); return; }
  const activeSession = session;
  await chrome.storage.session.set({ [SESSION_KEY]: { document: activeSession.document, password: activeSession.password, issuedAt: activeSession.issuedAt, expiresAt: activeSession.expiresAt } });
  if (session !== activeSession || sessionGeneration !== activeSession.generation) {
    await chrome.storage.session.remove(SESSION_KEY);
    return;
  }
  await chrome.alarms.create(SESSION_EXPIRY_ALARM, { when: activeSession.expiresAt });
}

async function touchSession() {
  if (!session) return;
  session.issuedAt = Date.now();
  session.expiresAt = session.issuedAt + SESSION_TTL_MS;
  session.deadline = performance.now() + SESSION_TTL_MS;
  await persistSession();
}

function publicCredentials(origin) {
  if (!sessionIsActive()) {
    session = null;
    return null;
  }
  return session.credentials.filter((item) => item.origins.some((candidate) => originsMatch(candidate, origin)))
    .map(({ id, label, username }) => ({ id, label, username }));
}

function publicIndex() {
  if (!sessionIsActive()) {
    session = null;
    return null;
  }
  return session.credentials.map(({ id, label, username, origins }) => ({ id, label, username, origins }));
}

const credentialIndex = (document) => document.items
  .filter((item) => item.kind === "password" && !item.deletedAt)
  .map((item) => ({ id: item.id, label: item.title, username: item.username, password: item.password, origins: item.origins }));

async function openSession(document, password) {
  const issuedAt = Date.now();
  sessionGeneration += 1;
  session = { document, password, credentials: credentialIndex(document), issuedAt, expiresAt: issuedAt + SESSION_TTL_MS, deadline: performance.now() + SESSION_TTL_MS, generation: sessionGeneration };
  await persistSession();
}

async function readStoredVault() {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  return stored[STORAGE_KEY] ?? null;
}

async function persistDocument(document) {
  const vault = await readStoredVault();
  if (!vault || !session) { session = null; await persistSession(); return false; }
  const updated = updateEncryptedVault(vault, session.password, document);
  await chrome.storage.local.set({ [STORAGE_KEY]: updated });
  await openSession(document, session.password);
  return true;
}

async function ensureContent(tabId) {
  try {
    return await chrome.tabs.sendMessage(tabId, { type: "SPACE_CONTENT_SCAN" });
  } catch {
    await chrome.scripting.executeScript({ target: { tabId, allFrames: false }, files: ["content.js"] });
    return chrome.tabs.sendMessage(tabId, { type: "SPACE_CONTENT_SCAN" });
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "SPACE_FORM_STATE" && sender.tab && normalizeOrigin(message.origin)) {
    formStates.set(sender.tab.id, { kind: message.kind, usernameCount: message.usernameCount, passwordCount: message.passwordCount });
    return false;
  }
  if (!isMessage(message) || !extensionSender(sender)) return false;
  if (message.type === "SPACE_LOCK") {
    const operation = expireSession();
    sessionInvalidation = operation.then(() => undefined, () => undefined);
    void operation.then(() => sendResponse({ ok: true }), () => sendResponse({ ok: false, error: "internal" }));
    return true;
  }
  const operation = operationQueue.then(() => handle(message), () => handle(message));
  operationQueue = operation.then(() => undefined, () => undefined);
  void operation.then(sendResponse, () => sendResponse({ ok: false, error: "internal" }));
  return true;
});

async function handle(message) {
  await restrictSessionAccess;
  await sessionInvalidation;
  await restoreSession();
  if (message.type === "SPACE_LOCK") {
    await expireSession();
    return { ok: true };
  }
  if (message.type === "SPACE_CREATE_VAULT") {
    if (await readStoredVault()) return { ok: false, error: "vault-exists" };
    const now = new Date().toISOString();
    const document = { formatVersion: 1, vaultId: crypto.randomUUID(), revision: 0, createdAt: now, updatedAt: now, groups: [], items: [] };
    const created = createEncryptedVault(document, message.password);
    await chrome.storage.local.set({ [STORAGE_KEY]: created.vault });
    await openSession(document, message.password);
    return { ok: true, recoveryKey: created.recoveryKey };
  }
  if (message.type === "SPACE_UNLOCK") {
    const vault = await readStoredVault();
    if (!vault) return { ok: false, error: "vault-missing" };
    try {
      const document = unlockWithPassword(vault, message.password);
      await openSession(document, message.password);
      return { ok: true };
    } catch {
      return { ok: false, error: "invalid-credentials" };
    }
  }
  if (!isAutofillAllowed(message.origin)) return { ok: false, state: "blocked", reason: "unsafe-origin" };
  const tab = await chrome.tabs.get(message.tabId);
  if (!tab.url || !originsMatch(tab.url, message.origin)) return { ok: false, state: "blocked", reason: "origin-mismatch" };
  if (message.type === "SPACE_GET_STATE") {
    const form = await ensureContent(message.tabId).catch(() => ({ kind: "none", usernameCount: 0, passwordCount: 0 }));
    const credentials = publicCredentials(message.origin);
    if (credentials === null) return { ok: true, state: "locked", hasVault: Boolean(await readStoredVault()), form };
    return { ok: true, state: credentials.length ? "populated" : "empty", credentials, allCredentials: publicIndex(), form };
  }
  if (message.type === "SPACE_GET_SECRET") {
    const index = publicIndex();
    const activeSession = session;
    const selected = index && activeSession.credentials.find((item) => item.id === message.credentialId);
    if (!selected) return { ok: false, error: "credential-unavailable" };
    await touchSession();
    if (session !== activeSession || sessionGeneration !== activeSession.generation || !sessionIsActive(activeSession)) return { ok: false, error: "locked" };
    return { ok: true, username: selected.username, password: selected.password };
  }
  if (message.type === "SPACE_PREVIEW_IMPORT") {
    clearPendingImport();
    const index = publicIndex();
    if (!index) return { ok: false, error: "locked" };
    try {
      const parsed = importChromeCsv(message.csv);
      const existing = new Set(session.credentials.flatMap((item) =>
        item.origins.map((origin) => `${origin}\u0000${item.username}\u0000${item.password}`)
      ));
      let unsafe = 0;
      let existingDuplicates = 0;
      const accepted = parsed.accepted.filter((item) => {
        const normalized = normalizeOrigin(item.url);
        if (!normalized || !isAutofillAllowed(normalized)) { unsafe += 1; return false; }
        const candidate = `${normalized}\u0000${item.username}\u0000${item.password}`;
        if (existing.has(candidate)) { existingDuplicates += 1; return false; }
        existing.add(candidate); return true;
      });
      pendingImport = { token: crypto.randomUUID(), accepted, expiresAt: performance.now() + 120_000 };
      pendingImportTimer = setTimeout(clearPendingImport, 120_000);
      return { ok: true, token: pendingImport.token, accepted: accepted.length, duplicates: parsed.duplicates.length + existingDuplicates, issues: parsed.issues.slice(0, 100), issueCount: parsed.issues.length + unsafe };
    } catch { clearPendingImport(); return { ok: false, error: "invalid-import" }; }
  }
  if (message.type === "SPACE_COMMIT_IMPORT") {
    if (!session || !pendingImport || pendingImport.token !== message.token || performance.now() >= pendingImport.expiresAt) { clearPendingImport(); return { ok: false, error: "import-expired" }; }
    const now = new Date().toISOString();
    const imported = pendingImport.accepted.map((item) => ({ id: crypto.randomUUID(), kind: "password", title: item.title, origins: [normalizeOrigin(item.url)], username: item.username, password: item.password, ...(item.note ? { notes: item.note } : {}), favorite: false, createdAt: now, updatedAt: now, version: 1 }));
    const document = { ...session.document, revision: session.document.revision + 1, updatedAt: now, items: [...session.document.items, ...imported] };
    if (!await persistDocument(document)) { clearPendingImport(); return { ok: false, error: "vault-missing" }; }
    clearPendingImport();
    return { ok: true, imported: imported.length };
  }
  if (message.type === "SPACE_SCAN") return { ok: true, ...(await ensureContent(message.tabId)) };
  if (message.type === "SPACE_ADD_CREDENTIAL") {
    if (!sessionIsActive()) { session = null; return { ok: false, error: "locked" }; }
    const now = new Date().toISOString();
    const item = { id: crypto.randomUUID(), kind: "password", title: message.title, origins: [normalizeOrigin(message.origin)], username: message.username, password: message.password, favorite: false, createdAt: now, updatedAt: now, version: 1 };
    const document = { ...session.document, revision: session.document.revision + 1, updatedAt: now, items: [...session.document.items, item] };
    if (!await persistDocument(document)) return { ok: false, error: "vault-missing" };
    return { ok: true, credentialId: item.id };
  }
  if (message.type === "SPACE_UPDATE_CREDENTIAL") {
    if (!session) return { ok: false, error: "locked" };
    if (!message.title.trim()) return { ok: false, error: "invalid-credential" };
    const website = normalizeOrigin(message.website);
    if (!website || !isAutofillAllowed(website)) return { ok: false, error: "unsafe-origin" };
    const index = session.document.items.findIndex((item) => item.id === message.credentialId && item.kind === "password" && !item.deletedAt);
    if (index < 0) return { ok: false, error: "credential-unavailable" };
    const now = new Date().toISOString();
    const current = session.document.items[index];
    const replacement = { ...current, title: message.title.trim(), origins: [website], username: message.username, password: message.password, updatedAt: now, version: current.version + 1 };
    const items = session.document.items.slice(); items[index] = replacement;
    const document = { ...session.document, revision: session.document.revision + 1, updatedAt: now, items };
    if (!await persistDocument(document)) return { ok: false, error: "vault-missing" };
    return { ok: true };
  }
  if (message.type === "SPACE_DELETE_CREDENTIAL") {
    if (!session) return { ok: false, error: "locked" };
    const index = session.document.items.findIndex((item) => item.id === message.credentialId && item.kind === "password" && !item.deletedAt);
    if (index < 0) return { ok: false, error: "credential-unavailable" };
    const now = new Date().toISOString();
    const current = session.document.items[index];
    const items = session.document.items.slice();
    items[index] = { ...current, deletedAt: now, updatedAt: now, version: current.version + 1 };
    const document = { ...session.document, revision: session.document.revision + 1, updatedAt: now, items };
    if (!await persistDocument(document)) return { ok: false, error: "vault-missing" };
    return { ok: true };
  }
  if (message.type === "SPACE_EXPORT_BACKUP") {
    const vault = await readStoredVault();
    if (!vault) return { ok: false, error: "vault-missing" };
    try {
      unlockWithPassword(vault, message.password);
      const activeSession = session;
      await touchSession();
      if (session !== activeSession || !activeSession || sessionGeneration !== activeSession.generation || !sessionIsActive(activeSession)) return { ok: false, error: "locked" };
      return { ok: true, filename: "space-backup.json", content: JSON.stringify(vault) };
    } catch { return { ok: false, error: "invalid-credentials" }; }
  }
  if (message.type === "SPACE_FILL_GENERATED") {
    await ensureContent(message.tabId);
    return chrome.tabs.sendMessage(message.tabId, { type: "SPACE_CONTENT_FILL", requestId: crypto.randomUUID(),
      origin: message.origin, credential: { username: "", password: message.password } });
  }
  const credentials = publicCredentials(message.origin);
  const activeSession = session;
  const activeGeneration = sessionGeneration;
  const selected = credentials && activeSession.credentials.find((item) => item.id === message.credentialId);
  if (!selected || !selected.origins.some((candidate) => originsMatch(candidate, message.origin))) return { ok: false, error: "credential-unavailable" };
  await ensureContent(message.tabId);
  if (session !== activeSession || sessionGeneration !== activeGeneration || !sessionIsActive(activeSession)) {
    await expireSession();
    return { ok: false, error: "locked" };
  }
  const response = await chrome.tabs.sendMessage(message.tabId, { type: "SPACE_CONTENT_FILL", requestId: crypto.randomUUID(),
    origin: message.origin, credential: { username: selected.username, password: selected.password } });
  if (response?.ok) await touchSession();
  return response;
}

chrome.runtime.onSuspend.addListener(() => {
  session = null;
  clearPendingImport();
  formStates.clear();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== SESSION_EXPIRY_ALARM) return;
  const operation = expireSession();
  sessionInvalidation = operation.then(() => undefined, () => undefined);
});
