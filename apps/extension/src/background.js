import { isAutofillAllowed, normalizeOrigin, originsMatch } from "./origin.js";
import { isMessage } from "./protocol.js";
import { createEncryptedVault, unlockWithPassword, updateEncryptedVault } from "@space/core";

const SESSION_TTL_MS = 60_000;
const STORAGE_KEY = "encryptedVault";
let session = null;
let formStates = new Map();

function extensionSender(sender) {
  return typeof sender.url === "string" && sender.url.startsWith(chrome.runtime.getURL(""));
}

function publicCredentials(origin) {
  if (!session || performance.now() >= session.expiresAt) {
    session = null;
    return null;
  }
  return session.credentials.filter((item) => item.origins.some((candidate) => originsMatch(candidate, origin)))
    .map(({ id, label, username }) => ({ id, label, username }));
}

function publicIndex() {
  if (!session || performance.now() >= session.expiresAt) {
    session = null;
    return null;
  }
  return session.credentials.map(({ id, label, username, origins }) => ({ id, label, username, origins }));
}

const credentialIndex = (document) => document.items
  .filter((item) => item.kind === "password" && !item.deletedAt)
  .map((item) => ({ id: item.id, label: item.title, username: item.username, password: item.password, origins: item.origins }));

function openSession(document, password) {
  session = { document, password, credentials: credentialIndex(document), expiresAt: performance.now() + SESSION_TTL_MS };
}

async function readStoredVault() {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  return stored[STORAGE_KEY] ?? null;
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
  void handle(message).then(sendResponse, () => sendResponse({ ok: false, error: "internal" }));
  return true;
});

async function handle(message) {
  if (message.type === "SPACE_LOCK") {
    session = null;
    return { ok: true };
  }
  if (message.type === "SPACE_CREATE_VAULT") {
    if (await readStoredVault()) return { ok: false, error: "vault-exists" };
    const now = new Date().toISOString();
    const document = { formatVersion: 1, vaultId: crypto.randomUUID(), revision: 0, createdAt: now, updatedAt: now, groups: [], items: [] };
    const created = createEncryptedVault(document, message.password);
    await chrome.storage.local.set({ [STORAGE_KEY]: created.vault });
    openSession(document, message.password);
    return { ok: true, recoveryKey: created.recoveryKey };
  }
  if (message.type === "SPACE_UNLOCK") {
    const vault = await readStoredVault();
    if (!vault) return { ok: false, error: "vault-missing" };
    try {
      const document = unlockWithPassword(vault, message.password);
      openSession(document, message.password);
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
    const selected = index && session.credentials.find((item) => item.id === message.credentialId);
    if (!selected) return { ok: false, error: "credential-unavailable" };
    session.expiresAt = performance.now() + SESSION_TTL_MS;
    return { ok: true, username: selected.username, password: selected.password };
  }
  if (message.type === "SPACE_SCAN") return { ok: true, ...(await ensureContent(message.tabId)) };
  if (message.type === "SPACE_ADD_CREDENTIAL") {
    if (!session || performance.now() >= session.expiresAt) { session = null; return { ok: false, error: "locked" }; }
    const now = new Date().toISOString();
    const item = { id: crypto.randomUUID(), kind: "password", title: message.title, origins: [normalizeOrigin(message.origin)], username: message.username, password: message.password, favorite: false, createdAt: now, updatedAt: now, version: 1 };
    const document = { ...session.document, revision: session.document.revision + 1, updatedAt: now, items: [...session.document.items, item] };
    const vault = await readStoredVault();
    if (!vault) { session = null; return { ok: false, error: "vault-missing" }; }
    const updated = updateEncryptedVault(vault, session.password, document);
    await chrome.storage.local.set({ [STORAGE_KEY]: updated });
    openSession(document, session.password);
    return { ok: true, credentialId: item.id };
  }
  if (message.type === "SPACE_FILL_GENERATED") {
    await ensureContent(message.tabId);
    return chrome.tabs.sendMessage(message.tabId, { type: "SPACE_CONTENT_FILL", requestId: crypto.randomUUID(),
      origin: message.origin, credential: { username: "", password: message.password } });
  }
  const credentials = publicCredentials(message.origin);
  const selected = credentials && session.credentials.find((item) => item.id === message.credentialId);
  if (!selected || !selected.origins.some((candidate) => originsMatch(candidate, message.origin))) return { ok: false, error: "credential-unavailable" };
  await ensureContent(message.tabId);
  const response = await chrome.tabs.sendMessage(message.tabId, { type: "SPACE_CONTENT_FILL", requestId: crypto.randomUUID(),
    origin: message.origin, credential: { username: selected.username, password: selected.password } });
  if (response?.ok) session.expiresAt = performance.now() + SESSION_TTL_MS;
  return response;
}

chrome.runtime.onSuspend.addListener(() => {
  session = null;
  formStates.clear();
});
