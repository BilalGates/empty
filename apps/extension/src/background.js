import { isAutofillAllowed, normalizeOrigin, originsMatch } from "./origin.js";
import { isMessage } from "./protocol.js";

const SESSION_TTL_MS = 60_000;
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
  if (!isAutofillAllowed(message.origin)) return { ok: false, state: "blocked", reason: "unsafe-origin" };
  const tab = await chrome.tabs.get(message.tabId);
  if (!tab.url || !originsMatch(tab.url, message.origin)) return { ok: false, state: "blocked", reason: "origin-mismatch" };
  if (message.type === "SPACE_GET_STATE") {
    const form = await ensureContent(message.tabId).catch(() => ({ kind: "none", usernameCount: 0, passwordCount: 0 }));
    const credentials = publicCredentials(message.origin);
    if (credentials === null) return { ok: true, state: "locked", form };
    return { ok: true, state: credentials.length ? "populated" : "empty", credentials, form };
  }
  if (message.type === "SPACE_SCAN") return { ok: true, ...(await ensureContent(message.tabId)) };
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
