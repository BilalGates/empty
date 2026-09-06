import { chooseFillTargets, detectDocument } from "./detection.js";
import { originsMatch } from "./origin.js";
import { isMessage } from "./protocol.js";

if (!globalThis.__spaceContentInstalled) {
  globalThis.__spaceContentInstalled = true;
  let lastSignature = "";
  let scheduled = false;

  const report = () => {
    scheduled = false;
    const result = detectDocument();
    const signature = `${location.origin}:${result.kind}:${result.usernameCount}:${result.passwordCount}`;
    if (signature === lastSignature) return;
    lastSignature = signature;
    chrome.runtime.sendMessage({ type: "SPACE_FORM_STATE", origin: location.origin, kind: result.kind,
      usernameCount: result.usernameCount, passwordCount: result.passwordCount }).catch(() => {});
  };
  const schedule = () => {
    if (scheduled) return;
    scheduled = true;
    queueMicrotask(report);
  };
  new MutationObserver(schedule).observe(document.documentElement, { childList: true, subtree: true, attributes: true,
    attributeFilter: ["type", "name", "autocomplete", "disabled", "readonly", "style", "class"] });
  addEventListener("pageshow", schedule, { passive: true });
  addEventListener("popstate", schedule, { passive: true });
  addEventListener("hashchange", schedule, { passive: true });

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (!isMessage(message)) return false;
    if (message.type === "SPACE_CONTENT_SCAN") {
      const { kind, usernameCount, passwordCount } = detectDocument();
      sendResponse({ ok: true, kind, usernameCount, passwordCount });
      return false;
    }
    if (message.type !== "SPACE_CONTENT_FILL") return false;
    if (!originsMatch(message.origin, location.origin)) {
      sendResponse({ ok: false, error: "origin-mismatch" });
      return false;
    }
    const target = chooseFillTargets();
    if (target.kind !== "login" || !target.password) {
      sendResponse({ ok: false, error: target.kind === "none" ? "no-login-form" : "confirmation-required" });
      return false;
    }
    if (target.username && message.credential.username) setNativeValue(target.username, message.credential.username);
    setNativeValue(target.password, message.credential.password);
    sendResponse({ ok: true });
    return false;
  });
  schedule();
}

function setNativeValue(input, value) {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  if (!setter) return;
  setter.call(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
  input.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
}
