import { isAutofillAllowed, normalizeOrigin } from "./origin.js";
import { generatePassword } from "./generator.js";

const status = document.querySelector("#status");
const content = document.querySelector("#content");
const originLabel = document.querySelector("#origin");
const generator = document.querySelector("#generator");
const generated = document.querySelector("#generated");
const regenerate = document.querySelector("#regenerate");
const fillGenerated = document.querySelector("#fill-generated");
let context = null;
let generatedPassword = "";

function regeneratePassword() {
  generatedPassword = generatePassword();
  generated.textContent = "•".repeat(generatedPassword.length);
}

function notice(title, body, { focus = false, urgent = false } = {}) {
  content.replaceChildren();
  const box = document.createElement("div");
  box.className = "notice";
  box.setAttribute("role", urgent ? "alert" : "status");
  const heading = document.createElement("h2");
  heading.textContent = title;
  const copy = document.createElement("p");
  copy.textContent = body;
  box.append(heading, copy);
  content.append(box);
  if (focus) {
    heading.tabIndex = -1;
    heading.focus();
  }
}

function showResponse(response) {
  status.hidden = true;
  content.hidden = false;
  if (!response?.ok || response.state === "blocked") {
    notice("Space is unavailable here", "For safety, filling works only on secure web pages you explicitly open.");
    generator.hidden = true;
    return;
  }
  if (response.form?.kind === "signup" || response.form?.kind === "password-change") {
    notice("Review before filling", "Space does not automatically fill new or changed passwords.");
  } else if (response.state === "locked") {
    notice("Space is locked", "Unlock Space in the app, then reopen this panel.");
  } else if (response.state === "empty") {
    notice("No login for this site", "Create one in Space, then return here to fill it.");
  } else {
    content.replaceChildren();
    for (const credential of response.credentials) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "credential";
      button.dataset.credentialId = credential.id;
      const label = document.createElement("span");
      label.textContent = credential.label || "Login";
      const username = document.createElement("small");
      username.textContent = credential.username;
      button.append(label, username);
      button.addEventListener("click", () => fill(credential.id));
      content.append(button);
    }
  }
}

async function fill(credentialId) {
  const button = content.querySelector(`[data-credential-id="${CSS.escape(credentialId)}"]`);
  if (button) button.disabled = true;
  const response = await chrome.runtime.sendMessage({ type: "SPACE_FILL", tabId: context.tabId, origin: context.origin, credentialId });
  if (response?.ok) window.close();
  else notice("Could not fill", response?.error === "confirmation-required" ? "Review this form and fill it manually." : "The page changed. Reopen Space and try again.", { focus: true, urgent: true });
}

regenerate.addEventListener("click", regeneratePassword);
fillGenerated.addEventListener("click", async () => {
  fillGenerated.disabled = true;
  const response = await chrome.runtime.sendMessage({ type: "SPACE_FILL_GENERATED", tabId: context.tabId, origin: context.origin, password: generatedPassword });
  if (response?.ok) window.close();
  else {
    fillGenerated.disabled = false;
    notice("Could not fill", response?.error === "confirmation-required" ? "Generated passwords require confirmation on this form." : "No eligible login form was found.", { focus: true, urgent: true });
  }
});

const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
const origin = tab?.url ? normalizeOrigin(tab.url) : null;
if (!tab?.id || !origin || !isAutofillAllowed(origin)) {
  showResponse({ ok: false, state: "blocked" });
} else {
  context = { tabId: tab.id, origin };
  originLabel.textContent = new URL(origin).hostname;
  regeneratePassword();
  showResponse(await chrome.runtime.sendMessage({ type: "SPACE_GET_STATE", ...context }));
}
