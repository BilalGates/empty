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

function inputField(labelText, type, name, options = {}) {
  const label = document.createElement("label");
  label.textContent = labelText;
  const input = document.createElement("input");
  input.type = type;
  input.name = name;
  input.required = options.required ?? true;
  if (options.value) input.value = options.value;
  input.autocomplete = options.autocomplete ?? "off";
  label.append(input);
  return { label, input };
}

async function refresh() {
  showResponse(await chrome.runtime.sendMessage({ type: "SPACE_GET_STATE", ...context }));
}

function vaultAccess(hasVault) {
  content.replaceChildren();
  const heading = document.createElement("h2");
  heading.textContent = hasVault ? "Unlock Space" : "Create your vault";
  const form = document.createElement("form");
  const password = inputField("Master password", "password", "master-password", { autocomplete: hasVault ? "current-password" : "new-password" });
  form.append(password.label);
  let confirmation;
  if (!hasVault) {
    confirmation = inputField("Confirm master password", "password", "confirm-password", { autocomplete: "new-password" });
    form.append(confirmation.label);
  }
  const submit = document.createElement("button");
  submit.type = "submit";
  submit.textContent = hasVault ? "Unlock" : "Create vault";
  const error = document.createElement("p");
  error.className = "form-error";
  error.setAttribute("role", "alert");
  form.append(submit, error);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.textContent = "";
    if (confirmation && password.input.value !== confirmation.input.value) { error.textContent = "Passwords do not match."; return; }
    submit.disabled = true;
    submit.textContent = hasVault ? "Unlocking…" : "Creating…";
    const response = await chrome.runtime.sendMessage({ type: hasVault ? "SPACE_UNLOCK" : "SPACE_CREATE_VAULT", password: password.input.value });
    password.input.value = "";
    if (confirmation) confirmation.input.value = "";
    if (!response?.ok) { error.textContent = hasVault ? "The master password is incorrect." : "The vault could not be created."; submit.disabled = false; submit.textContent = hasVault ? "Unlock" : "Create vault"; return; }
    if (response.recoveryKey) {
      content.replaceChildren();
      const title = document.createElement("h2"); title.textContent = "Save your recovery key";
      const warning = document.createElement("p"); warning.textContent = "This is the only time Space will show it. Store it offline.";
      const key = document.createElement("code"); key.className = "recovery-key"; key.textContent = response.recoveryKey;
      const done = document.createElement("button"); done.type = "button"; done.textContent = "I saved it"; done.addEventListener("click", refresh);
      content.append(title, warning, key, done);
    } else await refresh();
  });
  content.append(heading, form);
  password.input.focus();
}

function appendVaultActions() {
  const details = document.createElement("details");
  const summary = document.createElement("summary"); summary.textContent = "Add login for this site";
  const form = document.createElement("form");
  const title = inputField("Name", "text", "title", { value: new URL(context.origin).hostname, autocomplete: "off" });
  const username = inputField("Username or email", "text", "username", { required: false, autocomplete: "username" });
  const password = inputField("Password", "password", "password", { autocomplete: "new-password" });
  const submit = document.createElement("button"); submit.type = "submit"; submit.textContent = "Save login";
  const error = document.createElement("p"); error.className = "form-error"; error.setAttribute("role", "alert");
  form.append(title.label, username.label, password.label, submit, error);
  form.addEventListener("submit", async (event) => {
    event.preventDefault(); submit.disabled = true; error.textContent = "";
    const response = await chrome.runtime.sendMessage({ type: "SPACE_ADD_CREDENTIAL", ...context, title: title.input.value, username: username.input.value, password: password.input.value });
    password.input.value = "";
    if (response?.ok) await refresh(); else { submit.disabled = false; error.textContent = response?.error === "locked" ? "Space locked. Unlock it again." : "The login could not be saved."; }
  });
  details.append(summary, form);
  const lock = document.createElement("button"); lock.type = "button"; lock.className = "text-button"; lock.textContent = "Lock Space";
  lock.addEventListener("click", async () => { await chrome.runtime.sendMessage({ type: "SPACE_LOCK" }); await refresh(); });
  content.append(details, lock);
}

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
    generator.hidden = true;
    vaultAccess(response.hasVault);
    return;
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
  generator.hidden = false;
  appendVaultActions();
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
