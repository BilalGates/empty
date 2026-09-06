const USER_HINT = /(?:user|email|login|identifier|account)/i;
const CURRENT_HINT = /(?:current|old)/i;
const NEW_HINT = /(?:new|confirm|repeat|signup|register)/i;

export function classifyFields(fields) {
  const visible = fields.filter((field) => !field.disabled && !field.readOnly && field.visible !== false);
  const passwords = visible.filter((field) => field.type === "password");
  const usernames = visible.filter((field) =>
    field.type === "email" || field.autocomplete === "username" || USER_HINT.test(field.hint || "")
  );
  const hasNewPassword = passwords.some((field) =>
    field.autocomplete === "new-password" || NEW_HINT.test(field.hint || "")
  );
  const hasCurrentPassword = passwords.some((field) =>
    field.autocomplete === "current-password" || CURRENT_HINT.test(field.hint || "")
  );
  const kind = hasNewPassword ? (hasCurrentPassword ? "password-change" : "signup") : passwords.length ? "login" : "none";
  return { kind, usernameCount: usernames.length, passwordCount: passwords.length };
}

function visible(element) {
  const style = getComputedStyle(element);
  return !element.disabled && !element.readOnly && style.display !== "none" && style.visibility !== "hidden" && element.getClientRects().length > 0;
}

function hint(element) {
  const label = element.labels ? [...element.labels].map((item) => item.textContent || "").join(" ") : "";
  return [element.name, element.id, element.placeholder, element.getAttribute("aria-label"), label].filter(Boolean).join(" ");
}

export function detectDocument(documentRef = document) {
  const inputs = [...documentRef.querySelectorAll("input")];
  const model = inputs.map((input) => ({
    type: (input.type || "text").toLowerCase(),
    autocomplete: (input.autocomplete || "").toLowerCase(),
    hint: hint(input),
    disabled: input.disabled,
    readOnly: input.readOnly,
    visible: visible(input)
  }));
  return { ...classifyFields(model), fields: inputs };
}

export function chooseFillTargets(documentRef = document) {
  const detected = detectDocument(documentRef);
  if (detected.kind === "signup" || detected.kind === "password-change") return { ...detected, username: null, password: null };
  const candidates = detected.fields.filter(visible);
  const password = candidates.find((input) => input.type === "password" && input.autocomplete !== "new-password") || null;
  const username = candidates.find((input) => input.type === "email" || input.autocomplete === "username" || USER_HINT.test(hint(input))) || null;
  return { ...detected, username, password };
}
