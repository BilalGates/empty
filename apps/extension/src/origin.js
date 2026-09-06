export function normalizeOrigin(value) {
  if (typeof value !== "string" || value.length > 2048) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    if (url.username || url.password) return null;
    return url.origin.toLowerCase();
  } catch {
    return null;
  }
}

export function isAutofillAllowed(value) {
  const origin = normalizeOrigin(value);
  if (!origin) return false;
  const url = new URL(origin);
  return url.protocol === "https:" || url.hostname === "localhost" || url.hostname === "127.0.0.1";
}

export function originsMatch(left, right) {
  const a = normalizeOrigin(left);
  const b = normalizeOrigin(right);
  return a !== null && a === b;
}
