const ids = (value) => typeof value === "string" && value.length > 0 && value.length <= 128;
const origin = (value) => typeof value === "string" && value.length <= 2048;

export function isMessage(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  switch (value.type) {
    case "SPACE_GET_STATE":
    case "SPACE_SCAN":
      return Number.isSafeInteger(value.tabId) && value.tabId >= 0 && origin(value.origin);
    case "SPACE_FILL":
      return Number.isSafeInteger(value.tabId) && value.tabId >= 0 && ids(value.credentialId) && origin(value.origin);
    case "SPACE_FILL_GENERATED":
      return Number.isSafeInteger(value.tabId) && value.tabId >= 0 && origin(value.origin) &&
        typeof value.password === "string" && value.password.length >= 12 && value.password.length <= 256;
    case "SPACE_CONTENT_SCAN":
      return true;
    case "SPACE_CONTENT_FILL":
      return ids(value.requestId) && origin(value.origin) && value.credential &&
        typeof value.credential.username === "string" && value.credential.username.length <= 1024 &&
        typeof value.credential.password === "string" && value.credential.password.length <= 4096;
    default:
      return false;
  }
}
