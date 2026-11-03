const ids = (value) => typeof value === "string" && value.length > 0 && value.length <= 128;
const origin = (value) => typeof value === "string" && value.length <= 2048;

export function isMessage(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  switch (value.type) {
    case "EMPTY_CREATE_VAULT":
    case "EMPTY_UNLOCK":
      return typeof value.password === "string" && value.password.length >= 12 && value.password.length <= 1024;
    case "EMPTY_LOCK":
      return true;
    case "EMPTY_ADD_CREDENTIAL":
      return Number.isSafeInteger(value.tabId) && value.tabId >= 0 && origin(value.origin) &&
        typeof value.title === "string" && value.title.length >= 1 && value.title.length <= 256 &&
        typeof value.username === "string" && value.username.length <= 1024 &&
        typeof value.password === "string" && value.password.length >= 1 && value.password.length <= 4096;
    case "EMPTY_UPDATE_CREDENTIAL":
      return Number.isSafeInteger(value.tabId) && value.tabId >= 0 && origin(value.origin) && ids(value.credentialId) &&
        typeof value.title === "string" && value.title.length >= 1 && value.title.length <= 256 &&
        typeof value.website === "string" && value.website.length >= 1 && value.website.length <= 2048 &&
        typeof value.username === "string" && value.username.length <= 1024 &&
        typeof value.password === "string" && value.password.length >= 1 && value.password.length <= 4096;
    case "EMPTY_DELETE_CREDENTIAL":
      return Number.isSafeInteger(value.tabId) && value.tabId >= 0 && origin(value.origin) && ids(value.credentialId);
    case "EMPTY_EXPORT_BACKUP":
      return Number.isSafeInteger(value.tabId) && value.tabId >= 0 && origin(value.origin) &&
        typeof value.password === "string" && value.password.length >= 12 && value.password.length <= 1024;
    case "EMPTY_RESTORE_BACKUP":
      return Number.isSafeInteger(value.tabId) && value.tabId >= 0 && origin(value.origin) &&
        ["password", "recovery-key"].includes(value.method) &&
        typeof value.secret === "string" && value.secret.length >= 1 && value.secret.length <= 1024 &&
        typeof value.content === "string" && value.content.length >= 1 && value.content.length <= 20_000_000 &&
        typeof value.replaceConfirmed === "boolean";
    case "EMPTY_GET_STATE":
    case "EMPTY_SCAN":
      return Number.isSafeInteger(value.tabId) && value.tabId >= 0 && origin(value.origin);
    case "EMPTY_FILL":
      return Number.isSafeInteger(value.tabId) && value.tabId >= 0 && ids(value.credentialId) && origin(value.origin);
    case "EMPTY_GET_SECRET":
      return Number.isSafeInteger(value.tabId) && value.tabId >= 0 && ids(value.credentialId) && origin(value.origin);
    case "EMPTY_PREVIEW_IMPORT":
      return Number.isSafeInteger(value.tabId) && value.tabId >= 0 && origin(value.origin) &&
        typeof value.csv === "string" && value.csv.length >= 1 && value.csv.length <= 5_000_000;
    case "EMPTY_COMMIT_IMPORT":
      return Number.isSafeInteger(value.tabId) && value.tabId >= 0 && origin(value.origin) && ids(value.token);
    case "EMPTY_FILL_GENERATED":
      return Number.isSafeInteger(value.tabId) && value.tabId >= 0 && origin(value.origin) &&
        typeof value.password === "string" && value.password.length >= 12 && value.password.length <= 256;
    case "EMPTY_CONTENT_SCAN":
      return true;
    case "EMPTY_CONTENT_FILL":
      return ids(value.requestId) && origin(value.origin) && value.credential &&
        typeof value.credential.username === "string" && value.credential.username.length <= 1024 &&
        typeof value.credential.password === "string" && value.credential.password.length <= 4096;
    default:
      return false;
  }
}
