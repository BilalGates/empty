import { pino } from "pino";
export function createLogger(level: string) {
  return pino({
    level,
    redact: {
      paths: [
        "req.headers.authorization", "req.headers.cookie", "req.body", "res.body",
        "err.body", "error.body", "token", "secret", "ciphertext", "nonce", "wrappedKey"
      ],
      censor: "[REDACTED]"
    },
    base: null,
    timestamp: pino.stdTimeFunctions.isoTime
  });
}
