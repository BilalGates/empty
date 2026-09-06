import { pino } from "pino";
import type { DestinationStream, LoggerOptions } from "pino";

export const REDACT_PATHS = [
  "req.headers.authorization", "req.headers.cookie", "req.body", "res.body",
  "err.body", "error.body", "token", "secret", "ciphertext", "nonce", "wrappedKey"
] as const;

export function createLogger(level: string, destination?: DestinationStream) {
  const options: LoggerOptions = {
    level,
    redact: {
      paths: [...REDACT_PATHS],
      censor: "[REDACTED]"
    },
    base: null,
    timestamp: pino.stdTimeFunctions.isoTime
  };
  return destination ? pino(options, destination) : pino(options);
}
