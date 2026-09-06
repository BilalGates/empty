import { describe, expect, it } from "vitest";
import { createLogger } from "./logger.js";
import { pushSchema } from "./sync.js";

const mutation = (mutationId: string, itemId: string) => ({
  mutationId,
  itemId,
  baseItemVersion: 0,
  ciphertext: "opaque",
  nonce: "opaque",
  wrappedKey: "opaque",
  aad: null
});

describe("security regressions", () => {
  it("rejects repeated item ids before a sync transaction", () => {
    const itemId = "3b9c11fe-5d77-4a47-8e12-872ffcaf1050";
    const parsed = pushSchema.safeParse({ mutations: [
      mutation("729f5f98-b82d-4a11-849f-1ece2d0057a4", itemId),
      mutation("8e935999-ace2-433f-b725-f570b8a4ad1a", itemId)
    ] });
    expect(parsed.success).toBe(false);
  });

  it("redacts nested error bodies", () => {
    let output = "";
    const sentinel = ["sentinel", "do", "not", "log"].join("-");
    const logger = createLogger("info", { write: (message: string) => { output += message; } });
    logger.error({ err: { body: { password: sentinel } } }, "failed");
    expect(output).not.toContain(sentinel);
    expect(output).toContain("[REDACTED]");
  });
});
