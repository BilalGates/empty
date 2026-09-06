import { describe, expect, it } from "vitest";
import { generateDeviceToken, hashDeviceToken } from "./auth.js";
describe("device credentials", () => {
  it("creates high-entropy bearer tokens", () => { const a=generateDeviceToken();const b=generateDeviceToken();expect(a).toMatch(/^space_dt_[A-Za-z0-9_-]{43}$/);expect(a).not.toBe(b); });
  it("binds hashes to the deployment pepper", () => { const token="space_dt_"+"a".repeat(43);expect(hashDeviceToken(token,"x".repeat(32))).toHaveLength(32);expect(hashDeviceToken(token,"x".repeat(32)).equals(hashDeviceToken(token,"y".repeat(32)))).toBe(false); });
});
