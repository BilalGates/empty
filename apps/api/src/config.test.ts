import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
describe("configuration",()=>{
 it("rejects a weak device-token pepper",()=>expect(()=>loadConfig({DATABASE_URL:"postgres://test",DEVICE_TOKEN_PEPPER:"short"})).toThrow());
 it("accepts an isolated test configuration",()=>expect(loadConfig({NODE_ENV:"test",DATABASE_URL:"postgres://test",DEVICE_TOKEN_PEPPER:"p".repeat(32)}).PORT).toBe(3000));
});
