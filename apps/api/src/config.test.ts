import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
describe("configuration",()=>{
 it("rejects a weak device-token pepper",()=>expect(()=>loadConfig({DATABASE_URL:"postgres://test",DEVICE_TOKEN_PEPPER:"short"})).toThrow());
 it("accepts an isolated test configuration",()=>expect(loadConfig({NODE_ENV:"test",DATABASE_URL:"postgres://test",DEVICE_TOKEN_PEPPER:"p".repeat(32)}).PORT).toBe(3000));
 it("requires PostgreSQL TLS by default",()=>expect(loadConfig({DATABASE_URL:"postgres://test",DEVICE_TOKEN_PEPPER:"p".repeat(32)}).DATABASE_SSL_MODE).toBe("require"));
 it("rejects an unknown PostgreSQL TLS policy",()=>expect(()=>loadConfig({DATABASE_URL:"postgres://test",DATABASE_SSL_MODE:"prefer",DEVICE_TOKEN_PEPPER:"p".repeat(32)})).toThrow());
});
