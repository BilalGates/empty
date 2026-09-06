# Release readiness

Last reviewed: 2026-09-06  
Decision: **NOT READY for production credentials**

## Verified locally

- Locked Node dependency graph with zero known `npm audit` vulnerabilities at high/critical threshold.
- Lint, TypeScript checks, unit tests, workspace builds, secret scan, permission audit, and migration ordering.
- PostgreSQL 17 migration on an empty database and idempotent rerun.
- Real API flows for authentication, disabled users, sync idempotency, conflicts, duplicate-item atomic rejection, pull, tombstones, and device revocation.
- Non-root API container build, readiness, and graceful runtime behavior.
- Loaded Manifest V3 Chromium fixtures for traditional, dynamic, SPA, signup/change guard, exact-origin rejection, encrypted local storage, memory-only worker session restoration, local CSV import, lock/unlock, add, and fill.
- Deterministic Chrome ZIP generated twice with the same SHA-256.
- Every Swift source parses on Windows; the standalone iOS sync transport also passes Windows typecheck. CI generates the Xcode project and performs the macOS build gate.

## Production blockers

1. The Chrome preview encrypts one canonical JSON vault. It does not yet implement the normative `space.vault/1` per-object deterministic-CBOR, HKDF-separated keys, signed operations, device sequence/DAG, or authenticated checkpoint/rollback design.
2. Only the Argon2id reference vector is versioned. The protocol requires shared positive and negative vectors for HKDF, CBOR/AAD, envelopes, recovery encoding, PRF, device transfer, signatures, checkpoints, parser mutation and resource bounds, exercised by every platform.
3. iOS still needs a real signed host-app bootstrap for the canonical vault identity/key, physical-device AutoFill and protected-data lock tests, and retained macOS archive evidence. Windows parsing is not an Apple SDK build.
4. Independent security/adversarial review must be repeated on the exact candidate commit after blockers 1–3 close.
5. Store accounts, signing identities, privacy disclosures, support URLs, deployment secrets, backup rehearsal and an authorized promotion are external release prerequisites.

No tag, ZIP, passing unit suite, or local demo overrides these blockers. See `docs/releases/README.md` for the evidence required on the exact tagged candidate.
