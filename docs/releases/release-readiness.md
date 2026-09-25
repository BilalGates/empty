# Release readiness

Last reviewed: 2026-09-25
Decision: **NOT READY for production credentials**

## Verified locally

The 2026-09-24 development increment added deterministic CBOR, exact `vault-object` AAD encoders, an isolated per-object envelope reader/writer in TypeScript, and a matching bounded reader in Swift. Independent libsodium/HKDF bytes verify both AEAD purposes and framing. `npm run check`, secret/permission/migration gates, the macOS Xcode Release simulator build, and simulator tests pass. XcodeGen now preserves the app and provider entitlements, and the build gate checks them. This verifies isolated protocol components, not signed operations, production persistence/sync, or production AutoFill behavior.

The first typed V1 payload (`password`) now has strict decoders on both platforms and dispatch from authenticated object type. A shared corpus also fixes a conservative canonical origin grammar. The Swift password-object writer now matches the independent artifact vector byte for byte and uses fresh key/nonce material in its public path. The TypeScript gate passes 56 core/protocol tests plus 11 extension tests; the iOS simulator passes 53 tests. The iOS preview provider compares full origins for URL service identifiers and binds direct selected identities to saved records, while domain/app identifiers fail closed. Physical-device AutoFill behavior, other payload types, signed operations, and production persistence/sync remain unverified.

The numeric signed-operation header schema is now fixed and has a shared TypeScript/Swift byte vector, including SHA-256 of the exact framed object artifact. This is parser evidence only; signatures, device authorization, DAG application, checkpoints, and migration are not implemented in the reachable flow.

- Locked Node dependency graph with zero known `npm audit` vulnerabilities at high/critical threshold.
- Lint, TypeScript checks, unit tests, workspace builds, secret scan, permission audit, and migration ordering.
- PostgreSQL 17 migration on an empty database and idempotent rerun.
- Real API flows for authentication, disabled users, sync idempotency, conflicts, duplicate-item atomic rejection, pull, tombstones, and device revocation.
- Non-root API container build, readiness, and graceful runtime behavior.
- Loaded Manifest V3 Chromium fixtures for traditional, dynamic, SPA, signup/change guard, exact-origin rejection, encrypted local storage, key-only worker session restoration, local CSV import, CRUD tombstones, encrypted backup restore, lock-during-fill cancellation, unlocked-write latency, and fill.
- Deterministic Chrome ZIP generated twice with the same SHA-256.
- Every Swift source parses on Windows; the standalone iOS sync transport also passes Windows typecheck. CI generates the Xcode project and performs the macOS build gate.

## Production blockers

1. The Chrome preview still encrypts one canonical JSON vault. Isolated V1 per-object CBOR/HKDF/AEAD helpers exist in TypeScript and Swift, but neither product uses them; signed operations, device sequence/DAG, and authenticated checkpoint/rollback are not implemented.
2. Shared Argon2id, HKDF, XChaCha, object AAD, and object-envelope vectors now run in TypeScript and Swift for the implemented slice. Recovery encoding, PRF, device transfer, signatures, checkpoints, broader parser mutation, and resource-bound vectors remain required on every platform.
3. iOS still needs a real signed host-app bootstrap for the canonical vault identity/key, physical-device AutoFill and protected-data lock tests, and retained macOS archive evidence. Windows parsing is not an Apple SDK build.
4. Independent security/adversarial review must be repeated on the exact candidate commit after blockers 1–3 close.
5. Store accounts, signing identities, privacy disclosures, support URLs, deployment secrets, backup rehearsal and an authorized promotion are external release prerequisites.

No tag, ZIP, passing unit suite, or local demo overrides these blockers. See `docs/releases/README.md` for the evidence required on the exact tagged candidate.
