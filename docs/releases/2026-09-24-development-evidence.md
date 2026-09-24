# Development evidence — 2026-09-24

Branch: `feat/space-foundation`, uncommitted development increment. This is not a release approval.

## Passed locally

- `npm run check`: lint, TypeScript, 50 Vitest tests, 11 extension tests, and all workspace builds.
- `npm run security:secrets`, `npm run security:permissions`, `node scripts/check-migrations.mjs`, and `git diff --check`.
- `npm test --workspace @space/protocol`: 19 tests, including deterministic CBOR rejection and three shared AAD vectors at integer-width boundaries.
- Swift AAD encoder matched all three JSON vectors in a standalone macOS executable.
- `bash scripts/ios-build-gate.sh`: Xcode 26.6 Release simulator build passed after XcodeGen generated both Info.plists and the required app/provider entitlements. The gate now asserts the entitlement values.
- `xcodebuild ... test` on iPhone 17 Pro, iOS 26.5 simulator: Xcode result bundle reported 43 passed, zero failed, zero skipped.
- The per-object envelope increment added a versioned frame, random DEK/nonces, HKDF-separated vault wrap key, and separate XChaCha AEAD contexts. An independent Python-stdlib/libsodium fixture matches TypeScript framing/ciphertext and Swift decryption. TypeScript rejects every single-byte fixture mutation, seven altered routing fields, wrong VRK, and the first byte above the 1 MiB ciphertext limit. Swift opens the same fixture, rejects every-byte mutations and malformed framing, checks trusted AAD, and validates authenticated deterministic CBOR. The simulator result now reports 43 passed, zero failed or skipped.
- Independent security and adversarial reviews found no remaining Critical or High issue in this increment. They identified an unsafe negative-integer CBOR edge case and a payload-allocation/cleanup limit; both were fixed and retested.

## Still required

- The V1 object envelope remains isolated: TypeScript writes and reads it, while Swift reads, decrypts, and validates canonical CBOR. Key slots, type-specific payload validation, Swift writing, operation signatures, DAG/checkpoint, parser fuzzing, migration, and complete cross-platform vectors remain open; Chrome/iOS persistence and sync do not use these helpers.
- A signed physical-device run is still needed for actual Keychain/App Group/AutoFill entitlements, biometric cancellation, protected-data lock, and memory-pressure behavior. Unsigned simulator builds cannot establish those properties.
- The provider filter's shared predicate is tested, but controller wiring and direct identity requests need device-level integration tests. A prior design uses host matching for iOS service identifiers and must be reviewed against actual AutoFill semantics before release.
- This branch has no production promotion, store signing, or final candidate security approval. The decision remains **not ready for real credentials**.
