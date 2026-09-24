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

- The V1 object envelope remains isolated: TypeScript writes and reads it, while Swift reads, decrypts, and validates canonical CBOR. Key slots, payload schemas beyond `password`, Swift writing, operation signatures, DAG/checkpoint, parser fuzzing, migration, and complete cross-platform vectors remain open; Chrome/iOS persistence and sync do not use these helpers.

## Password payload increment

- The first V1 typed payload (`password`) has exact integer-keyed CBOR fields, size/type/time bounds, and a shared vector used by TypeScript and Swift tests. Both typed open wrappers require `object_type=password` in the caller's trusted AAD before accepting the payload.
- `npm run check` passed with 54 core/protocol tests and 11 extension tests. The iPhone 17 Pro / iOS 26.5 simulator result bundle reported 46 passed, zero failed or skipped. Secret, permission, and migration gates passed.
- Independent security and adversarial review found no remaining Critical, High, or Medium issue in these isolated helpers. Origin semantic validation, other object schemas, Swift writer, persistence/sync integration, and physical-device AutoFill remain open.

## Canonical password origin increment

- TypeScript and Swift reject unsafe or noncanonical V1 wire origins using the same positive/negative JSON corpus. V1 deliberately rejects Unicode IDN, `xn--` A-labels, and IPv6 until a shared reviewed rule exists; neither decoder repairs paths, ports, or host case.
- `npm run check` passed with 56 core/protocol tests and 11 extension tests. The iPhone 17 Pro / iOS 26.5 simulator result bundle reported 48 passed, zero failed or skipped. The iOS Release build and secret/permission/migration gates passed.
- Independent security and adversarial reviews found no Critical/High/Medium issue in the isolated validators after tightening IDN and DNS suffix handling. The current iOS provider preview compares only hosts; V1 remains disconnected until an exact requested/saved-origin check is implemented and tested at the AutoFill boundary.
- A signed physical-device run is still needed for actual Keychain/App Group/AutoFill entitlements, biometric cancellation, protected-data lock, and memory-pressure behavior. Unsigned simulator builds cannot establish those properties.
- The provider filter's shared predicate is tested, but controller wiring and direct identity requests need device-level integration tests. A prior design uses host matching for iOS service identifiers and must be reviewed against actual AutoFill semantics before release.
- This branch has no production promotion, store signing, or final candidate security approval. The decision remains **not ready for real credentials**.
