# Local release-gate evidence — 2026-09-07

Candidate branch: `feat/space-foundation`  
Latest functional commit tested: `25f3705`

This is retained local evidence, not a production release approval.

## Passed

- Full `npm run check`: 27 Vitest tests, 11 extension unit tests, lint, TypeScript and all workspace builds.
- Chrome MV3 E2E: encrypted persistence, key-only session restoration, content-script isolation, lock-during-fill cancellation, local CSV import, CRUD/tombstone, backup reauthentication, failed-restore preservation, recovery-key restore, form variants, and exact-origin rejection.
- Unlocked Chrome add/edit operations are gated below five seconds; Argon2id remains on unlock and sensitive reauthentication.
- Secret and extension-permission gates pass with `activeTab`, `alarms`, `scripting`, and `storage` only.
- PostgreSQL 17 integration passes bootstrap binding, A→B, B→A, stale conflict, vault scoping, and revoked-device denial.
- API image builds as non-root user `space` with migrations before server startup.
- Shared Argon2id, HKDF-SHA-256, and XChaCha20-Poly1305 vectors pass under the independent Noble implementation. Every Swift file parses under Swift 6.3.3 on Windows.
- Current Chrome artifact was generated twice byte-identically:
  `875f6ec1eb0b27c8f051a0ceb36b6c8f8c70a164f2204a4254f2dbf2e00a5815  space-chrome.zip`.
- `npm audit --audit-level=high` reports zero vulnerabilities.

## Still blocked

- macOS/Xcode resolution and simulator build cannot run on this Windows host. GitHub CLI is authenticated and manual CI dispatch is configured, but publishing the local commits was denied by the environment pending explicit user authorization.
- Physical iPhone signing, protected-data/AutoFill testing, Apple Developer entitlements, and App Store installation require an Apple account, signing assets, and a device.
- The signed per-object deterministic-CBOR DAG/checkpoint protocol remains a production-credential blocker; the linear opaque backend and local preview vault must not be represented as the final zero-knowledge V1 protocol.

See `release-readiness.md` and the iOS/extension security review records for the remaining security evidence.
