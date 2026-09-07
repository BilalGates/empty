# iOS crypto change-gate record

Status: primitive scaffold accepted; production activation blocked.

## Scope and trust-boundary delta

`SpaceVaultPrimitiveSuite` adds fixed-parameter Argon2id, HKDF-SHA-256, and XChaCha20-Poly1305-IETF to `SpaceShared`. It does not read or write the local cache, define AAD, serialize a vault record, or run from the app or AutoFill extension. The AES-GCM local preview remains unchanged and must not be uploaded as `space.vault/1`.

The native-code surface is limited to pinned SwiftPM revisions of the PHC Argon2 reference implementation and swift-sodium's bundled libsodium. Exact provenance and binary hashes are recorded in `apps/ios/DEPENDENCIES.md`.

## Evidence completed

- Argon2id is fixed at 64 MiB, three iterations, four lanes, a 16-byte salt, and 32-byte output. Inputs are NFC-normalized and bounded before KDF work.
- HKDF labels are fixed and key, vault-ID, and slot-ID sizes fail closed.
- XChaCha requires a 32-byte key, 24-byte nonce, bounded plaintext/AAD, and maps every authentication failure to one non-secret external error.
- The common corpus in `/test-vectors` is executed independently by Noble in TypeScript and by the Swift tests. Ciphertext/AAD mutation and malformed-size tests fail closed.
- Mutable secret buffers are wiped on best effort; no logs, analytics, or persistence contain password or key material.
- Adversarial review found redirect replay and premature runtime-integration risks. Redirects are now rejected by a retained URLSession delegate; runtime integration stays blocked.

## Mandatory evidence still open

Do not connect this suite to persistence, backup, recovery, sync, or AutoFill until all of the following are attached to a release candidate:

1. deterministic CBOR and exact AAD vectors shared by Swift and TypeScript;
2. per-record DEK wrapping, tombstone, Ed25519 operation, ancestry, merge, and checkpoint positive/negative vectors;
3. clean macOS Xcode resolution proving the pinned revisions and committed `Package.resolved`, plus local verification of the signed swift-sodium tag;
4. Swift unit results on simulator and physical passcode-protected iPhone, including memory-pressure, background-lock, AutoFill, and malformed corpus runs;
5. independent security approval of the complete reachable workflow, not only the primitive facade.

No production-security claim is authorized while this record remains blocked.
