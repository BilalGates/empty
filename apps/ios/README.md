# Space for iOS

This directory is an XcodeGen source project for the SwiftUI host app and its AutoFill
Credential Provider extension. Generate `Space.xcodeproj` on macOS with:

```sh
brew install xcodegen
cd apps/ios
xcodegen generate
xcodebuild -project Space.xcodeproj -scheme Space \
  -destination 'platform=iOS Simulator,name=iPhone 16' test
```

The local cache format `space.ios.local-cache/1` is intentionally not the interoperable
`space.vault/1` protocol. It uses CryptoKit AES-GCM solely as a representative encrypted
App Group cache. `SpaceVaultPrimitiveSuite` now validates the normative Argon2id,
HKDF-SHA-256, and XChaCha20-Poly1305-IETF primitives against vectors, using the immutable
dependencies recorded in `DEPENDENCIES.md`. It remains disconnected from persistence
until deterministic CBOR/AAD, per-object envelopes, signatures, and checkpoints have
their complete shared vector corpus. Do not sync the local cache file or treat it as a
V1 wire artifact.

`SpaceSyncClient` now implements authenticated `/v1/session`, fail-closed
`/v1/bootstrap/bind`, and canonical
`/v1/vaults/{vaultId}/sync/{push,pull}` transport. Its device credential is stored by
`KeychainDeviceSessionStore` as a this-device-only Keychain item, and remote endpoints
must use HTTPS (debug builds permit loopback HTTP). The transport deliberately does not
feed remote records into the local AES-GCM cache: that remains blocked until the iOS
XChaCha20-Poly1305/Argon2id implementation passes the shared cross-platform vectors.

The host app supports local vault creation, biometric unlock, adding and deleting
logins, a concealed detail view, 60-second local-only clipboard copies, and immediate
refresh of AutoFill identities after a confirmed encrypted save. Moving the app out of
the foreground locks the model, dismisses secret-entry sheets, and covers the UI for the
app switcher.
Chrome CSV import uses the system file picker, rejects files above 5 MB, parses and
deduplicates entirely on-device, performs one confirmed encrypted save, and reminds the
user to delete the plaintext source file.

The host app supports local vault creation, biometric unlock, adding and deleting
logins, a concealed detail view, 60-second local-only clipboard copies, and immediate
refresh of AutoFill identities after a confirmed encrypted save. Moving the app out of
the foreground locks the model, dismisses secret-entry sheets, and covers the UI for the
app switcher.

The checked-in project descriptor uses development bundle identifiers but no team or signing material. Follow `docs/operations/ios-signing.md` before device testing or distribution.
