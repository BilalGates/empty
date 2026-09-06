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
App Group cache while the project selects and audits an iOS XChaCha20-Poly1305 dependency
and lands the shared CBOR/vector corpus. Do not sync this cache file or treat it as a V1
wire artifact.

The checked-in project descriptor uses development bundle identifiers but no team or signing material. Follow `docs/operations/ios-signing.md` before device testing or distribution.
