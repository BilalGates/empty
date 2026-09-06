# iOS signing and device verification

Status: scaffolding; signing and device verification are release blockers.

## Required Apple configuration

The development identifiers in `apps/ios/project.yml` must be registered to the selected team. An Apple Developer Account
Holder or Admin must create and consistently configure:

1. An explicit App ID for the host app (`com.space`).
2. An explicit App ID for the credential provider (`com.space.credential-provider`).
3. App Group `group.com.space.shared`, assigned only to those two App IDs.
4. Keychain Sharing group `$(AppIdentifierPrefix)com.space.shared`, assigned only to
   those two App IDs. The team prefix is not interchangeable with the Team ID for older
   accounts; inspect the generated provisioning profiles.
5. The AutoFill Credential Provider capability on both targets.
6. Development and distribution profiles regenerated after capabilities are enabled.

Set `DEVELOPMENT_TEAM` locally or in an untracked `.xcconfig`; do not commit certificates,
private keys, provisioning profiles, API keys, or signing passwords. Confirm the generated
entitlements with `codesign -d --entitlements :- <artifact>` rather than trusting Xcode's UI.

## Generate and validate on macOS

```sh
cd apps/ios
xcodegen generate
xcodebuild -project Space.xcodeproj -scheme Space \
  -destination 'platform=iOS Simulator,name=iPhone 16' test
xcodebuild -project Space.xcodeproj -scheme Space \
  -destination 'generic/platform=iOS' archive
```

Simulator tests exercise format and policy logic, but do not establish the security
properties of Keychain access control, biometric invalidation, extension launch, or
AutoFill identity suggestions. Those require a signed build on a passcode-protected device.

## Mandatory physical-device matrix

- Enable Space in **Settings > General > AutoFill & Passwords** and verify suggested
  identities include service, username, and opaque record ID but never the password.
- Locked: tapping a suggestion must return `userInteractionRequired`; it must never return
  an empty or cached plaintext credential.
- Face ID/Touch ID success: release only the selected credential.
- User cancellation and system cancellation: close without retry loops or alternate error
  oracles; no credential is returned.
- Enroll/remove biometrics after provisioning: `.biometryCurrentSet` must invalidate the
  local key. Space fails closed and requires the future master-password/recovery bootstrap;
  it must not recreate a key over an existing encrypted cache.
- Remove the device from the account: after authenticated sync marks it revoked, delete the
  local Keychain item and encrypted replica. Server revocation alone cannot erase a key the
  device already possessed; suspected extraction requires VRK rotation per the protocol.
- Offline: serve only the last valid local encrypted replica and make staleness visible in
  the host app once sync UI exists. Never reduce Argon2 cost inside the extension.
- Memory pressure/background: drop plaintext arrays and lock the host app. Inspect memory
  and crash diagnostics to confirm passwords, keys, request bodies, and ciphertext are not
  logged.
- With App Group or Keychain entitlement deliberately mismatched, both targets must fail
  closed and display a setup error; they must not fall back to an unshared container.
- Reboot-before-first-unlock and locked-device launches must respect
  `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`.

## Security limitations and release blockers

- `space.ios.local-cache/1` is local scaffolding, not the normative `space.vault/1`
  XChaCha20-Poly1305/CBOR format. Production sync is blocked until Security approves a
  maintained XChaCha implementation, deterministic CBOR, and the common positive/negative
  vector corpus. Do not substitute AES-GCM for V1 without a new versioned suite and ADR.
The locally generated vault identity must be bound to authenticated account bootstrap before multiple accounts are supported. It is public context, not a key, but an unauthenticated local identity does not prove server-side account or vault ownership.
- Master-password Argon2id, recovery, device transfer, signed sync/checkpoints, imports, and
  revocation transport are not implemented by this scaffold. Biometric unlock is not a
  recovery mechanism.
- Swift's `Data`, `String`, Codable, SwiftUI, and UIKit make copies that cannot be reliably
  zeroized. The implementation clears owned collections best-effort; endpoint compromise
  while unlocked remains outside the threat-model guarantee.
- App Store/TestFlight delivery is blocked pending independent Security and adversarial
  review, real-device results for the matrix above, privacy manifest/reason-API audit,
  accessibility QA, and `npm run security:secrets` plus `npm run security:permissions` at
  repository release gate.

References: Apple's public documentation for
[credential provider extensions](https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller),
[credential identity storage](https://developer.apple.com/documentation/authenticationservices/ascredentialidentitystore),
[Keychain access control](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility),
and [LocalAuthentication](https://developer.apple.com/documentation/localauthentication/lacontext).
