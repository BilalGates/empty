---
name: space-ios-credential-provider
description: Implement or review Space iOS app and AutoFill Credential Provider changes using supported AuthenticationServices, Keychain, and LocalAuthentication APIs.
---

# Space iOS credential provider

Consult current Apple AuthenticationServices documentation before API changes. Keep the app and extension in an App Group with least-entitlement access. Store only wrapped keys and required metadata in Keychain; gate biometric key release with LocalAuthentication. Provide password identities to the system store without secret values. Never access Apple Passwords private storage. Verify locked, cancelled-biometric, revoked-device, offline, and extension-memory-pressure flows. Document signing or device-only verification that cannot run locally.

