# System architecture

## Context and trust boundaries

```text
visited page (hostile)
  <-> content script (exposed adapter)
  <-> extension trusted context (policy + unlocked session)
  <-> local encrypted replica
  <-> TLS
  <-> API (opaque records only)
  <-> PostgreSQL (opaque records only)

iOS UI / AutoFill provider
  <-> shared app-group encrypted replica
  <-> Keychain-protected unlock material
  <-> TLS <-> same API
```

The browser page, network and server are not trusted with vault plaintext. The
extension service worker is trusted for policy but is ephemeral; it must reconstruct
state from encrypted storage and require unlock again when no valid unlock session
exists. A content script is treated as an exposed adapter even though it belongs to
the extension.

The iOS host app and credential-provider extension share only the minimum encrypted
database and coordination state through an App Group. Key-encryption material is held
using platform security facilities and released only after the configured user-
presence policy. The provider must operate within extension time and memory limits;
it consumes a prepared searchable index whose sensitive values remain encrypted at
rest.

## Components

### `apps/extension`

- Manifest V3 service worker owns sessions, sync, origin matching and release of one
  selected credential.
- Content scripts discover fields and request actions using typed messages. They do
  not receive search results beyond display-safe choices or secret fields before an
  explicit fill/copy action.
- Extension pages render popup/settings/unlock UI and communicate through the same
  policy boundary.
- Executable JavaScript and WASM are packaged with the extension; no remote code is
  loaded. Chrome documents both the service-worker model and the prohibition on
  remotely hosted executable code: [Manifest V3 overview](https://developer.chrome.com/docs/extensions/develop/migrate/what-is-mv3) and [remote hosted code guidance](https://developer.chrome.com/docs/extensions/develop/migrate/remote-hosted-code).

### `apps/ios`

- SwiftUI host app manages the vault, groups, imports, device/recovery settings and
  foreground synchronization.
- An AutoFill Credential Provider Extension supplies identities and credentials via
  public AuthenticationServices APIs. Space never reads Apple Passwords' private
  storage. See Apple's [AuthenticationServices documentation](https://developer.apple.com/documentation/authenticationservices).
- Keychain and LocalAuthentication protect a locally wrapped unlock key; biometrics
  authorize its use and do not replace the master-password key hierarchy. See Apple's
  [Keychain Services documentation](https://developer.apple.com/documentation/security/keychain-services).

### `apps/api`

- Account authentication, passkey/WebAuthn challenges, sessions and rate limits.
- Device registration, listing and revocation.
- Authorization and atomic append of opaque record versions.
- Incremental change feed, snapshots and acknowledgement watermarks.
- Secret-free operational audit events, health/readiness and migration state.

It has no decrypt endpoint, crypto key store or dependency on decrypted credential
schemas. WebAuthn behavior follows the current W3C specification rather than a
vendor-specific flow: [Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/).

### Client packages

- `protocol`: strict schemas, compatibility windows and deterministic codecs.
- `crypto`: audited primitives behind `seal/open/wrap/unwrap`; cryptographic choices
  are owned by the security spec and change gate.
- `core`: credential and group rules over plaintext values that exist only in an
  unlocked process.
- `sync`: durable state machine over encrypted records; cannot inspect plaintext.
- `import`: bounded parsers. Plaintext import never leaves the client and is not
  written to logs or temporary server storage.

## Authentication and unlock

Service authentication answers “may this account/device call the sync API?” Vault
unlock answers “can this local user obtain the vault key?” These flows have different
credentials and lifetimes.

The preferred service login is a passkey/WebAuthn credential. A service session token
authorizes API access but cannot decrypt the vault. The master password is processed
locally by the client KDF and is never sent to the API. Recovery and hardware-assisted
unlock add independently versioned envelopes around the random vault key; they do not
change the ciphertext item format.

## Data flow: fill one credential

1. The content script reports the top-frame origin, frame origin and field hints.
2. The trusted extension context independently reads the tab/frame origin and rejects
   mismatches, opaque origins and lookalike-origin substitutions.
3. It searches the unlocked local index using normalized origins.
4. The user selects a credential unless a narrowly defined policy permits suggestion.
5. The trusted context returns one short-lived fill response to the requesting frame.
6. The content script writes only requested fields and clears its references.

Passwords are not sent in discovery messages, telemetry or HTML attributes. A page
can always observe values filled into its own fields; Space does not claim otherwise.

## Availability and degradation

- Offline: unlocked clients read/write locally and enqueue mutations.
- API unavailable: exponential backoff with jitter; user edits remain durable.
- Conflicts: both versions remain accessible until explicit merge/selection.
- No biometric availability: fall back to master-password unlock, subject to policy.
- No WebAuthn PRF capability: hardware key may authenticate the account but is not
  silently treated as a vault-unlock factor.
- AutoFill provider cannot refresh: serve the last valid encrypted local replica and
  surface staleness in the host app.

## Evolution rules

Wire, ciphertext, KDF and envelope versions are distinct integers. Readers support a
documented compatibility window. Writers emit only the active version. A migration
must be resumable and must preserve the old envelope/ciphertext until the new one is
verified. Changes to crypto, recovery, serialization or unlock require the crypto
change gate and an ADR when they alter interoperability.

