# Space architecture

Status: baseline for MVP implementation  
Last updated: 2026-09-05

Space is a zero-knowledge, offline-capable password manager. The service authenticates
accounts and synchronizes opaque encrypted records; it never needs plaintext vault
content or a key capable of decrypting it.

This document is the architectural map. Normative detail lives in:

- [System architecture](docs/architecture/system.md)
- [Module boundaries and contracts](docs/architecture/contracts.md)
- [Data model](docs/architecture/data-model.md)
- [Synchronization protocol](docs/architecture/sync.md)
- [ADR-0001: TypeScript core for the MVP](docs/decisions/0001-typescript-core-for-mvp.md)

Security documents define cryptographic algorithms, key hierarchy, recovery and the
threat model. If they conflict with this overview, the security documents govern
cryptographic behavior and an ADR must reconcile the discrepancy.

## Architectural drivers

1. A compromised API or complete database export must not reveal vault plaintext.
2. Extension and iPhone remain usable offline after a successful local unlock.
3. Synchronization must detect concurrent edits and must never silently discard a
   newer secret.
4. Authentication to the service and cryptographic vault unlock are separate systems.
5. Chrome content scripts receive only the item selected for a single action, never
   the vault or vault key.
6. Passwords ship first, while the data model can add passkeys, TOTP and secure items
   without changing the sync protocol.

## Proposed monorepo

```text
apps/
  api/                    HTTP authentication, sync and device lifecycle
  extension/              Chrome Manifest V3 extension
  ios/                    SwiftUI app + AutoFill credential provider
packages/
  core/                   TypeScript domain logic; no UI or platform APIs
  protocol/               versioned wire schemas/codecs and compatibility fixtures
  crypto/                 narrow cryptographic facade; no product/domain policy
  sync/                   client state machine, retries and conflict representation
  import/                 local-only import parsers and normalization
  ui/                     web design tokens and accessible primitives
  test-fixtures/           non-secret fixtures and cross-platform vectors
infra/
  docker/                 production images and local composition
  migrations/             PostgreSQL schema migrations
docs/                     product, architecture, security and operations truth
```

Dependencies point inward: apps may depend on packages; `core` depends only on
`protocol` types and injected crypto/time/random interfaces; `protocol` depends on no
application package. The API does not depend on client crypto or decrypted domain
models. iOS implements the normative protocol in Swift and proves compatibility with
the same fixtures.

## System invariants

- All secret-bearing item fields are encrypted before crossing an application trust
  boundary or being persisted outside protected client storage.
- Every ciphertext is bound with authenticated associated data to its vault, record,
  record kind and format version. Exact encoding belongs to the cryptographic spec.
- Server-side mutations are authenticated, authorized to an active device and
  idempotent.
- Record versions are immutable. The server retains concurrent heads until a client
  explicitly resolves them.
- Deletes are tombstones and synchronize like other versions.
- Cursors are opaque and monotonically advance within one vault epoch. Clients reject
  a response that moves behind their durable high-water mark.
- Revocation blocks future API access but cannot erase plaintext or keys already
  obtained by a formerly trusted device.
- Logs, metrics and audit events contain identifiers and result codes, not secrets,
  ciphertext bodies, tokens, usernames, URLs, notes or TOTP material.
- No content script, visited page or remote script can call the crypto package
  directly.

## MVP deployment

The backend is a stateless API behind TLS and a reverse proxy, plus PostgreSQL. One
deployment may serve many accounts, but every query is scoped by the authenticated
account and vault. Extension and iOS clients keep a local encrypted replica and sync
incrementally. Background jobs may compact acknowledged history and expire sessions;
they cannot decrypt data.

The first release deliberately uses a TypeScript core for web-facing code and native
Swift implementations on iOS, joined by a normative protocol and cross-platform test
vectors. Rust/WASM and a Rust-to-Swift bridge remain a gated future migration, not an
MVP dependency.

