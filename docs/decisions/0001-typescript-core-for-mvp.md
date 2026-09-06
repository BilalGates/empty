# ADR-0001: TypeScript core for the MVP; defer shared Rust core

- Status: accepted
- Date: 2026-09-05
- Owners: Architecture, Security and iOS

## Context

Space needs consistent protocol, cryptography and sync behavior in a Chrome extension,
backend tooling and native iOS app. A shared Rust library compiled to WASM and bridged
to Swift could reduce implementation divergence, but it also adds two foreign-function
boundaries, WASM packaging/CSP review, memory-copy/zeroization caveats, cross-compiling,
ABI ownership and a larger release matrix before product behavior exists.

The security objective is behavioral equivalence around standard primitives, not one
language at any cost. Native platform libraries and audited dependencies can implement
a small, normative protocol independently, with shared test vectors catching drift.

## Decision

For the MVP:

1. Use TypeScript for `packages/core`, `packages/protocol`, `packages/sync`, import
   logic and the Chrome extension integration.
2. Implement the iOS domain/protocol/crypto adapters natively in Swift.
3. Keep the API outside the plaintext and cryptographic domain; it consumes generated
   opaque wire contracts only.
4. Define cryptographic and serialization behavior in a language-neutral normative
   specification, with deterministic cross-platform vectors and invalid-input corpus.
5. Keep `crypto` behind a byte-oriented facade so a Rust implementation can replace
   it without changing product/domain APIs.

This ADR does not select algorithms. The security ADR/specification must select
standard primitives and maintained libraries after review.

## Consequences

Positive:

- Fastest path to a testable extension and sync engine with one toolchain.
- iOS uses native lifecycle, Keychain/LocalAuthentication and AuthenticationServices
  idioms without an early FFI layer.
- Protocol compatibility is explicit and independently testable rather than assumed
  from code reuse.
- Fewer build and supply-chain components in the first release.

Negative:

- Security-sensitive behavior exists in two implementations.
- TypeScript cannot guarantee memory zeroization and runs in a garbage-collected
  runtime; lock clears references on a best-effort basis, not as a hard guarantee.
- Every protocol/crypto change requires synchronized vectors and implementation
  review across TypeScript and Swift.

Mitigations:

- Keep crypto orchestration small and ban application-defined primitives.
- Require the crypto change gate, independent review, property tests and vectors.
- Prevent content scripts/UI from importing crypto or key-owning modules.
- Pin dependencies and record library/version decisions separately.

## Alternatives considered

### Shared Rust core immediately

Potentially strong type/memory properties and one implementation, but rejected for the
MVP because integration complexity and two platform bridges increase delivery and
review surface before equivalence benefits are demonstrated. WASM also does not make
browser memory secret from a compromised extension context.

### TypeScript everywhere, including a hybrid iOS app

Rejected. It weakens integration with native credential-provider lifecycle, platform
security facilities and future passkey APIs, while still not eliminating native code.

### Swift core ported to the extension

Rejected because Swift/WASM browser packaging and ecosystem maturity add risk without
clear MVP advantage.

## Revisit triggers

Re-evaluate a shared Rust core when at least one is true:

- cross-platform vector drift causes a release-blocking incident;
- passkey/PRF or migration logic grows beyond the narrow facades;
- measured crypto/import performance is inadequate;
- an audited Rust library materially improves a required primitive unavailable with
  equivalent assurance on both platforms;
- the team can own reproducible WASM and Swift bridge builds, fuzzing and release
  artifacts.

A migration proposal must prototype Chrome MV3 packaging and iOS static-library/FFI
integration, compare binary size and latency, define secret-memory behavior, keep old
formats readable and pass the full existing cross-platform vector corpus.

