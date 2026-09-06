# Foundation execution plan

Status: active

## Outcome

A reproducible security-first MVP slice: versioned encrypted vault core, imports and generator, incremental conflict-aware sync, PostgreSQL API, usable Manifest V3 shell, native iOS/AutoFill skeleton, CI, operations, and release audit.

## Milestones

1. Establish architecture, threat model, ADRs, Skills, and repository gates.
2. Implement protocol/core with negative and compatibility tests.
3. Implement sync model and API with migrations and lifecycle tests.
4. Integrate minimal extension vault flows and autofill boundary.
5. Add iOS app/provider architecture and testable shared fixtures.
6. Run adversarial review, fix release-blocking findings, and publish an honest RC report.

## Explicit external blockers

App Store and Chrome Web Store publication, Apple signing/team entitlements, production domain/TLS, and production WebAuthn relying-party configuration require owner accounts or credentials. They do not block local artifacts and documentation.

