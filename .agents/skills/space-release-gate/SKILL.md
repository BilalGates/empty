---
name: space-release-gate
description: Produce and audit a reproducible Space release candidate across core, API, Chrome extension, database migrations, and iOS artifacts.
---

# Space release gate

Read `docs/releases/release-readiness.md`. Use a clean dependency install and run lint, typecheck, unit/integration/crypto tests, builds, secret scan, permission audit, and dependency audit. Verify migrations both forward and rollback-safe, Docker health, extension unpacked/package behavior, version alignment, changelog, backup/restore, and known limitations. Classify audit findings and stop the candidate for unresolved Critical/High issues. Never claim App Store or Chrome Web Store publication without the external signing and submission evidence.

