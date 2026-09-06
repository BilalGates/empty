# Releases

A tag is a candidate, not proof of release readiness. The candidate is releasable only after every required gate succeeds on the exact tagged commit and the evidence is retained with the release record.

Required evidence:

1. `npm ci`, `npm run check`, `npm run security:secrets`, and `npm run security:permissions` pass from a clean checkout.
2. API migrations apply to an empty PostgreSQL database and to a sanitized copy of the previous release schema; rollback/forward-fix steps are rehearsed.
3. The API container builds from a committed lockfile, runs as a non-root user, becomes ready, and shuts down gracefully.
4. The Chrome extension builds into a deterministic ZIP whose SHA-256 is recorded. Permissions and manifest contents are reviewed before store submission.
5. The iOS Release configuration builds on the pinned macOS/Xcode runner with signing disabled in CI. Archive/sign/notarization remain controlled release actions.
6. Crypto/security and adversarial reviews have no unresolved blocking finding.

The release workflow validates candidates but deliberately does not publish, upload, sign, deploy, or submit artifacts. Those external actions require a separately authorized promotion step.
