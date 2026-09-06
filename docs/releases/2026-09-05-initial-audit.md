# Initial release audit — 2026-09-05

Status: **not ready**.

## Blocking items

- Shell execution was unavailable during construction, so no clean-checkout install, typecheck, test, migration, Docker, Chrome or Xcode gate has produced evidence.
- The API Dockerfile uses `npm install` without a committed lockfile in its build context. The resulting dependency graph is not reproducible.
- `000_bootstrap.sql` duplicates the product schema and marks `001_initial` as applied. Replace both with one canonical baseline or a bookkeeping-only `000` plus canonical `001`; verify an empty database and upgrade fixture.
- Backend security/adversarial findings remain open: disabled-user authorization, duplicate-item batch validation, parser-body log redaction, no-store headers, conditional PostgreSQL SSL configuration and atomic revocation auditing.
- Extension and iOS paths/schemes in release scripts must be checked against the final repository layout.
- Version consistency between the root package, API, Chrome manifest and iOS marketing/build versions is not yet proven.

Do not create or promote a production release until these items are closed and the release-candidate workflow succeeds on the tagged commit.
