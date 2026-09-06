# Release remediation

Status: blocked by local execution helper; release remains not ready.

## High findings to close

1. API authentication must join `users` and reject `disabled_at IS NOT NULL` for already-issued device tokens.
2. Sync push must reject duplicate item IDs before any transaction effect.
3. Logger redaction must cover nested `err.body` and `error.body` with a sentinel regression test.
4. Migrations must remove the `000_bootstrap` shortcut that marks `001` applied without running it; verify empty and upgraded databases.
5. iOS must use the authenticated canonical vault UUID, not a placeholder, for namespace and AAD.
6. App and provider must share the explicit Team-ID-prefixed Keychain access group without fallback.
7. iOS must reject non-regular or oversized envelope files before reading, then recheck size after reading for TOCTOU.

## Required medium fixes

- Connect the Chrome popup to the rejection-sampling generator and remove modulo-based generation.
- Set `Cache-Control: no-store` on sensitive API success and error responses.
- Omit undefined PostgreSQL SSL configuration under strict TypeScript.
- Align iOS plaintext and envelope size limits and remove the LocalAuthentication compatibility shim.
- Correct release scripts from `apps/chrome` to `apps/extension` and generate the Xcode project before using `Space.xcodeproj`.

## Resume gate

After filesystem execution is restored: initialize Git on `feat/space-foundation`, install and lock dependencies, run `npm run check`, security scripts, PostgreSQL integration tests, deterministic extension packaging, Docker build/health, loaded Chrome E2E, and macOS iOS build. Re-run independent Security and QA reviews. No real secrets may be stored before all High findings are closed and evidence is recorded.

