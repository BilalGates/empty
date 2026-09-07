# Space Chrome extension

Manifest V3 implementation for a local encrypted preview vault and explicit, origin-bound credential filling. It has no host permissions: opening the toolbar popup grants `activeTab`, after which the service worker injects the bundled content script into the top frame only.

## Security boundaries

- Exact normalized origins are compared immediately before listing and filling; subdomains, lookalikes, scheme changes, and non-default ports do not match.
- Filling is limited to HTTPS, plus localhost/127.0.0.1 for development.
- The content script never receives a vault or credential list. A fill message contains only the selected username/password and a bounded request id.
- Only the encrypted vault container is written to persistent `chrome.storage.local`. The unlocked session retains the random vault key—not the master password—in Chrome's memory-only `storage.session`, restricted to trusted extension contexts. It expires after five minutes of inactivity and is cleared on manual lock, browser restart, extension reload, update, or disable. Argon2 runs on unlock and sensitive reauthentication, not on every edit.
- Signup and password-change forms require a separate confirmation flow and are not filled automatically. Iframes are not injected.
- Runtime messages use a small validated allowlist. Extension-page requests are accepted only from this extension; page reports must come from a Chrome tab.
- The build bundles local source only. There is no remote code, analytics, or externally loaded asset.

The popup creates a vault, displays its recovery key once, unlocks, adds origin-scoped credentials, searches only non-secret metadata, copies on explicit action, reveals at most one password for 15 seconds, locks manually, and fills only a selected exact-origin credential. The current encrypted JSON container is a preview format, not the normative CBOR per-object `space.vault/1` protocol; do not use it for real credentials until the cross-platform vector gate is closed.

Chrome CSV import is parsed locally, reviewed before commit, and never written to
persistent storage as plaintext. Credentials can be edited or tombstoned from global
search. Encrypted backups require master-password reauthentication and download without
adding the broad `downloads` permission. A backup can be restored only after local
authenticated decryption with its master password or recovery key succeeds and
current-vault replacement is confirmed; plaintext
CSV export is intentionally disabled.

## Build and test

From this directory:

```sh
npm install
npm run check
```

Load `apps/extension/dist` with **Load unpacked** on `chrome://extensions`. The unit tests cover strict protocol validation, exact origin matching, and form classification. Manual/automated browser scenarios live in `tests/fixtures/chrome`.

## QA checklist

1. Serve the fixture directory from `http://localhost` and load each page.
2. Confirm traditional, SPA, and dynamically inserted login forms are detected without page errors.
3. Confirm signup/password-change pages display the review state and are not filled.
4. Confirm username and password writes dispatch bubbling `input` and `change` events.
5. Confirm the iframe child is untouched and a lookalike hostname never receives an offered credential.
6. Exercise popup states: loading, blocked, locked, empty, populated, failure, and long labels/usernames; use keyboard-only navigation and 200% zoom.
7. Inspect the packed manifest: only `activeTab`, `scripting`, and ciphertext-only `storage` permissions should be present.
