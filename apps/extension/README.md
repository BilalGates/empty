# Space Chrome extension

Manifest V3 shell for explicit, origin-bound credential filling. It intentionally has no host permissions: opening the toolbar popup grants `activeTab`, after which the service worker injects the bundled content script into the top frame only.

## Security boundaries

- Exact normalized origins are compared immediately before listing and filling; subdomains, lookalikes, scheme changes, and non-default ports do not match.
- Filling is limited to HTTPS, plus localhost/127.0.0.1 for development.
- The content script never receives a vault or credential list. A fill message contains only the selected username/password and a bounded request id.
- Secrets are not written to Chrome storage, logs, HTML attributes, or page datasets. The background session is memory-only, expires after 60 seconds of inactivity, and is cleared when the worker suspends.
- Signup and password-change forms require a separate confirmation flow and are not filled automatically. Iframes are not injected.
- Runtime messages use a small validated allowlist. Extension-page requests are accepted only from this extension; page reports must come from a Chrome tab.
- The build bundles local source only. There is no remote code, analytics, or externally loaded asset.

The current shell deliberately starts locked. A future native/core bridge may establish the in-memory session, but must pass only origin-scoped records and must use the repository crypto-change gate before adding any secret transport or storage.

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
7. Inspect the packed manifest: only `activeTab` and `scripting` permissions should be present.
