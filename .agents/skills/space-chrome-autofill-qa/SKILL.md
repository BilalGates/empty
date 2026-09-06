---
name: space-chrome-autofill-qa
description: Validate Space Chrome autofill, form detection, origin matching, permissions, and content-script isolation against real fixture pages.
---

# Space Chrome autofill QA

Build the packaged Manifest V3 extension and test traditional, SPA, dynamic, signup, password-change, iframe, and multi-account fixtures. Verify exact normalized-origin matching, user confirmation where required, no lookalike fill, correct `input`/`change` events, keyboard access, and no page breakage. Confirm the content script receives only the selected credential, unlocked material expires, no remote code is used, and manifest permissions remain minimal. Run unit tests and the permissions checker; record browser version and failures.

