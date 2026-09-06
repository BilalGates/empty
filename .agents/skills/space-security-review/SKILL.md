---
name: space-security-review
description: Review Space changes for trust-boundary, secret-handling, authentication, authorization, logging, and dependency regressions before integration or release.
---

# Space security review

Read `docs/security/threat-model.md` and the changed trust-boundary documentation. Trace attacker-controlled input to storage, logs, crypto, and UI. Verify authorization at the data operation, not only the route. Search for plaintext persistence and complete tokens. Check replay, rollback, origin confusion, lifecycle, cleanup, rate limits, and error leakage. Run the relevant tests and security scripts. Record actionable findings by severity; do not approve with unresolved Critical or High findings.

