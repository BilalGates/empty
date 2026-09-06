---
name: space-crypto-change-gate
description: Mandatory gate for any Space encryption, KDF, vault serialization, recovery, WebAuthn, unlock, or secret-storage change.
---

# Space crypto change gate

Before editing, read `docs/security/cryptographic-protocol.md`, `docs/security/threat-model.md`, and relevant ADRs. Use only reviewed library primitives. Preserve explicit format, algorithm, KDF, and envelope versions; bind context with canonical AAD; generate nonces and keys with a CSPRNG; never log secrets. Add or update deterministic vectors where meaningful, round-trip/negative/property tests, migration notes, threat-model impact, and recovery impact. Require independent security and adversarial review. A functional fix may not silently reduce KDF cost, authentication, integrity, or rollback detection.

