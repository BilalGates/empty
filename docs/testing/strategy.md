# Testing strategy

Protocol/core tests cover canonical encoding, crypto round trips, authentication failures, AAD substitution, key rewrap, Unicode compatibility, URL matching, password generation, and hostile CSV parsing. Sync tests cover idempotency, pagination, concurrent edits, conflicts, and tombstones. API tests cover migrations, authorization, revocation, replay, rate limits, and secret-safe logs against PostgreSQL.

Chrome QA loads the packaged extension against traditional, SPA, dynamic, signup, and password-change fixtures. iOS QA covers Keychain/vault state and locked, biometric-cancelled, offline, and provider flows on macOS CI and a physical device.

Ciphertext, nonce, revision, vault id, and envelope substitution must fail closed. Fuzz targets cover CSV, protocol decoding, base64url, and encrypted-object parsing. Multi-device tests must demonstrate create/sync, offline conflict, deletion, revocation, password rewrap, and recovery.

Windows can run Node, API, and extension tests. iOS compilation requires macOS CI; biometrics and the provider lifecycle ultimately require signing and a physical iPhone.

