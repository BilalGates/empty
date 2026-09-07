# Backend security review

Scope: API authentication, device lifecycle, opaque vault persistence, incremental synchronization, deployment and operational logging.

## Trust boundaries and invariants

- The API never accepts an unlock password, derives a vault key or decrypts an envelope. Device service authentication is deliberately independent from client-side vault unlock.
- A device token is generated with 256 bits of randomness. PostgreSQL stores only `HMAC-SHA-256(pepper, token)` and a 128-bit lookup fingerprint; the full digest is compared with a timing-safe primitive.
- All sync records are append-only versions. A tombstone is represented only by a fully null encrypted envelope. The database owns a monotonically increasing per-vault revision.
- Push locks the vault row, verifies every base item version before writing any record, and commits the entire batch or none of it. A version mismatch returns an explicit conflict without overwriting the head.
- Mutation receipts bind each mutation UUID to a SHA-256 payload digest and the original response. A UUID replay with different content is rejected.

## Review checklist

- Authorization is scoped from the authenticated device to its single user and vault; client-supplied user/vault identifiers are never trusted.
- Revocation is rechecked on sync operations and before issuing another device credential.
- Helmet headers, body limits and per-IP rate limits are enabled. Coolify must be the only ingress because the application trusts one proxy hop.
- Structured request logging excludes headers and bodies; operational code must never add envelope fields, bearer tokens, or secrets to log context.
- PostgreSQL is isolated on an internal network and production connections require verified TLS when they leave the compose-local network.

## Integration review items

Before release, run typecheck/tests against PostgreSQL and confirm: disabled users cannot authenticate; duplicate item IDs in one push are rejected as a validation error; all `/v1` responses send `Cache-Control: no-store`; error serialization redacts parser `err.body`; and device revocation plus its audit event are committed atomically. These items require adversarial verification in addition to the normal security review.

The network API must not issue a new device token from an ordinary bearer session. Administrative provisioning plus authenticated vault-identity binding is the temporary safe boundary. Remote enrollment remains blocked on a step-up, replay-safe, signed/SAS ceremony covered by the crypto change gate.
