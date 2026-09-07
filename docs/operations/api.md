# Space API operations

The API stores only opaque encrypted envelopes and their synchronization metadata. Unlocking and key derivation stay on the client. Device bearer tokens authenticate the service session but never unlock a vault.

## Deployment

Set `POSTGRES_PASSWORD` and an independently generated `DEVICE_TOKEN_PEPPER` of at least 32 random characters in the Coolify secret store. Never bake either into an image or commit an `.env` file. Terminate TLS at Coolify's proxy and do not expose PostgreSQL publicly. The API listens on port 3000; route health checks to `/health/ready`.

The bundled Compose PostgreSQL is isolated on its internal Docker network and therefore sets `DATABASE_SSL_MODE=disable`. Any managed or externally routed PostgreSQL deployment must set `DATABASE_SSL_MODE=require` and present a certificate trusted by the container.

Run `docker compose up -d --build`. Startup takes an advisory migration lock and applies ordered SQL migrations before accepting traffic. Deploy one migration-compatible API version at a time.

For initial provisioning, create a user and vault with UUIDs in an administrative SQL session, then run `USER_ID=... VAULT_ID=... DEVICE_LABEL=... npm run device:create` inside the API container. The command prints the device token exactly once. Transfer it over an authenticated channel and clear terminal capture/history if applicable.

## Implemented API contract

All `/v1` responses use `Cache-Control: no-store` and require a device bearer token except health endpoints. `GET /v1/bootstrap` returns the authenticated public account, vault and device identifiers plus the current server revision. A client that already has an expected canonical vault identity should call `POST /v1/bootstrap/bind` with `{ "expectedVaultId": "..." }`; a mismatch fails with `409` and does not rewrite local or server identity.

Canonical synchronization routes are `POST /v1/vaults/{vaultId}/sync/push` and `GET /v1/vaults/{vaultId}/sync/pull`. The path vault must equal the vault bound to the authenticated device. `/v1/sync/*` remains a deprecated compatibility alias and returns a successor `Link` header.

Remote device enrollment is intentionally unavailable. A bearer session alone is not sufficient step-up authorization to mint another device credential. Until the signed/SAS approval ceremony is implemented and independently reviewed, provision each device with the administrative `device:create` command, then use `/v1/bootstrap/bind`. This binds service identity only: it never transfers, wraps or validates a vault key.

The current API is a linear `baseItemVersion` synchronization slice. It preserves opaque immutable versions, atomic batches, idempotent mutation receipts and explicit stale-write conflicts, but it is not the target signed DAG/multi-head protocol described in `docs/architecture/sync.md`. Do not use it for real vault data or claim malicious-server rollback/fork resistance.

## Monitoring and incident response

- `/health/live` proves the process is serving; `/health/ready` additionally checks PostgreSQL.
- Logs contain request IDs, routes, status and operational errors. Request bodies, authorization headers, ciphertext, nonces, wrapped keys and tokens are redacted by design.
- Revoke a suspected device immediately with `DELETE /v1/devices/:deviceId` from another active device. Every authenticated operation rechecks revocation; rotation means creating a new credential and revoking the old one.
- Rotate the token pepper only with a coordinated device re-enrollment plan: changing it invalidates every current device token.

## Backups and restore

Back up PostgreSQL using encrypted, access-controlled storage. A logical backup contains ciphertext and metadata, not vault plaintext, but it remains sensitive. Keep backup credentials outside the database and test restores regularly in an isolated environment.

Example backup: `pg_dump --format=custom --no-owner --dbname="$DATABASE_URL" --file=space.dump`. Restore into an empty database with `pg_restore --clean --if-exists --no-owner`. After restore, verify the migration table, `/health/ready`, incremental pull from a known cursor, and device revocation. Never inspect or log envelope columns during validation.

Retention and deletion must cover primary data, replicas, snapshots and backup expiry. PostgreSQL point-in-time recovery is recommended; record and rehearse the selected RPO/RTO before production launch.
