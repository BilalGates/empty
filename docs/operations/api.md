# Space API operations

The API stores only opaque encrypted envelopes and their synchronization metadata. Unlocking and key derivation stay on the client. Device bearer tokens authenticate the service session but never unlock a vault.

## Deployment

Set `POSTGRES_PASSWORD` and an independently generated `DEVICE_TOKEN_PEPPER` of at least 32 random characters in the Coolify secret store. Never bake either into an image or commit an `.env` file. Terminate TLS at Coolify's proxy and do not expose PostgreSQL publicly. The API listens on port 3000; route health checks to `/health/ready`.

Run `docker compose up -d --build`. Startup takes an advisory migration lock and applies ordered SQL migrations before accepting traffic. Deploy one migration-compatible API version at a time.

For initial provisioning, create a user and vault with UUIDs in an administrative SQL session, then run `USER_ID=... VAULT_ID=... DEVICE_LABEL=... npm run device:create` inside the API container. The command prints the device token exactly once. Transfer it over an authenticated channel and clear terminal capture/history if applicable.

## Monitoring and incident response

- `/health/live` proves the process is serving; `/health/ready` additionally checks PostgreSQL.
- Logs contain request IDs, routes, status and operational errors. Request bodies, authorization headers, ciphertext, nonces, wrapped keys and tokens are redacted by design.
- Revoke a suspected device immediately with `DELETE /v1/devices/:deviceId` from another active device. Every authenticated operation rechecks revocation; rotation means creating a new credential and revoking the old one.
- Rotate the token pepper only with a coordinated device re-enrollment plan: changing it invalidates every current device token.

## Backups and restore

Back up PostgreSQL using encrypted, access-controlled storage. A logical backup contains ciphertext and metadata, not vault plaintext, but it remains sensitive. Keep backup credentials outside the database and test restores regularly in an isolated environment.

Example backup: `pg_dump --format=custom --no-owner --dbname="$DATABASE_URL" --file=space.dump`. Restore into an empty database with `pg_restore --clean --if-exists --no-owner`. After restore, verify the migration table, `/health/ready`, incremental pull from a known cursor, and device revocation. Never inspect or log envelope columns during validation.

Retention and deletion must cover primary data, replicas, snapshots and backup expiry. PostgreSQL point-in-time recovery is recommended; record and rehearse the selected RPO/RTO before production launch.
