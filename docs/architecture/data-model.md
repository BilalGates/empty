# Data model

Space has two related models: the encrypted logical vault owned by clients and the
minimal operational model stored by the service.

## Client logical model

All fields below, including item kind and display metadata, are encrypted as one
record payload. The outer opaque-record identifiers and version ancestry are sync
metadata.

```text
VaultRecord
  schemaVersion
  recordId
  kind: credential | group | vault_settings
  createdAt, updatedAt
  body

CredentialBody
  credentialKind: password | passkey | totp | secure_item
  title
  origins[]
  username?
  secret                     kind-specific encrypted object
  groupId?                   null means ungrouped
  notes?
  favorite?
  customFields[]             deferred in UI, reserved in schema

GroupBody
  name
  sortKey?
```

Groups are intentionally one level deep in V1. Deleting a group does not delete its
credentials: a client migration writes affected credentials with `groupId = null`
and then tombstones the group. Search is client-side over the unlocked replica.

`origins` store parsed, normalized matching descriptors rather than arbitrary string
comparison. Web descriptors distinguish scheme, ASCII host and effective port. App
association descriptors are separate typed variants. Display URLs remain encrypted
user data and are not treated as matching authority.

Passwords, TOTP seeds, recovery codes, passkey private material and notes never appear
in an index persisted without encryption. A client may maintain an encrypted search
index regenerated from the source records.

## Server relational model

Suggested PostgreSQL tables (names are non-normative; constraints are normative):

### Identity and access

- `accounts(id, created_at, status)`
- `auth_credentials(id, account_id, kind, public_data, sign_count, created_at,
  revoked_at)` — WebAuthn public keys and server authentication metadata only.
- `devices(id, account_id, display_name, public_key, created_at, last_seen_at,
  revoked_at)`
- `sessions(id, account_id, device_id, token_hash, expires_at, rotated_from,
  revoked_at)` — only a keyed/token hash is stored, never the bearer token.
- `vaults(id, account_id, epoch, next_sequence, created_at)`
- `vault_devices(vault_id, device_id, role, joined_at, revoked_at,
  acknowledged_sequence)`

Account ownership is V1's authorization model. `role` leaves room for future sharing
but sharing semantics are explicitly out of scope.

### Opaque sync state

- `record_versions(vault_id, record_id, version_id, format_version, key_version,
  mutation, nonce, ciphertext, ciphertext_digest, author_device_id,
  client_mutation_id, created_sequence, received_at)`
- `version_parents(vault_id, version_id, parent_version_id)`
- `record_heads(vault_id, record_id, version_id)` — one or more rows during conflict.
- `change_log(vault_id, sequence, record_id, version_id, operation)`
- `idempotency_keys(vault_id, device_id, client_mutation_id, request_digest,
  response_sequence, expires_at)`
- `sync_snapshots(id, vault_id, through_sequence, object_ref, digest, created_at)`

Required uniqueness includes `(vault_id, version_id)`, `(vault_id, device_id,
client_mutation_id)` and `(vault_id, sequence)`. Every foreign key includes `vault_id`
where possible to prevent cross-vault reference mistakes. Database row-level
security may add defense in depth, but application authorization remains mandatory.

Ciphertext and nonce have hard size bounds. A parent must belong to the same record.
A batch append allocates sequences, inserts versions/parents/change rows, advances
heads and stores idempotency results in one transaction.

### Operations

- `audit_events(id, account_id, device_id?, event_type, outcome, occurred_at,
  request_id, network_fingerprint?)`
- `rate_limit_state` only if the selected limiter requires durable state; otherwise a
  dedicated external limiter is preferred.

Audit payloads use an allowlist. They must not include record IDs where avoidable,
URLs, usernames, ciphertext, request bodies, credential descriptors, raw IP addresses
without an approved retention purpose, or token material.

## Local replica

Each client persists:

- opaque versions and their head graph;
- an encrypted materialized current view;
- pending client mutations with stable IDs;
- server cursor/high-water sequence and vault epoch;
- device/session metadata stored separately from vault-unlock material;
- encrypted envelopes and format metadata;
- conflict state, including all unresolved heads.

The transaction that applies a pull page also advances the durable cursor. Likewise,
creating a local edit and enqueueing its mutation are atomic. Plaintext caches are
memory-only, bounded by lock TTL and cleared on lock/background/security events as far
as the platform permits.

## Version graph and conflicts

Each version names zero or more parents. A normal edit has one parent; creation has
none; a resolved merge names all heads it supersedes. Concurrent versions remain
multiple heads. A server accepts a syntactically valid branch even if it is based on
an older head, then reports the resulting conflict. This preserves offline work and
prevents last-write-wins data loss.

Clients may auto-merge only non-secret, independently changed fields when the merge
policy is proven deterministic. Concurrent password/TOTP/passkey/recovery-code edits
require explicit user choice and retain both originals until the resolution syncs.

## Retention and deletion

A tombstone is an encrypted record version whose outer `mutation` is `delete`. It is
retained until every non-revoked device has acknowledged a later sequence plus the
configured recovery window. Devices absent beyond the retention policy must perform a
new snapshot bootstrap; they cannot rely on an expired cursor.

Account deletion and cryptographic erasure policies belong to operations/security
documentation. Database backups contain ciphertext and operational metadata; they
must preserve sequence consistency and remain encrypted at the infrastructure layer.

