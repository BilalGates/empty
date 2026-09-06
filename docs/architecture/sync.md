# Synchronization protocol

## Goals and non-goals

The protocol synchronizes independently encrypted record versions across intermittent
clients, supports idempotent retries and exposes conflicts. It does not merge
plaintext, distribute a decrypted vault key, provide real-time collaboration or
guarantee recovery from a malicious server that permanently withholds all updates.

## Client state machine

```text
LOCKED
  -> AUTHENTICATED (service session; vault still encrypted)
  -> UNLOCKED
  -> PUSH_PENDING
  -> PULLING
  -> APPLYING (atomic local transaction)
  -> IDLE

Any network failure -> BACKOFF -> retry with same mutation IDs
Epoch/cursor violation -> RECOVERY_REQUIRED (no destructive local reset)
```

Service authentication may refresh while the vault remains locked because sync moves
opaque records. Creating or resolving records requires unlock.

## Push

`POST /v1/vaults/{vaultId}/sync/push`

```json
{
  "protocolVersion": 1,
  "vaultEpoch": 1,
  "knownSequence": 412,
  "mutations": ["OpaqueRecordVersion"],
  "batchId": "client-generated UUID"
}
```

The API validates session/device/vault membership, epoch, limits, IDs, ancestry shape
and exact idempotency replay. It does not validate plaintext or AEAD content. Within
one database transaction it:

1. returns the stored result for an identical replay;
2. rejects reuse of a mutation ID with different bytes;
3. inserts each immutable version and its parent links;
4. removes declared parent heads that are still heads and adds the new head;
5. appends one ordered change per accepted version;
6. commits the idempotency result.

The response includes each accepted/duplicate/rejected result, its allocated sequence,
the current server sequence and the complete current head IDs for touched records.
Validation failure of one mutation does not create an ambiguous partial result: the
MVP batch is atomic. Clients split an oversized batch before submission.

A stale `knownSequence` is not itself an error; it is expected after offline work. A
new version that does not descend from every current head creates or preserves a
conflict. The server never replaces all heads merely because a request arrived later.

## Pull

`GET /v1/vaults/{vaultId}/sync/pull?cursor={opaque}&limit={n}`

The first request may omit a cursor. A page returns:

```json
{
  "protocolVersion": 1,
  "vaultEpoch": 1,
  "fromExclusive": 412,
  "throughInclusive": 512,
  "changes": [{"sequence": 413, "version": "OpaqueRecordVersion"}],
  "nextCursor": "opaque-authenticated-cursor",
  "hasMore": true,
  "serverHeadCommitment": "base64url"
}
```

Pages are ordered by sequence and pinned to a stable `throughInclusive` for that pull
cycle so concurrent writes do not cause gaps. The client validates monotonic sequence,
epoch, duplicate equivalence, ciphertext digest and structural limits before applying
the page and cursor atomically. It decrypts only after structural acceptance; an AEAD
failure quarantines that record version and raises a non-secret integrity error.

The cursor is an opaque, server-authenticated encoding of vault, position, pull upper
bound and expiry. It is not a bearer authorization credential.

## Bootstrap and snapshots

A new/recovered device downloads an authenticated manifest of current record heads
plus all referenced versions needed to construct them. Large vaults may use an opaque
snapshot at sequence `S` followed by changes `> S`. The snapshot is generated from
ciphertext rows and includes a digest/commitment; the server never decrypts it.

The device verifies every record with AEAD after obtaining the vault key. Bootstrap is
not considered complete until the local replica and cursor commit atomically. A failed
bootstrap preserves any pre-existing replica.

## Conflict handling

Conflict exists when a record has more than one head. Pull returns every head/version;
the local UI labels the record conflicted. For a password conflict the user sees safe
field-level differences only after unlock, chooses/merges, and the client writes a new
version listing every conflict head as parents. Until that version is acknowledged,
all branches remain locally recoverable.

Concurrent deletion and edit is a conflict, not automatic deletion. Conflict decisions
are themselves normal encrypted versions and propagate to all devices.

## Retry and idempotency

- Mutation IDs are generated once when the local transaction is created and survive
  restarts.
- Network timeout after push retries identical bytes and batch ID.
- `429` and transient `5xx` honor `Retry-After` and exponential backoff with jitter.
- Authentication refresh rotates tokens; it does not regenerate mutation IDs.
- Permanent per-request validation errors quarantine the mutation for user/support
  action without logging its payload.

## Revocation

Revoking a device atomically revokes all its service sessions and prevents new sync
requests. Each authenticated request rechecks device status; long-lived authorization
caches have a short bounded lifetime. Other devices receive a device-lifecycle change
and may rotate vault-key envelopes according to security policy.

Revocation is prospective. It cannot retract keys or plaintext already present on a
lost device. Vault-key rotation plus re-encryption is the response when compromise is
suspected, and requires an explicit resumable migration plan.

## Rollback and malicious-server limits

Clients durably pin `vaultEpoch`, highest applied sequence and a commitment to the
observed head set. They reject lower epochs/sequences, inconsistent duplicate
sequences, invalid ancestry and failure to include known heads in a claimed snapshot.
Device-signed checkpoints or cross-device checkpoint comparison can strengthen this
later and must be designed by the security protocol.

These checks detect many rollback/equivocation attempts after a client has observed
newer state. A single client with no external trusted checkpoint cannot prove that a
malicious server has not withheld a newer update, and a brand-new device cannot detect
a self-consistent old snapshot solely from server data. Product claims must retain
this limitation.

## Compaction

The server may remove non-head history/tombstones only below the minimum durable
acknowledgement of all active devices and after the recovery retention window. A stale
device whose cursor predates retained history receives `SNAPSHOT_REQUIRED`, never an
empty success. Revoked devices do not block compaction after the retention window.

## Test obligations

- Create on A, pull on B; edit/delete propagation.
- Offline concurrent edits, edit-versus-delete and explicit merge.
- Timeout at every push transaction boundary followed by identical retry.
- Reused mutation ID with altered bytes is rejected.
- Pagination under concurrent writes has no gaps or duplicates with different bytes.
- Revoked sessions fail on push, pull and refresh.
- Rollback of sequence, epoch, cursor, heads or snapshot is rejected.
- Malformed/oversized graph, ciphertext and cursor inputs fail within bounded work.
- Cross-TypeScript/Swift fixtures produce identical wire bytes and accept the same
  valid/invalid corpus.

