# Module boundaries and contracts

## Dependency rules

| Module | May know | Must not know |
| --- | --- | --- |
| `protocol` | wire versions and validation | UI, storage engines, plaintext policy |
| `crypto` | byte inputs, algorithms, envelope formats | credentials, URLs, HTTP, UI |
| `core` | plaintext domain rules while unlocked | PostgreSQL, Chrome/Apple APIs |
| `sync` | opaque record versions and local sync state | plaintext fields or vault key |
| API | accounts, devices, opaque versions, cursors | master password, vault key, item schema |
| content script | field hints and one authorized fill payload | vault/index, keys, sync/session token |
| iOS provider | minimal local query/unlock contract | account administration, imports |

CI should enforce these boundaries with workspace dependency constraints. A platform
adapter translates native events into contracts; domain packages do not import
platform globals.

## Contract conventions

- External API prefix: `/v1`; media type includes `application/json` for MVP.
- Binary fields use unpadded base64url and declare an explicit maximum decoded size.
- IDs are client-generated random UUIDs and are never derived from secret material.
- Timestamps are RFC 3339 UTC for display/audit only; ordering uses server sequence and
  version ancestry, never wall-clock time.
- Unknown fields are ignored only where the schema marks them extensible. Unknown
  enum variants fail closed.
- Every request has a bounded body, a request ID and a client-generated idempotency
  key for mutations.
- Errors are stable `{code, requestId, retryable, details?}` objects and never echo
  submitted secrets or ciphertext.

Normative schemas should be generated from one version-controlled specification and
validated at every trust boundary. Generated TypeScript and Swift types do not make
input trusted.

## Opaque record contract

```ts
type OpaqueRecordVersion = {
  vaultId: string;
  recordId: string;
  versionId: string;
  parentVersionIds: string[];
  formatVersion: number;
  keyVersion: number;
  mutation: "upsert" | "delete";
  nonce: Base64Url;
  ciphertext: Base64Url;
  ciphertextDigest: Base64Url;
  authorDeviceId: string;
  clientMutationId: string;
};
```

`mutation` leaks whether a record was deleted, a deliberate minimum-metadata tradeoff
needed for efficient retention and compaction. Record kind, title, origin, username,
group, notes and secret material remain inside ciphertext. `ciphertextDigest` is for
integrity/idempotency diagnostics and is not a substitute for AEAD authentication.
The API computes neither semantic merges nor decrypted diffs.

The authenticated associated data is derived from an unambiguous normative encoding
of at least `vaultId`, `recordId`, `versionId`, `parentVersionIds`, `formatVersion`,
`keyVersion` and `mutation`. The security protocol owns the exact encoding.

## Client/platform ports

```ts
interface CryptoPort {
  sealRecord(input: PlainRecord, context: RecordContext): Promise<SealedRecord>;
  openRecord(input: SealedRecord, context: RecordContext): Promise<PlainRecord>;
  wrapVaultKey(input: VaultKey, factor: UnlockFactor): Promise<KeyEnvelope>;
  unwrapVaultKey(envelope: KeyEnvelope, factor: UnlockFactor): Promise<VaultKey>;
}

interface ReplicaStore {
  transaction<T>(fn: (tx: ReplicaTransaction) => Promise<T>): Promise<T>;
  getHeads(recordId: string): Promise<OpaqueRecordVersion[]>;
  append(version: OpaqueRecordVersion): Promise<void>;
  getSyncCheckpoint(): Promise<SyncCheckpoint>;
}

interface SyncTransport {
  push(batch: PushRequest, session: ServiceSession): Promise<PushResponse>;
  pull(cursor: string | null, limit: number, session: ServiceSession): Promise<PullPage>;
}
```

Native Swift protocols mirror behavior, not TypeScript ABI. Compatibility is proven
with shared JSON fixtures, protocol conformance tests and crypto test vectors.

## API surface

| Endpoint | Purpose | Important behavior |
| --- | --- | --- |
| `POST /v1/auth/webauthn/*` | registration/login ceremony | short-lived single-use challenges |
| `POST /v1/sessions/refresh` | rotate service session | replay-safe token rotation |
| `GET /v1/devices` | list devices | no unlock factors or secret metadata |
| `DELETE /v1/devices/{id}` | revoke device | invalidates sessions atomically |
| `POST /v1/vaults/{id}/sync/push` | append mutation batch | transactional, idempotent |
| `GET /v1/vaults/{id}/sync/pull` | incremental changes | stable pagination snapshot |
| `POST /v1/vaults/{id}/sync/ack` | record durable high-water mark | monotonic per device |
| `GET /health/live` | process liveness | no dependency details |
| `GET /health/ready` | DB/migration readiness | protected detail in logs only |

Precise auth challenge routes may be split during implementation; the invariants are
single-use challenges, strict origin/RP-ID validation, session rotation and separation
from vault unlock.

## Extension messages

Messages are discriminated unions with `protocolVersion`, `requestId`, `tabId` and
`frameId` bound by the receiver to Chrome-provided sender metadata. The caller's copy
of those identifiers is never authoritative.

- `FIELD_REPORT`: field classifications and origins; no entered values.
- `LIST_MATCHES`: returns IDs and minimal encrypted-context-derived labels after the
  trusted context validates origin.
- `FILL_SELECTED`: explicit item ID and target fields; response contains exactly one
  fill payload and expires after one use/short timeout.
- `CAPTURE_CANDIDATE`: page event hint; trusted UI asks the user before saving.
- `LOCK_STATE`: contains only locked/unlocked and expiry, never keys.

Sensitive copy/show/export actions are not available to a content script contract.

## Compatibility

Clients send `clientProtocolVersion` and build version. The API publishes a minimum
and maximum accepted protocol version without forcing an unlock. Unsupported clients
receive `CLIENT_UPGRADE_REQUIRED`; the server never rewrites opaque ciphertext to
make it compatible. Read support for the previous wire version is retained through a
published migration window.

