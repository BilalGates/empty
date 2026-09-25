# space.vault/1 implementation track

Status: in progress; not approved for production credentials.

## First slice: restricted deterministic CBOR

`packages/protocol/src/cbor.ts` now encodes and decodes the restricted CBOR value
subset needed for future authenticated headers: safe integers, UTF-8 strings, byte
strings, arrays, and maps with nonnegative integer keys. The decoder rejects
nonminimal integers, duplicate or unordered keys, indefinite lengths, tags,
floating-point/simple values, invalid UTF-8, trailing bytes, excess depth and size.
It is not yet used for vault persistence, AAD, or signed operations.

`packages/protocol/src/frame.ts` now adds the exact V1 magic, version, kind, and
length framing. `test-vectors/cbor-frame-v1.json` holds shared positive and negative
bytes. Semantic field schemas and authenticated use remain pending.

`packages/protocol/src/object-aad.ts` freezes and validates the nine integer-key
fields for an encrypted object's AAD. `test-vectors/object-aad-v1.json` fixes exact
bytes for both platforms. `packages/protocol/src/object-record.ts` now validates the
framed record and the nonce/ciphertext shapes; `test-vectors/object-record-v1.json`
fixes public parser bytes. AEAD use remains pending and parsed bytes are untrusted.

Security impact: this reduces serialization ambiguity once schemas are frozen. It
does not authenticate data by itself or close rollback, fork, or tampering risks.
The local JSON preview remains a separate format and must not be relabeled V1.

Migration/recovery impact: none in this slice. No stored bytes or recovery key
format changed. A future migration must keep the preview readable until users can
verify a complete V1 rewrite and encrypted backup restore.

## Remaining gates

1. Freeze slot, operation, checkpoint, and recovery schemas; extend positive and
   negative vectors beyond the now-fixed object record.
2. Implement per-object key hierarchy and envelopes with canonical AAD, then
   signed device operations, sequence/DAG validation, and sealed checkpoints.
3. Implement equivalent Swift parsing and cryptography against the same corpus.
4. Add parser mutation/fuzz and resource-bound tests, migration interruption and
   recovery tests, and hostile-server replay/fork/rollback scenarios.
5. Obtain independent security and adversarial reviews of the exact candidate;
   repeat the release gates before storing real credentials.
