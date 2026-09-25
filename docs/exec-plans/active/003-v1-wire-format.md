# V1 wire-format implementation

Status: in progress; no production activation.

## Completed in this increment

- The `vault-object` AAD integer-key schema is fixed in the protocol specification.
- TypeScript deterministic CBOR encoding and decoding reject non-shortest forms, unsorted or duplicate map keys, invalid UTF-8, unsupported types, trailing bytes, excessive nesting, and oversized maps or strings.
- Three shared byte vectors fix the exact AAD for one password object, including integer-width boundaries. TypeScript and Swift encoders consume them. The TypeScript AAD schema decoder rejects unknown fields and invalid types.
- The TypeScript object envelope now uses a versioned binary frame, a fresh per-version DEK and nonces, separate HKDF-derived wrap key, and separate wrap/payload AEAD contexts. Its reader compares the complete AAD to trusted routing metadata and verifies both tags before CBOR parsing. A libsodium/Python reference vector fixes the exact bytes.
- The Swift object reader parses the same bounded canonical frame, compares caller-supplied AAD, verifies both tags, and validates deterministic CBOR before returning payload bytes. It remains isolated from app persistence, sync, and AutoFill.
- The first typed payload schema (`password`) now has exact integer keys, bounded fields, strict TypeScript/Swift decoders, and a shared byte vector. Both platforms also reject noncanonical origins using a shared positive/negative corpus; this decoder is not connected to AutoFill.
- Independent security and adversarial reviews found no remaining Critical or High issue in these isolated helpers. Review found an unsafe negative-integer edge case and a payload-allocation/cleanup limit; both were corrected and retested before completion.

## Next protocol gates

1. Finish schemas for the remaining object types, parser mutation/resource tests, and fuzzing. The iOS preview now checks exact origins for URL service identifiers; verify Apple's URL/domain and direct-request association behavior on a signed physical device before connecting V1 records.
2. Fix numeric schemas and vectors for slots, operations, signatures, and checkpoints. Add parser fuzzing.
3. Implement the Swift V1 object writer. Then integrate both platforms with persistence only through a reviewed migration and compare authenticated context to trusted routing metadata at every caller.
4. Implement signed DAG operations and checkpoint validation before enabling remote multi-device vault sync.
5. Repeat independent security and adversarial review of the complete reachable flow, then perform device and release-candidate gates.

## Threat and migration impact

The new helpers are not used by the existing Chrome JSON preview vault or iOS AES-GCM local cache. No vault data is migrated, no unlock/recovery behavior changes, and no new artifact is accepted from storage or the network. The helper's main risks are divergent serialization, parser resource exhaustion, and context substitution when later connected to persistence or sync; bounds, AEAD and trusted-context comparison address them locally, while the integration gate above remains mandatory. Existing preview data must never be relabeled as `space.vault/1`; a later migration needs an authenticated, resumable N-1 to N plan and recovery test.

The origin grammar is intentionally narrower than the preview's URL handling. A later migration must surface unsupported IDN/IPv6 origins for explicit user resolution without silently dropping credentials or broadening AutoFill matches; recovery data and key slots are unchanged by this isolated validator.

## Local evidence

- `npm run check`, secret scan, permission gate, and migration-order gate passed on this increment.
- The Swift AAD encoder compiled against Foundation and matched all three JSON vectors in a standalone macOS executable.
- The Xcode Release simulator build gate passed after correcting the generated framework Info.plist and preserving app/provider entitlements in the XcodeGen spec.
- Xcode's iPhone 17 Pro / iOS 26.5 simulator now tests the full Swift object reader, every-byte artifact mutation, noncanonical framing, and authenticated invalid CBOR in addition to shared vectors. This is simulator evidence, not signed-device AutoFill evidence.
