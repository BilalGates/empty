# Extension unlocked-session security review

Status: accepted for the local preview vault.

The unlocked MV3 session now contains only the encoded random vault key and expiry metadata. It no longer retains the master password or a plaintext vault document. This avoids repeating Argon2id for each mutation while preserving Argon2id on unlock and backup reauthentication.

The key grants plaintext access while unlocked, so it remains a high-value secret. It is stored only in Chrome's memory-backed `storage.session`, restricted to trusted extension contexts, never sent to a content script, and removed by a five-minute sliding alarm, manual lock, restart, reload, update, or disable. Live checks use a monotonic deadline. Manual lock increments the session generation synchronously, so fills, secret reads, restores, and writes already awaiting an asynchronous browser operation fail closed.

On MV3 worker restoration, Space decrypts and authenticates the current persistent vault with the session key before reconstructing plaintext state. A malformed, stale, or mismatched key clears the session. Sessions from the previous password/document shape fail schema validation and require a fresh unlock; no persistent migration is required.

Evidence: core positive/negative session-key tests, extension protocol/unit build, Chrome E2E worker restoration, content-script denial, lock-during-fill race, encrypted backup rejection/restore, plaintext persistence guards, permission gate, and secret scan. A malicious privileged extension/debugger or local malware capable of reading another extension's process memory remains outside the documented threat model.

Encrypted backup restore accepts either its master password or the recovery key shown at vault creation. Both paths unwrap the same random vault key and authenticate the complete ciphertext and AAD before persistent replacement. Invalid recovery input leaves the current vault unchanged, and the recovery key is never persisted.
