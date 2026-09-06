# Ciphertext backup and restore

Back up PostgreSQL using encrypted infrastructure snapshots or `pg_dump` over an authenticated channel. Ciphertext backups remain sensitive because they enable offline KDF attacks and reveal timing metadata.

Restore into an isolated database at the same schema version, validate constraints, then start one replica in maintenance mode. Verify pull cursors with a disposable account before traffic. Clients must compare their authenticated checkpoint and block on rollback rather than silently accepting older state.

Never include `.env`, token peppers, TLS/signing keys, plaintext exports, recovery keys, or master passwords. Back up token peppers separately in a secrets manager with a rotation plan.

