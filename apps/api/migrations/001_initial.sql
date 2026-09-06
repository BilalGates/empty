BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at timestamptz NOT NULL DEFAULT now(),
  disabled_at timestamptz
);

CREATE TABLE vaults (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  current_revision bigint NOT NULL DEFAULT 0 CHECK (current_revision >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, user_id)
);

CREATE TABLE devices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  vault_id uuid NOT NULL,
  label text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 120),
  token_fingerprint bytea NOT NULL UNIQUE CHECK (octet_length(token_fingerprint) = 16),
  token_hash bytea NOT NULL CHECK (octet_length(token_hash) = 32),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz,
  revoked_at timestamptz,
  FOREIGN KEY (vault_id, user_id) REFERENCES vaults(id, user_id) ON DELETE RESTRICT
);

-- Append-only encrypted item versions. The service cannot decrypt any envelope field.
CREATE TABLE sync_records (
  vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE RESTRICT,
  item_id uuid NOT NULL,
  item_version bigint NOT NULL CHECK (item_version > 0),
  revision bigint NOT NULL CHECK (revision > 0),
  mutation_id uuid NOT NULL,
  author_device_id uuid NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  ciphertext text,
  nonce text,
  wrapped_key text,
  aad text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (vault_id, item_id, item_version),
  UNIQUE (vault_id, revision),
  UNIQUE (vault_id, mutation_id),
  CHECK (
    (ciphertext IS NULL AND nonce IS NULL AND wrapped_key IS NULL AND aad IS NULL)
    OR
    (ciphertext IS NOT NULL AND nonce IS NOT NULL AND wrapped_key IS NOT NULL)
  ),
  CHECK (ciphertext IS NULL OR octet_length(ciphertext) <= 1048576),
  CHECK (nonce IS NULL OR octet_length(nonce) <= 256),
  CHECK (wrapped_key IS NULL OR octet_length(wrapped_key) <= 8192),
  CHECK (aad IS NULL OR octet_length(aad) <= 8192)
);
CREATE INDEX sync_records_pull_idx ON sync_records (vault_id, revision);
CREATE INDEX sync_records_head_idx ON sync_records (vault_id, item_id, item_version DESC);

CREATE TABLE mutation_receipts (
  vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE RESTRICT,
  mutation_id uuid NOT NULL,
  device_id uuid NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  payload_hash bytea NOT NULL CHECK (octet_length(payload_hash) = 32),
  http_status integer NOT NULL,
  response jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (vault_id, mutation_id)
);

CREATE TABLE audit_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  vault_id uuid REFERENCES vaults(id) ON DELETE RESTRICT,
  device_id uuid REFERENCES devices(id) ON DELETE SET NULL,
  event_type text NOT NULL CHECK (event_type IN ('device_created', 'device_revoked', 'sync_push', 'sync_conflict')),
  occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_events_user_time_idx ON audit_events (user_id, occurred_at DESC);

INSERT INTO schema_migrations(version) VALUES ('001_initial');

COMMIT;
