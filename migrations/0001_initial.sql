-- Privacy gateway initial schema.
--
-- Two tables, and the uniqueness rules are the design (guide §13.2):
--   * (tenant_id, scope_id)                                     one scope row
--   * (tenant_id, scope_id, token)                              one mapping per token
--   * (tenant_id, scope_id, entity_type, canonical_value_hmac)  deterministic reuse
--
-- The last one is what makes "the same value gets the same token inside one
-- scope" a database guarantee rather than an application convention: two
-- concurrent requests tokenizing the same value cannot produce two tokens.
--
-- encrypted_original is ciphertext produced by the gateway before insertion, so
-- this database and its backups never contain plaintext identifiers.

BEGIN;

CREATE TABLE IF NOT EXISTS scopes (
    tenant_id                TEXT        NOT NULL,
    scope_id                 TEXT        NOT NULL,
    status                   TEXT        NOT NULL CHECK (status IN ('ACTIVE', 'CLOSED', 'EXPIRED')),
    privacy_mode             TEXT        NOT NULL CHECK (privacy_mode IN ('CLEAN', 'SANITIZED_LOCKED')),
    policy_version           TEXT        NOT NULL,
    client_conversation_id   TEXT,
    turn_count               INTEGER     NOT NULL DEFAULT 0,
    file_count               INTEGER     NOT NULL DEFAULT 0,
    cumulative_bytes         BIGINT      NOT NULL DEFAULT 0,
    cumulative_pages         INTEGER     NOT NULL DEFAULT 0,
    mapping_count            INTEGER     NOT NULL DEFAULT 0,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_active_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    idle_expires_at          TIMESTAMPTZ NOT NULL,
    absolute_expires_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, scope_id)
);

CREATE INDEX IF NOT EXISTS scopes_expiry_idx
    ON scopes (status, idle_expires_at, absolute_expires_at);

CREATE TABLE IF NOT EXISTS token_mappings (
    tenant_id             TEXT        NOT NULL,
    scope_id              TEXT        NOT NULL,
    created_by_request_id TEXT        NOT NULL,
    token                 TEXT        NOT NULL,
    entity_type           TEXT        NOT NULL,
    encrypted_original    BYTEA       NOT NULL,
    canonical_value_hmac  TEXT        NOT NULL,
    policy_version        TEXT        NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at            TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, scope_id, token)
);

CREATE UNIQUE INDEX IF NOT EXISTS token_mappings_canonical_idx
    ON token_mappings (tenant_id, scope_id, entity_type, canonical_value_hmac);

CREATE INDEX IF NOT EXISTS token_mappings_expiry_idx
    ON token_mappings (expires_at);

-- Deleting a scope must take its mappings with it.
ALTER TABLE token_mappings
    DROP CONSTRAINT IF EXISTS token_mappings_scope_fk;
ALTER TABLE token_mappings
    ADD CONSTRAINT token_mappings_scope_fk
    FOREIGN KEY (tenant_id, scope_id) REFERENCES scopes (tenant_id, scope_id)
    ON DELETE CASCADE;

COMMIT;
