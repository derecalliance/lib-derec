-- Initial schema for the Postgres-backed DeRec stores.
-- Same shape as the SQLite migration; column types translated to
-- Postgres equivalents (BIGINT for u64 / u32 / version counters,
-- BYTEA for opaque payloads, INTEGER for SecretKind discriminants).
-- Every protocol-side table is keyed first by `secret_id` so a
-- single backing database can serve multiple vaults on the same
-- device without leakage between them.

CREATE TABLE channels (
    secret_id  BIGINT NOT NULL,
    channel_id BIGINT NOT NULL,
    data       BYTEA  NOT NULL,
    PRIMARY KEY (secret_id, channel_id)
);

CREATE TABLE channel_links (
    secret_id BIGINT NOT NULL,
    a         BIGINT NOT NULL,
    b         BIGINT NOT NULL,
    PRIMARY KEY (secret_id, a, b)
);

CREATE TABLE secrets (
    secret_id  BIGINT  NOT NULL,
    channel_id BIGINT  NOT NULL,
    kind       INTEGER NOT NULL,
    data       BYTEA   NOT NULL,
    PRIMARY KEY (secret_id, channel_id, kind)
);

CREATE TABLE shares (
    secret_id       BIGINT NOT NULL,
    channel_id      BIGINT NOT NULL,
    version         BIGINT NOT NULL,
    share_secret_id BIGINT NOT NULL,
    bytes           BYTEA  NOT NULL,
    PRIMARY KEY (secret_id, channel_id, version)
);

CREATE TABLE user_secrets (
    secret_id   BIGINT NOT NULL PRIMARY KEY,
    version     BIGINT NOT NULL,
    description TEXT,
    payload     BYTEA  NOT NULL
);
