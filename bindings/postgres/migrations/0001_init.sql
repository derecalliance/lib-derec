-- Initial schema for the Postgres-backed DeRec stores.
-- Same shape as the SQLite migration; column types translated to
-- Postgres equivalents (BIGINT for u64 / u32 / version counters,
-- BYTEA for opaque payloads, INTEGER for SecretKind discriminants).
-- Every protocol-side table is keyed first by `secret_id` so a
-- single backing database can serve multiple vaults on the same
-- device without leakage between them.

-- Helper channels: unique per channel_id, one row per pairing.
CREATE TABLE channels (
    secret_id  BIGINT NOT NULL,
    channel_id BIGINT NOT NULL,
    data       BYTEA  NOT NULL,
    PRIMARY KEY (secret_id, channel_id)
);

-- Replica-group members. Keyed by `replica_id`, NOT by `channel_id`: every
-- member of a group shares one channel, so a channel-keyed table would
-- collide at the second member. `channel_id` is an ordinary column because a
-- member moves between channels during an admission handover while remaining
-- the same member.
CREATE TABLE replica_members (
    secret_id  BIGINT NOT NULL,
    replica_id BIGINT NOT NULL,
    channel_id BIGINT NOT NULL,
    data       BYTEA  NOT NULL,
    PRIMARY KEY (secret_id, replica_id)
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

-- One share per `(secret_id, channel_id, version)`. A helper stores exactly
-- one share per version and knows nothing about replicas: `replica_id` is
-- absent from the helper path entirely, so it is not part of this key.
CREATE TABLE shares (
    secret_id       BIGINT NOT NULL,
    channel_id      BIGINT NOT NULL,
    version         BIGINT NOT NULL,
    share_secret_id BIGINT NOT NULL,
    bytes           BYTEA  NOT NULL,
    CONSTRAINT shares_uniq UNIQUE (secret_id, channel_id, version)
);

CREATE TABLE user_secrets (
    secret_id   BIGINT NOT NULL PRIMARY KEY,
    version     BIGINT NOT NULL,
    description TEXT,
    payload     BYTEA  NOT NULL
);
