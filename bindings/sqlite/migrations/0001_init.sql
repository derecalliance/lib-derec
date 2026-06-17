-- Initial schema for the SQLite-backed DeRec stores.
-- Every protocol-side table is keyed first by `secret_id` so a single
-- backing database can serve multiple vaults on the same device
-- without leakage between them.

CREATE TABLE channels (
    secret_id  INTEGER NOT NULL,
    channel_id INTEGER NOT NULL,
    data       BLOB    NOT NULL,
    PRIMARY KEY (secret_id, channel_id)
);

-- Undirected adjacency list for the channel-link graph. Each link is
-- materialized as two rows so a single index covers lookups from
-- either endpoint.
CREATE TABLE channel_links (
    secret_id INTEGER NOT NULL,
    a         INTEGER NOT NULL,
    b         INTEGER NOT NULL,
    PRIMARY KEY (secret_id, a, b)
);

CREATE TABLE secrets (
    secret_id  INTEGER NOT NULL,
    channel_id INTEGER NOT NULL,
    kind       INTEGER NOT NULL,
    data       BLOB    NOT NULL,
    PRIMARY KEY (secret_id, channel_id, kind)
);

CREATE TABLE shares (
    -- `replica_id` is part of the conceptual storage key: distinct
    -- replicas writing the same `(secret_id, channel_id, version)`
    -- must both survive because the wire layer cannot distinguish
    -- them (they reuse the source's shared key). NULL means a
    -- non-replica Owner produced the share.
    --
    -- SQLite forbids expressions inside PRIMARY KEY / UNIQUE
    -- constraints, so the four-tuple uniqueness contract is expressed
    -- via a separate UNIQUE INDEX with `COALESCE(replica_id, -1)` —
    -- two Owner re-sends (both replica_id = NULL) still collide and
    -- ON CONFLICT against the index updates the existing row.
    secret_id       INTEGER NOT NULL,
    channel_id      INTEGER NOT NULL,
    version         INTEGER NOT NULL,
    replica_id      INTEGER,
    share_secret_id INTEGER NOT NULL,
    bytes           BLOB    NOT NULL
);
CREATE UNIQUE INDEX shares_uniq
    ON shares (secret_id, channel_id, version, COALESCE(replica_id, -1));

CREATE TABLE user_secrets (
    secret_id   INTEGER NOT NULL PRIMARY KEY,
    version     INTEGER NOT NULL,
    description TEXT,
    payload     BLOB    NOT NULL
);
