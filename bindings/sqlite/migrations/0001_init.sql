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
    secret_id       INTEGER NOT NULL,
    channel_id      INTEGER NOT NULL,
    version         INTEGER NOT NULL,
    share_secret_id INTEGER NOT NULL,
    bytes           BLOB    NOT NULL,
    PRIMARY KEY (secret_id, channel_id, version)
);

CREATE TABLE user_secrets (
    secret_id   INTEGER NOT NULL PRIMARY KEY,
    version     INTEGER NOT NULL,
    description TEXT,
    payload     BLOB    NOT NULL
);
