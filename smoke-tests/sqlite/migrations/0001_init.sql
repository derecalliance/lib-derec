-- Initial schema for the SQLite-backed DeRec stores.
-- Every protocol-side table is keyed first by `secret_id` so a single
-- backing database can serve multiple secrets on the same device
-- without leakage between them.

-- Helper channels: unique per channel_id, one row per pairing.
CREATE TABLE channels (
    secret_id  INTEGER NOT NULL,
    channel_id INTEGER NOT NULL,
    data       BLOB    NOT NULL,
    PRIMARY KEY (secret_id, channel_id)
);

-- Replica-group members. Keyed by `replica_id`, NOT by `channel_id`: every
-- member of a group shares one channel, so a channel-keyed table would
-- collide at the second member. `channel_id` is stored as an ordinary column
-- because a member moves between channels during an admission handover while
-- remaining the same member.
CREATE TABLE replica_members (
    secret_id  INTEGER NOT NULL,
    replica_id INTEGER NOT NULL,
    channel_id INTEGER NOT NULL,
    data       BLOB    NOT NULL,
    PRIMARY KEY (secret_id, replica_id)
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

-- One share per `(secret_id, channel_id, version)`. A helper stores exactly
-- one share per version and knows nothing about replicas: `replica_id` is
-- absent from the helper path entirely, so it is not part of this key.
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

-- In-flight orchestrator state: verification challenges, recovery
-- accumulators, pending unpair acks, the active sharing round and the active
-- catch-up. Persisting it is the whole point of the state store — a response
-- arriving after a process restart is dropped as unsolicited if the request
-- that expected it did not survive.
--
-- `StateKey`'s secondary key differs per kind, so it is flattened into two
-- integer columns rather than modelled per variant:
--   PendingVerification / PendingUnpair -> sub_a = channel_id
--   PendingRecovery                     -> sub_a = recovered secret_id,
--                                          sub_b = version
--   SharingRound                        -> sub_a = version
--   PendingSyncCheck                    -> no secondary key, both 0
-- `kind` is part of the key, so the two channel-keyed kinds cannot collide.
--
-- SharingRound's version is load-bearing, not decoration. Several rounds can
-- be open at once: publishes are started by the pair-completion hook and by
-- the promotion inside `verify_fingerprint`, not only by `start(ProtectSecret)`.
-- Keying it on `kind` alone would let a new round silently replace one already
-- in flight, after which neither completes and no `SharingComplete` is emitted
-- for either.
CREATE TABLE protocol_state (
    secret_id INTEGER NOT NULL,
    kind      INTEGER NOT NULL,
    sub_a     INTEGER NOT NULL,
    sub_b     INTEGER NOT NULL,
    data      BLOB    NOT NULL,
    PRIMARY KEY (secret_id, kind, sub_a, sub_b)
);

