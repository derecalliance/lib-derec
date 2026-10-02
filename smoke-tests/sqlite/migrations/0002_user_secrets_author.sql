-- The replica-group member that published the stored version, so a replica
-- can tell a re-send of the version it holds from a rival copy of it.
-- NULL when the version was not published by a group member.
ALTER TABLE user_secrets ADD COLUMN author_replica_id INTEGER;
