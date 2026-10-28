-- The owner-side threshold each share's version was split with
-- (`Share::threshold`). NULL on a helper's row, and on owner rows written
-- before the threshold was recorded.
ALTER TABLE shares ADD COLUMN threshold INTEGER;
-- The threshold the next publish splits at (`UserSecrets::threshold`). NULL on
-- a snapshot written before the threshold was recorded.
ALTER TABLE user_secrets ADD COLUMN threshold INTEGER;
