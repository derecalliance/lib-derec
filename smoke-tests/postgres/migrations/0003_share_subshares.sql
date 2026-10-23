-- The owner-side subshare count of each share (`Share::subshares`). NULL on a
-- helper's row, and on owner rows written before the count was recorded.
ALTER TABLE shares ADD COLUMN subshares BIGINT;
