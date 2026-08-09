DELETE FROM user_refresh_tokens;

ALTER TABLE user_refresh_tokens
RENAME COLUMN token TO token_hash;

ALTER TABLE user_refresh_tokens
ALTER COLUMN token_hash TYPE VARCHAR(64);

DROP INDEX IF EXISTS idx_refresh_token_val;
CREATE INDEX idx_refresh_token_hash ON user_refresh_tokens(token_hash);
