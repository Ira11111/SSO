-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';
ALTER TABLE users
DROP COLUMN is_admin,
    DROP COLUMN ref_token;

DROP TABLE applications;

CREATE TABLE tokens (
    id SERIAL PRIMARY KEY,
    token VARCHAR(64) NOT NULL,
    user_id INTEGER UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT false,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(user_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
DROP INDEX IF EXISTS idx_tokens_user;
DROP TABLE tokens;

CREATE TABLE applications (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    secret TEXT NOT NULL UNIQUE
);

ALTER TABLE users
    ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN ref_token TEXT;
-- +goose StatementEnd