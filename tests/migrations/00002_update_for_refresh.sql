-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';
DROP TABLE applications;

CREATE TABLE tokens (
    id SERIAL PRIMARY KEY,
    token VARCHAR(64) NOT NULL,
    user_id INTEGER UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT false,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
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
-- +goose StatementEnd
