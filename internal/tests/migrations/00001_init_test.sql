-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash BYTEA NOT NULL
    );
CREATE TABLE IF NOT EXISTS applications (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    secret TEXT NOT NULL UNIQUE
    );

INSERT INTO applications (id, name, secret)
VALUES (1, 'test', 'test-secret')
    ON CONFLICT DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
DROP TABLE IF EXISTS applications;
-- +goose StatementEnd