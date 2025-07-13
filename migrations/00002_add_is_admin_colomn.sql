-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';
ALTER TABLE users
    ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT false;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
ALTER TABLE users
    DROP COLUMN is_admin;
-- +goose StatementEnd
