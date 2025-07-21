-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';
ALTER TABLE users
    ADD COLUMN ref_token TEXT;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
ALTER TABLE users
DROP COLUMN ref_token;
-- +goose StatementEnd
