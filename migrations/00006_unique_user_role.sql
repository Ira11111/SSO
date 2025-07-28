-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';
ALTER TABLE user_role
    ADD CONSTRAINT user_role_unique_pair
    UNIQUE (user_id, role_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
ALTER TABLE user_role
    DROP CONSTRAINT user_role_unique_pair;
-- +goose StatementEnd
