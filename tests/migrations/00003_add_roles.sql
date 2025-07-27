-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';
CREATE TABLE roles
(
    id   SERIAL PRIMARY KEY,
    name VARCHAR(8) NOT NULL UNIQUE
);
INSERT INTO roles (name)
VALUES ('admin'),
       ('seller'),
       ('worker'),
       ('customer');
CREATE TABLE user_role
(
    id      SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
DROP TABLE user_role;
DROP TABLE roles;
-- +goose StatementEnd
