package postgresql

import (
	"AuthJWT/internal/config"
	"AuthJWT/internal/domain/models"
	"AuthJWT/internal/storage"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/lib/pq"
	"time"
)

type Storage struct {
	db *sql.DB
}

const (
	ErrUniqueViolation pq.ErrorCode = "23505"
	//ErrForeignKeyViolation pq.ErrorCode = "23503"
	//ErrNotNullViolation    pq.ErrorCode = "23502"
)

func NewStorage(cnf *config.DBConfig) (*Storage, error) {
	const op = "storage.postgres.NewStorage"

	db, err := sql.Open("postgres",
		fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
			cnf.Host,
			cnf.Port,
			cnf.User,
			cnf.Password,
			cnf.Database,
			cnf.SSLMode))
	// проверка корректности конфигурационных данных
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	// проверка подключения к БД
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &Storage{db}, nil
}

func (s *Storage) SaveUser(ctx context.Context, email string, passHash []byte, role string) (int64, error) {
	const op = "storage.postgres.SaveUser"
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx, "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id", email, passHash)
	var id int64
	err = row.Scan(&id)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == ErrUniqueViolation {
			return 0, storage.ErrUserAlreadyExists
		}
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	roleid, err := s.Role(ctx, role)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, storage.ErrRoleDoesNotExist
		}
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	_, err = tx.ExecContext(ctx, "INSERT INTO user_role (user_id, role_id) VALUES ($1, $2)", id, roleid)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == ErrUniqueViolation {
			return 0, storage.ErrRoleAlreadyExists
		}
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	err = tx.Commit()
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

func (s *Storage) User(ctx context.Context, email string) (models.User, error) {
	const op = "storage.postgres.User"

	row := s.db.QueryRowContext(ctx, "SELECT * FROM users WHERE email = $1", email)
	var user models.User
	err := row.Scan(&user.Id, &user.Email, &user.PasswordHash)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, storage.ErrUserNotFound
		}
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil
}

func (s *Storage) SaveToken(ctx context.Context, token string, uid int64, exp time.Time) error {
	const op = "storage.postgres.SaveToken"

	_, err := s.db.ExecContext(ctx, "INSERT INTO tokens (token, user_id, expires_at) VALUES ($1, $2, $3)", token, uid, exp)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == ErrUniqueViolation {
			return storage.ErrTokenAlreadyExists
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (s *Storage) Token(ctx context.Context, token string) (models.Token, error) {
	const op = "storage.postgres.Token"

	var modelToken models.Token
	row := s.db.QueryRowContext(ctx, "SELECT id, user_id, token, expires_at, revoked FROM tokens WHERE token = $1", token)
	err := row.Scan(&modelToken.Id, &modelToken.UserId, &modelToken.Token, &modelToken.ExpiresAt, &modelToken.Revoked)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Token{}, storage.ErrTokenNotFound
		}
		return models.Token{}, fmt.Errorf("%s: %w", op, err)
	}
	return modelToken, nil
}

func (s *Storage) UpdateToken(ctx context.Context, tokenHash string, uid int64, exp time.Time) error {
	const op = "storage.postgres.UpdateToken"

	_, err := s.db.ExecContext(ctx, "UPDATE tokens SET token = $1, expires_at = $2, revoked = $3 WHERE user_id = $4", tokenHash, exp, false, uid)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (s *Storage) RevokeToken(ctx context.Context, uid int64) error {
	const op = "storage.postgres.RevokeToken"

	_, err := s.db.ExecContext(ctx, "UPDATE tokens SET revoked  = $1 WHERE user_id = $2", true, uid)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (s *Storage) CheckByUserId(ctx context.Context, uid int64) (bool, error) {
	const op = "storage.postgres.CheckByUserId"

	var exists bool
	row := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM tokens WHERE user_id = $1)", uid)
	err := row.Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return exists, nil
}

func (s *Storage) Role(ctx context.Context, role string) (int64, error) {
	const op = "storage.postgres.Role"

	var id int64
	row := s.db.QueryRowContext(ctx, "SELECT id FROM roles WHERE name = $1", role)
	err := row.Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, storage.ErrRoleDoesNotExist
		}
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	return id, nil
}

func (s *Storage) AddRole(ctx context.Context, uid int64, role string) error {
	const op = "storage.postgres.AddRole"

	roleid, err := s.Role(ctx, role)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return storage.ErrRoleDoesNotExist
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO user_role (user_id, role_id) VALUES ($1, $2)", uid, roleid)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == ErrUniqueViolation {
			return storage.ErrRoleAlreadyExists
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (s *Storage) UserRoles(ctx context.Context, uid int64) ([]string, error) {
	const op = "storage.postgres.UserRoles"
	var roles []string
	rows, err := s.db.QueryContext(ctx, "SELECT name FROM roles INNER JOIN user_role ON roles.id = user_role.role_id WHERE user_role.user_id = $1 ", uid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []string{}, storage.ErrRolesNotFound
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	for rows.Next() {
		var role string
		if err = rows.Scan(&role); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		roles = append(roles, role)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return roles, nil
}
