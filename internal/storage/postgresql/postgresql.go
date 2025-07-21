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

func (s *Storage) SaveUser(ctx context.Context, email string, passHash []byte) (int64, error) {
	const op = "storage.postgres.SaveUser"

	stmt, err := s.db.Prepare("INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id")
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, email, passHash)
	var id int64
	err = row.Scan(&id)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == ErrUniqueViolation {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrUserAlreadyExists)
		}
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

func (s *Storage) User(ctx context.Context, email string) (models.User, error) {
	const op = "storage.postgres.User"

	stmt, err := s.db.Prepare("SELECT * FROM users WHERE email = $1")
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, email)
	var user models.User
	err = row.Scan(&user.Id, &user.Email, &user.PasswordHash)

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

	stmt, err := s.db.Prepare("INSERT INTO tokens (token, user_id, expires_at) VALUES ($1, $2, $3)")
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == ErrUniqueViolation {
			return storage.ErrTokenAlreadyExists
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	_, err = stmt.ExecContext(ctx, token, uid, exp)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (s *Storage) Token(ctx context.Context, token string) (models.Token, error) {
	const op = "storage.postgres.Token"
	stmt, err := s.db.Prepare("SELECT id, user_id, token, expires_at, revoked FROM tokens WHERE token = $1")
	if err != nil {
		return models.Token{}, fmt.Errorf("%s: %w", op, err)
	}
	var modelToken models.Token
	row := stmt.QueryRowContext(ctx, token)
	err = row.Scan(&modelToken.Id, &modelToken.UserId, &modelToken.Token, &modelToken.ExpiresAt, &modelToken.Revoked)
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

	stmt, err := s.db.Prepare("UPDATE tokens SET token = $1, expires_at = $2, revoked = $3 WHERE user_id = $4")
	if err != nil {
		return err
	}
	_, err = stmt.ExecContext(ctx, tokenHash, exp, false, uid)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (s *Storage) RevokeToken(ctx context.Context, uid int64) error {
	const op = "storage.postgres.RevokeToken"
	stmt, err := s.db.Prepare("UPDATE tokens SET revoked  = $1 WHERE user_id = $2")
	if err != nil {
		return err
	}

	_, err = stmt.ExecContext(ctx, true, uid)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (s *Storage) CheckByUserId(ctx context.Context, uid int64) (bool, error) {
	const op = "storage.postgres.CheckByUserId"

	stmt, err := s.db.Prepare("SELECT EXISTS(SELECT 1 FROM tokens WHERE user_id = $1)")
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	var exists bool
	row := stmt.QueryRowContext(ctx, uid)
	err = row.Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return exists, nil
}
