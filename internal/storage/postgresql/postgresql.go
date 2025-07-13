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

	fmt.Println(cnf)
	fmt.Printf("%T\n", cnf.Port)
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
	// проыерка подключения к БД
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	fmt.Println(db)
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

	stmt, err := s.db.Prepare("SELECT id, email, password_hash FROM users WHERE email = $1")
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

func (s *Storage) IsAdmin(ctx context.Context, uid int64) (bool, error) {
	// TODO: переделать после нормализации БД
	const op = "storage.postgres.IsAdmin"
	stmt, err := s.db.Prepare("SELECT is_admin FROM users WHERE id = $1")
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, uid)
	var isAdmin bool
	err = row.Scan(&isAdmin)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, storage.ErrUserNotFound
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return isAdmin, nil
}

func (s *Storage) App(ctx context.Context, appId int32) (models.App, error) {
	const op = "storage.postgres.App"
	stmt, err := s.db.Prepare("SELECT * FROM applications WHERE id = $1")
	if err != nil {
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}
	row := stmt.QueryRowContext(ctx, appId)
	var app models.App
	err = row.Scan(&app.Id, &app.Name, &app.Secret)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.App{}, storage.ErrAppNotFound
		}
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}
	return app, nil
}
