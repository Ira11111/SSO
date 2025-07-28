package auth

import (
	"AuthJWT/internal/domain/models"
	jwtlib "AuthJWT/internal/lib/jwt"
	"AuthJWT/internal/storage"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"os"
	"time"
)

var (
	// это ошибки которые может видеть хэндлер
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserAlreadyExists  = errors.New("user already Exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrTokenExpired       = errors.New("token expired")
	ErrTokenRevoked       = errors.New("token revoked")
	ErrInvalidToken       = errors.New("invalid token")
	ErrRoleDoesNotExist   = errors.New("role does not exists")
	ErrRoleAlreadyExists  = errors.New("role already exists")
	ErrUserRolesNotFound  = errors.New("users roles not found")
)

type Auth struct {
	logger        *slog.Logger
	userProvider  UserProvider
	tokenProvider TokenProvider
	roleProvider  RoleProvider
	accessTTL     time.Duration
	refreshTTL    time.Duration
	jwtKey        string
}

type UserProvider interface {
	SaveUser(ctx context.Context, email string, passHash []byte, role string) (int64, error)
	User(ctx context.Context, email string) (models.User, error)
}

type TokenProvider interface {
	SaveToken(ctx context.Context, token string, uid int64, exp time.Time) error
	Token(ctx context.Context, token string) (models.Token, error)
	UpdateToken(ctx context.Context, tokenHash string, uid int64, exp time.Time) error
	RevokeToken(ctx context.Context, uid int64) error
	CheckByUserId(ctx context.Context, uid int64) (bool, error)
}
type RoleProvider interface {
	AddRole(ctx context.Context, uid int64, role string) error
	UserRoles(ctx context.Context, uid int64) ([]string, error)
}

// конструктор, создает экземпляр сервиса аунтефикации
func New(log *slog.Logger, UserProvider UserProvider, TokenProvider TokenProvider, RoleProvider RoleProvider, accessTTL time.Duration, refTTL time.Duration) *Auth {
	return &Auth{
		logger:        log,
		userProvider:  UserProvider,
		tokenProvider: TokenProvider,
		roleProvider:  RoleProvider,
		accessTTL:     accessTTL,
		refreshTTL:    refTTL,
	}
}

func (a *Auth) privateKey() (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(os.Getenv("JWT_PRIVATE_KEY")))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return key.(*rsa.PrivateKey), nil
	}
	return privKey, nil
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:]) // Преобразуем в HEX строку
}

func (a *Auth) Login(ctx context.Context, email string, password string) (string, string, error) {
	const op = "sso.Login"
	log := a.logger.With(
		slog.String("op", op),
		slog.String("email", email),
	)
	log.Info("trying to login user")

	// находим пользователя
	user, err := a.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", op, ErrUserNotFound)
			return "", "", ErrUserNotFound
		}
		log.Warn("failed to login user", op, err.Error())
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	// проверяем пароль
	if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password)); err != nil {
		log.Warn("invalid credentials", op, ErrInvalidCredentials)
		return "", "", ErrInvalidCredentials
	}

	key, err := a.privateKey()
	if err != nil {
		log.Warn("failed to get key", op, err.Error())
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("trying to find available roles")
	roles, err := a.roleProvider.UserRoles(ctx, user.Id)
	if err != nil {
		log.Warn("failed to find available roles", op, err.Error())
		return "", "", fmt.Errorf("%s: %w", op, err)
	}
	log.Info("found available roles")

	log.Info("user successfully logged in")
	// создаем токен
	log.Info("trying to create token")
	accessToken, refToken, err := jwtlib.NewTokens(user.Id, roles, a.accessTTL, key)
	if err != nil {
		log.Warn("failed to generate token", op, err.Error())
		return "", "", fmt.Errorf("%s: %w", op, err)
	}
	log.Info("successfully generated token")

	log.Info("trying to save refresh token")
	tokenHash := hashToken(refToken)

	exists, err := a.tokenProvider.CheckByUserId(ctx, user.Id)
	if err != nil {
		log.Warn("failed to check by user id", op, err.Error())
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	if exists {
		err = a.tokenProvider.UpdateToken(ctx, tokenHash, user.Id, time.Now().UTC().Add(a.refreshTTL))
	} else {
		err = a.tokenProvider.SaveToken(ctx, tokenHash, user.Id, time.Now().UTC().Add(a.refreshTTL))
	}

	if err != nil {
		log.Warn("failed to save refresh token", op, err.Error())
		return "", "", fmt.Errorf("%s: %w", op, err)
	}
	log.Info("successfully saved refresh token")

	return accessToken, refToken, nil
}

func (a *Auth) RegisterNewUser(
	ctx context.Context,
	email string,
	password string,
	role string,
) (int64, error) {
	const op = "sso.RegisterNewUser"
	log := a.logger.With(slog.String("op", op))
	log.Info("trying register new user")

	// внутри функция хэширует пароль, создает для него соль (10 раз)
	// на выходе получаем хэш
	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password hash", err.Error())
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	// сохранение пользователя в базу данных
	uid, err := a.userProvider.SaveUser(ctx, email, passHash, role)
	if err != nil {
		log.Error("failed to save user", err.Error())
		if errors.Is(err, storage.ErrUserAlreadyExists) {
			log.Warn("user already exists", op)
			return 0, ErrUserAlreadyExists
		}
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("successfully register user", slog.String("op", op))
	return uid, nil
}

func (a *Auth) RefreshToken(ctx context.Context, refreshToken string) (string, string, error) {
	const op = "sso.RefreshToken"
	logger := a.logger.With(slog.String("op", op))
	logger.Info("trying to refresh token")

	// находим пользователя в БД

	//1. найти токен в БД
	logger.Info("trying to find refresh token")
	tokenHash := hashToken(refreshToken)
	token, err := a.tokenProvider.Token(ctx, tokenHash)
	if err != nil {
		logger.Error("failed to identify token", err.Error())
		if errors.Is(err, storage.ErrTokenNotFound) {
			return "", "", ErrInvalidToken
		}
		return "", "", fmt.Errorf("%s: %w", op, err)
	}
	logger.Info("successfully identify token")

	// валидируем токен
	logger.Info("trying to validate refresh token")

	if time.Now().UTC().After(token.ExpiresAt.UTC()) {
		logger.Warn("refresh token expired")
		return "", "", ErrTokenExpired
	}
	if token.Revoked == true {
		logger.Warn("refresh token revoked")
		return "", "", ErrTokenRevoked
	}
	logger.Info("successfully validate refresh token")

	// 2. на основе данных сгенерировать новые токены
	logger.Info("trying to generate tokens")
	key, err := a.privateKey()
	if err != nil {
		logger.Warn("failed to get private key", err.Error())
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	// Найти роли
	logger.Info("trying to find available roles")
	roles, err := a.roleProvider.UserRoles(ctx, token.UserId)
	if err != nil {
		logger.Warn("failed to find available roles", err.Error())
		return "", "", fmt.Errorf("%s: %w", op, err)
	}
	logger.Info("successfully find roles")

	// генерация токенов
	logger.Info("trying to create token")
	newAccessToken, newRefToken, err := jwtlib.NewTokens(token.UserId, roles, a.accessTTL, key)
	if err != nil {
		logger.Error("failed to generate new access token", err.Error())
		return "", "", fmt.Errorf("%s: %w", op, err)
	}
	logger.Info("successfully generated new tokens")

	// 3. сохранить новый токен в БД
	newHashToken := hashToken(newRefToken)
	err = a.tokenProvider.UpdateToken(ctx, newHashToken, token.UserId, time.Now().UTC().Add(a.refreshTTL))
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	// вернуть результат
	return newAccessToken, newRefToken, nil
}

func (a *Auth) AddRole(ctx context.Context, role string) ([]string, error) {
	const op = "sso.AddRole"
	logger := a.logger.With(slog.String("op", op))
	logger.Info("trying to add role")

	uid := ctx.Value("userId").(int64)
	err := a.roleProvider.AddRole(ctx, uid, role)
	if err != nil {
		logger.Error("failed to add role", err.Error())
		if errors.Is(err, storage.ErrRoleAlreadyExists) {
			return nil, ErrRoleAlreadyExists
		}
		if errors.Is(err, storage.ErrRoleDoesNotExist) {
			return nil, ErrRoleDoesNotExist
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	logger.Info("successfully add role")
	logger.Info("trying to find available roles")

	roles, err := a.roleProvider.UserRoles(ctx, uid)
	if err != nil {
		if errors.Is(err, storage.ErrRolesNotFound) {
			return nil, ErrUserRolesNotFound
		}
		logger.Error("failed to find available roles", err.Error())
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	logger.Info("successfully find available roles")
	return roles, nil

}
