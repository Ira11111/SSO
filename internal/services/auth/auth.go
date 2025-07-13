package auth

import (
	"AuthJWT/internal/domain/models"
	"AuthJWT/internal/lib/jwt"
	"AuthJWT/internal/storage"
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"time"
)

var (
	// это ошибки которые может видеть хэндлер
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidAppId       = errors.New("invalid app id")
	ErrUserAlreadyExists  = errors.New("user already Exists")
	ErrUserNotFound       = errors.New("user not found")
)

type Auth struct {
	// структура описывающая сервис аутентификации
	logger       *slog.Logger
	userSaver    UserSaver
	userProvider UserProvider
	appProvider  AppProvider
	tockenTTL    time.Duration
}

type UserSaver interface {
	SaveUser(
		ctx context.Context,
		email string,
		passHash []byte,
	) (int64, error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, uid int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appId int32) (models.App, error)
}

// конструктор, создает экземпляр сервиса аунтефикации
func New(log *slog.Logger, UserSaver UserSaver, UserProvider UserProvider, AppProvider AppProvider, tockenTTL time.Duration) *Auth {
	return &Auth{
		logger:       log,
		userSaver:    UserSaver,
		userProvider: UserProvider,
		appProvider:  AppProvider,
		tockenTTL:    tockenTTL,
	}
}

// функция login проверяет, зарегистрирован ли пользователь в системе
// если пользователя не существует или введен неверный пароль - возвращается ошибка
func (a *Auth) Login(ctx context.Context, email string, password string, appID int32) (string, error) {
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
			return "", fmt.Errorf("%s: %w", op)
		}
		log.Warn("failed to login user", op, err.Error())
		return "", fmt.Errorf("%s: %w", op, err)
	}

	// проверяем пароль
	if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password)); err != nil {
		log.Warn("invalid credentials", op, ErrInvalidCredentials)
		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	// получаем приложение
	// для создания токена используется ключ конкретного приложения
	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		log.Warn("failed to find app", op, ErrInvalidAppId)
		return "", fmt.Errorf("%s: %w", op, ErrInvalidAppId)
	}

	log.Info("user successfully logged in")
	// создаем токен
	log.Info("trying to create token")
	tocken, err := jwt.NewToken(user, app, a.tockenTTL)
	if err != nil {
		log.Warn("failed to generate token", op, err.Error())
		return "", fmt.Errorf("%s: %w", op, err)
	}
	log.Info("successfully generated token")
	return tocken, nil
}

// функция регистрирует нового пользователя в системе
// если переданные данные невалидны - возвращается ошибка
func (a *Auth) RegisterNewUser(
	ctx context.Context,
	email string,
	password string,
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
	uid, err := a.userSaver.SaveUser(ctx, email, passHash)
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

// функция проверяет, есть ли у пользователя с переданным идентификатором права администратора
func (a *Auth) IsAdmin(ctx context.Context, uid int64) (bool, error) {
	const op = "sso.IsAdmin"
	log := a.logger.With(slog.String("op", op))
	log.Info("trying to check user admin")

	isAdmin, err := a.userProvider.IsAdmin(ctx, uid)
	if err != nil {
		log.Error("failed to check user admin", slog.String("op", op))
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", op, err.Error())
			return false, ErrUserNotFound
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}
	log.Info("successfully check user admin", slog.String("op", op))
	return isAdmin, nil
}
