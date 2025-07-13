package app

import (
	grpcapp "AuthJWT/internal/app/grpc"
	"AuthJWT/internal/config"
	"AuthJWT/internal/services/auth"
	"AuthJWT/internal/storage/postgresql"
	"fmt"
	"log/slog"
	"time"
)

type App struct {
	GRPCServer  *grpcapp.App
	AuthService *auth.Auth
}

func New(logger *slog.Logger, port int, st *config.DBConfig, token time.Duration) *App {
	// Инициализация хранилища
	storage, err := postgresql.NewStorage(st)
	if err != nil {
		panic("failed to connect to database: " + err.Error())
	}
	// инициализация сервисного слоя
	fmt.Println("sso service")
	authService := auth.New(logger, storage, storage, storage, token)

	// инициализация обработчика
	grpcApp := grpcapp.NewApp(logger, authService, port)
	return &App{
		grpcApp,
		authService,
	}

}
