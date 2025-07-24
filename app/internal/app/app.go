package app

import (
	"AuthJWT/app/internal/app/grpc"
	"AuthJWT/app/internal/services/auth"
	"AuthJWT/app/internal/storage/postgresql"
	"AuthJWT/app/pkg/config"
	"fmt"
	"log/slog"
	"time"
)

type App struct {
	GRPCServer  *grpcapp.App
	AuthService *auth.Auth
}

func New(logger *slog.Logger, port int, st *config.DBConfig, accessTTl time.Duration, refTTL time.Duration) *App {
	// Инициализация хранилища
	storage, err := postgresql.NewStorage(st)
	if err != nil {
		panic("failed to connect to database: " + err.Error())
	}
	// инициализация сервисного слоя
	fmt.Println("sso service")
	authService := auth.New(logger, storage, storage, accessTTl, refTTL) // инициализация обработчика
	grpcApp := grpcapp.NewApp(logger, authService, port)
	return &App{
		grpcApp,
		authService,
	}

}
