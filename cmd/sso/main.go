package main

import (
	"AuthJWT/internal/app"
	"AuthJWT/internal/config"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// инициализировать объект конфига
	cnf := config.MustLoad()
	// логгер
	logger := initLogger(cnf.Env)
	if logger == nil {
		panic("logger is nil, check your configuration")
	}
	logger.Info("Start application")

	// инициализация приложения
	application := app.New(logger, &cnf.GRPC, &cnf.DB, cnf.AccessTokenTTL, cnf.RefreshTokenTTL)
	// запустить grpc сервер
	go application.GRPCServer.MustRun()

	// graceful shutdown
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)

	<-stopChan
	application.GRPCServer.Stop()
	logger.Info("Application stopped")
}

const (
	envlocal       = "local"
	envdevelopment = "develop"
	envproduction  = "prod"
)

func initLogger(envType string) *slog.Logger {
	var logger *slog.Logger

	switch envType {
	case envlocal:
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	case envdevelopment:
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	case envproduction:
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	return logger
}
