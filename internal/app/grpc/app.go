package grpcapp

import (
	authGRPC "AuthJWT/internal/grpc/auth"
	"AuthJWT/internal/services/auth"
	"fmt"
	i "github.com/Ira11111/go-interceptors/interceptors"
	"google.golang.org/grpc"
	"log/slog"
	"net"
)

type App struct {
	logger *slog.Logger
	server *grpc.Server
	port   int
}

func NewApp(logger *slog.Logger, authService *auth.Auth, port int, key string) *App {
	interceptor := i.NewAuthInterceptor(key)
	gRPCServer := grpc.NewServer(
		grpc.UnaryInterceptor(interceptor.JWTClaims()),
	)
	authGRPC.Register(gRPCServer, authService)
	return &App{
		logger: logger,
		server: gRPCServer,
		port:   port,
	}
}

func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

func (a *App) Run() error {
	const op = "grpcapp.Run"
	log := a.logger.With(
		slog.String("op", op),
		slog.Int("port", a.port),
	)
	log.Info("starting gRPC server")
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	log.Info("gRPC server running on", slog.String("address", listener.Addr().String()))

	if err := a.server.Serve(listener); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil

}

func (a *App) Stop() {
	const op = "grpcapp.Stop"
	a.logger.With(slog.String("op", op)).Info("stopping gRPC server", slog.Int("port", a.port))
	a.server.GracefulStop()
}
