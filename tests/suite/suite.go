package suite

import (
	"AuthJWT/internal/config"
	"context"
	sso "github.com/Ira11111/protos/gen/go/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"net"
	"strconv"
	"testing"
	"time"
)

const (
	grpcHost = "localhost"
)

type Suite struct {
	*testing.T // объект для взаимодействия с тестами
	Cfg        *config.Config
	AuthClient sso.AuthClient
}

func New(t *testing.T) (context.Context, *Suite) {
	t.Helper()   // чтобы при файле теста правильно формировался стек вызовов
	t.Parallel() // выполнение тестов параллельно

	cfg := config.MustLoadByPath("../config/tests.yaml")

	duration, err := time.ParseDuration(cfg.GRPC.Timeout)
	if err != nil {
		t.Fatalf("Ошибка парсинга времени: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), duration)

	t.Cleanup(func() {
		t.Helper()
		cancel()
	})

	conn, err := grpc.NewClient(
		net.JoinHostPort(grpcHost, strconv.Itoa(cfg.GRPC.Port)),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc serner connection failed %v", err)
	}

	return ctx, &Suite{
		T:          t,
		Cfg:        cfg,
		AuthClient: sso.NewAuthClient(conn),
	}
}
