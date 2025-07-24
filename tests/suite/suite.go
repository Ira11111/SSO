package suite

import (
	"AuthJWT/app/pkg/config"
	"context"
	sso "github.com/Ira11111/protos/v3/gen/go/sso"
	"github.com/joho/godotenv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"net"
	"os"
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

	if err := godotenv.Load("../.env.test"); err != nil {
		panic("Error loading .env.test file")
	}
	var res string
	res = os.Getenv("CONFIG_PATH")
	if res == "" {
		panic("CONFIG_PATH must be set")
	}

	cfg := config.MustLoadByPath(res)

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
