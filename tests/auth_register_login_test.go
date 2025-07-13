package tests

import (
	"AuthJWT/tests/suite"
	sso "github.com/Ira11111/protos/gen/go/sso"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

const (
	emptyAppID     = 0
	appId          = 1
	appSecret      = "test-secret"
	passDefaultLen = 10
)

func TestRegisterLogin_Login_HappyPath(t *testing.T) {
	ctx, s := suite.New(t)

	email := gofakeit.Email()
	pass := getRandomPass()

	respReg, err := s.AuthClient.Register(
		ctx,
		&sso.RegisterRequest{
			Email:    email,
			Password: pass,
		},
	)
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetUserId())

	respLogin, err := s.AuthClient.Login(
		ctx,
		&sso.LoginRequest{
			Email:    email,
			Password: pass,
			AppId:    appId,
		},
	)
	require.NoError(t, err)
	loginTime := time.Now()

	assert.NotEmpty(t, respLogin.Token)

	tokenParsed, err := jwt.Parse(respLogin.Token, func(token *jwt.Token) (interface{}, error) {
		return []byte(appSecret), nil
	})
	require.NoError(t, err)
	claims, ok := tokenParsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	require.Equal(t, appId, int(claims["app_id"].(float64)))
	require.Equal(t, email, claims["email"].(string))
	require.Equal(t, respReg.GetUserId(), int64(claims["uid"].(float64)))

	const delta = time.Second
	assert.InDelta(t, loginTime.Add(s.Cfg.TokenTTL).Unix(), claims["exp"].(float64), float64(delta))

}

func getRandomPass() string {
	return gofakeit.Password(true, true, true, true, true, passDefaultLen)
}
