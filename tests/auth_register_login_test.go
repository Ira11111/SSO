package tests

import (
	"AuthJWT/tests/suite"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	sso "github.com/Ira11111/protos/v3/gen/go/sso"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

const (
	passDefaultLen = 10
)

func TestRegisterLogin_Login_HappyPath(t *testing.T) {
	ctx, s := suite.New(t)

	email := gofakeit.Email()
	pass := getRandomPass()

	respReg, err := s.AuthClient.Register(
		ctx,
		&sso.AuthRequest{
			Email:    email,
			Password: pass,
		},
	)
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetUserId())

	respLogin, err := s.AuthClient.Login(
		ctx,
		&sso.AuthRequest{
			Email:    email,
			Password: pass,
		},
	)
	require.NoError(t, err)
	loginTime := time.Now()

	assert.NotEmpty(t, respLogin.AccessToken)
	assert.NotEmpty(t, respLogin.RefreshToken)

	tokenParsed, err := jwt.Parse(respLogin.AccessToken, func(token *jwt.Token) (interface{}, error) {
		block, _ := pem.Decode([]byte(os.Getenv("JWT_PUBLIC_KEY")))
		if block == nil {
			return nil, fmt.Errorf("failed to parse PEM block")
		}
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return pubKey, nil
	})
	require.NoError(t, err)
	claims, ok := tokenParsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	require.Equal(t, respReg.GetUserId(), int64(claims["uid"].(float64)))

	const delta = time.Second
	assert.InDelta(t, loginTime.Add(s.Cfg.AccessTokenTTL).Unix(), claims["exp"].(float64), float64(delta))

}

func getRandomPass() string {
	return gofakeit.Password(true, true, true, true, true, passDefaultLen)
}
