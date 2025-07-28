package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

// функция для генерации токена доступа
func NewTokens(id int64, roles []string, accessDuration time.Duration, key *rsa.PrivateKey) (string, string, error) {
	accessToken := jwt.New(jwt.SigningMethodRS512)
	accessClaims := accessToken.Claims.(jwt.MapClaims)

	// сохраняем нужные данные
	accessClaims["uid"] = id
	accessClaims["roles"] = roles
	accessClaims["exp"] = time.Now().Add(accessDuration).Unix()

	accessTokenString, err := accessToken.SignedString(key)
	if err != nil {
		return "", "", err
	}

	refToken, err := generateRefreshToken()
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refToken, nil
}

func generateRefreshToken() (string, error) {
	bytes := make([]byte, 32, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
