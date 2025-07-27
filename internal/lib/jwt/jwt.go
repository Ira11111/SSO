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

//func ValidateToken(tokenString string) (*jwt.Token, error) {
//	// валидируем токен проверяя корректность подписи
//	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
//		// реализуем функцию для получения публичного ключа
//		block, _ := pem.Decode([]byte(os.Getenv("JWT_PUBLIC_KEY")))
//		if block == nil {
//			return nil, fmt.Errorf("failed to parse PEM block")
//		}
//		pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
//		if err != nil {
//			return nil, err
//		}
//		return pubKey, nil
//	})
//
//	if err != nil {
//		return nil, err
//	}
//	if !token.Valid {
//		return nil, fmt.Errorf("invalid token")
//	}
//	return token, nil
//}
//
//func ParseToken(tokenString string) (int64, error) {
//	token, err := ValidateToken(tokenString)
//	if err != nil {
//		return 0, err
//	}
//
//	claims, ok := token.Claims.(jwt.MapClaims)
//	if !ok {
//		return 0, errors.New("invalid claims format")
//	}
//
//	// Получаем uid
//	uid, ok := claims["uid"].(float64)
//	if !ok {
//		return 0, errors.New("uid not found or invalid type")
//	}
//
//	return int64(uid), nil
//
//}
