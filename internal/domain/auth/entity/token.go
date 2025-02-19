package entity

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	AccessTokenTTL        = 1 * time.Hour
	RefreshTokenTTL       = 7 * 24 * time.Hour
	ResetPasswordTokenTTL = 30 * time.Minute
)

type Token struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
}

func GenerateAccessToken(userId string, Role int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":    userId,
		"role":       Role,
		"expires_at": time.Now().Add(AccessTokenTTL).Unix(),
	})

	return token.SignedString([]byte(os.Getenv("SECRET_KEY")))
}

func GenerateRefreshToken(userId string, Role int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":    userId,
		"role":       Role,
		"expires_at": time.Now().Add(RefreshTokenTTL).Unix(),
	})

	return token.SignedString([]byte(os.Getenv("SECRET_KEY")))
}

func GenerateResetToken(userId string, Role int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":    userId,
		"role":       Role,
		"expires_at": time.Now().Add(ResetPasswordTokenTTL).Unix(),
	})

	return token.SignedString([]byte(os.Getenv("SECRET_KEY")))
}
