package entity

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	AccessTokenTTL        = 3600 * time.Second
	RefreshTokenTTL       = 7 * 24 * 3600 * time.Second
	ResetPasswordTokenTTL = 30 * 60 * time.Second
)

type Token struct {
	AccessToken      string
	RefreshToken     string
	TokenType        string
	AccessExpiresIn  int
	RefreshExpiresIn int
}

func GenerateAccessToken(userId string, Role int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":    userId,
		"role":       Role,
		"token_type": "access",
		"expires_at": time.Now().Add(AccessTokenTTL).Unix(),
	})

	return token.SignedString([]byte(os.Getenv("SECRET_KEY")))
}

func GenerateRefreshToken(userId string, Role int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":    userId,
		"role":       Role,
		"token_type": "refresh",
		"expires_at": time.Now().Add(RefreshTokenTTL).Unix(),
	})

	return token.SignedString([]byte(os.Getenv("SECRET_KEY")))
}

func GenerateResetToken(userId string, Role int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":    userId,
		"role":       Role,
		"token_type": "reset",
		"expires_at": time.Now().Add(ResetPasswordTokenTTL).Unix(),
	})

	return token.SignedString([]byte(os.Getenv("SECRET_KEY")))
}

func GenerateToken(userId string, Role int) (*Token, error) {
	token := &Token{}
	accessToken, err := GenerateAccessToken(userId, Role)
	if err != nil {
		return nil, err
	}
	token.AccessToken = accessToken

	refreshToken, err := GenerateRefreshToken(userId, Role)
	if err != nil {
		return nil, err
	}

	token.RefreshToken = refreshToken
	token.TokenType = "Bearer"
	token.AccessExpiresIn = int(AccessTokenTTL.Seconds())
	token.RefreshExpiresIn = int(RefreshTokenTTL.Seconds())
	return token, nil
}
