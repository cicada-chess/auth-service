package entity

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	AccessTokenTTL         = 3600 * time.Second
	RefreshTokenTTL        = 7 * 24 * 3600 * time.Second
	ResetPasswordTokenTTL  = 30 * 60 * time.Second
	AccountConfirmationTTL = 30 * 60 * time.Second
)

type TokenType string

const (
	AccountConfirmation TokenType = "account_confirmation"
	PasswordReset       TokenType = "password_reset"
)

var ErrTokenInvalidOrExpired = errors.New("token invalid or expired")

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

func ValidateToken(tokenString string, tokenType TokenType) (*string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrTokenInvalidOrExpired
		}
		return []byte(os.Getenv("SECRET_KEY")), nil
	})
	if err != nil || !token.Valid {
		return nil, ErrTokenInvalidOrExpired
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		return nil, ErrTokenInvalidOrExpired
	}

	expires_at, ok := claims["expires_at"].(float64)
	if !ok || expires_at < float64(time.Now().Unix()) {
		return nil, ErrTokenInvalidOrExpired
	}

	token_type, ok := claims["token_type"].(string)
	if !ok || token_type != string(tokenType) {
		return nil, ErrTokenInvalidOrExpired
	}

	userId, ok := claims["userId"].(string)
	if !ok {
		return nil, ErrTokenInvalidOrExpired
	}
	return &userId, nil
}
