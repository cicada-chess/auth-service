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
	AccessToken         TokenType = "access"
	RefreshToken        TokenType = "refresh"
)

var ErrTokenInvalidOrExpired = errors.New("token is invalid or expired")

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
		"token_type": string(AccessToken),
		"expires_at": time.Now().Add(AccessTokenTTL).Unix(),
	})

	return token.SignedString([]byte(os.Getenv("SECRET_KEY")))
}

func GenerateRefreshToken(userId string, Role int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":    userId,
		"role":       Role,
		"token_type": string(RefreshToken),
		"expires_at": time.Now().Add(RefreshTokenTTL).Unix(),
	})

	return token.SignedString([]byte(os.Getenv("SECRET_KEY")))
}

func GeneratePasswordResetToken(userId string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":    userId,
		"token_type": string(PasswordReset),
		"expires_at": time.Now().Add(ResetPasswordTokenTTL).Unix(),
	})

	return token.SignedString([]byte(os.Getenv("SECRET_KEY")))
}

func GenerateAccountConfirmationToken(userId string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":    userId,
		"token_type": string(AccountConfirmation),
		"expires_at": time.Now().Add(AccountConfirmationTTL).Unix(),
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

func ValidateToken(tokenString string, tokenType TokenType) (*jwt.MapClaims, error) {
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

	return &claims, err
}

func GetUserIdFromToken(tokenString string, tokenType TokenType) (*string, error) {
	claims, err := ValidateToken(tokenString, tokenType)
	if err != nil {
		return nil, err
	}

	userId, ok := (*claims)["user_id"].(string)
	if !ok {
		return nil, ErrTokenInvalidOrExpired
	}
	return &userId, nil
}

func GetRoleFromToken(tokenString string, tokenType TokenType) (int, error) {
	claims, err := ValidateToken(tokenString, tokenType)
	if err != nil {
		return 0, err
	}

	role, ok := (*claims)["role"].(float64)
	if !ok {
		return 0, ErrTokenInvalidOrExpired
	}
	return int(role), nil
}
