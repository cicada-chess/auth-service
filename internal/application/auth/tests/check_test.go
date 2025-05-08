package auth_tests

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	auth "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/application/auth"
	authEntity "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/entity"
)

func TestAuthService_Check_NoBearerPrefix(t *testing.T) {
	svc := auth.NewAuthService(nil, nil)
	err := svc.Check(context.Background(), "InvalidTokenHeader")
	assert.Equal(t, auth.ErrTokenInvalidOrExpired, err)
}

func TestAuthService_Check_EmptyBearerToken(t *testing.T) {
	svc := auth.NewAuthService(nil, nil)
	err := svc.Check(context.Background(), "Bearer ")
	assert.Equal(t, auth.ErrTokenInvalidOrExpired, err)
}

func TestAuthService_Check_InvalidToken(t *testing.T) {
	svc := auth.NewAuthService(nil, nil)
	_ = os.Setenv("SECRET_KEY", "test_secret")
	err := svc.Check(context.Background(), "Bearer invalid_token_string")
	assert.Equal(t, auth.ErrTokenInvalidOrExpired, err)
}

func TestAuthService_Check_ValidToken(t *testing.T) {
	svc := auth.NewAuthService(nil, nil)
	_ = os.Setenv("SECRET_KEY", "test_secret")

	validToken, errGen := authEntity.GenerateAccessToken("12", 1)
	assert.NoError(t, errGen)

	err := svc.Check(context.Background(), "Bearer "+validToken)
	assert.NoError(t, err)
}
