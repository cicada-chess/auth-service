package auth_tests

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	auth "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/application/auth"
	authEntity "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/entity"
)

func TestAuthService_Refresh_InvalidToken(t *testing.T) {
	svc := auth.NewAuthService(nil, nil)
	_ = os.Setenv("SECRET_KEY", "test_secret")

	token, err := svc.Refresh(context.Background(), "invalid_token_string")
	assert.Equal(t, auth.ErrTokenInvalidOrExpired, err)
	assert.Nil(t, token)
}

func TestAuthService_Refresh_ValidToken(t *testing.T) {
	svc := auth.NewAuthService(nil, nil)
	_ = os.Setenv("SECRET_KEY", "test_secret")

	validToken, errGen := authEntity.GenerateRefreshToken("12", 1)
	assert.NoError(t, errGen)

	token, err := svc.Refresh(context.Background(), validToken)
	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.NotEmpty(t, token.AccessToken)

	err = svc.Check(context.Background(), "Bearer "+token.AccessToken)
	assert.NoError(t, err)

}
