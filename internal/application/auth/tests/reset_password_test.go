package auth_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/application/auth"
	authEntity "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/entity"
	mock_interfaces "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/mocks"
)

func TestAuthService_ResetPassword_InvalidToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAuthRepo := mock_interfaces.NewMockAuthRepository(ctrl)
	svc := auth.NewAuthService(mockAuthRepo, nil, nil)
	ctx := context.Background()

	err := svc.ResetPassword(ctx, "invalid_token", "new_password")
	assert.Equal(t, auth.ErrTokenInvalidOrExpired, err)
}

func TestAuthService_ResetPassword_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAuthRepo := mock_interfaces.NewMockAuthRepository(ctrl)
	svc := auth.NewAuthService(mockAuthRepo, nil, nil)
	ctx := context.Background()

	resetToken, err := authEntity.GenerateResetToken("1", 1)
	assert.NoError(t, err)

	mockAuthRepo.EXPECT().UpdateUserPassword(ctx, "1", "new_password").Return(nil)
	err = svc.ResetPassword(ctx, resetToken, "new_password")
	assert.NoError(t, err)
}
