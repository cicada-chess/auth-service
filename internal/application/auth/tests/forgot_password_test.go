package auth_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/application/auth"
	mock_sender "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/application/sender/mocks"
	mock_interfaces "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/mocks"
	userEntity "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/user/entity"
)

func TestAuthService_ForgotPassword_UserNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAuthRepo := mock_interfaces.NewMockAuthRepository(ctrl)
	svc := auth.NewAuthService(mockAuthRepo, nil, nil)
	ctx := context.Background()

	mockAuthRepo.EXPECT().GetUserByEmail(ctx, "").Return(nil, auth.ErrUserNotFound)
	err := svc.ForgotPassword(ctx, "")
	assert.Equal(t, auth.ErrUserNotFound, err)

}

func TestAuthService_ForgotPassword_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAuthRepo := mock_interfaces.NewMockAuthRepository(ctrl)
	mockEmailSender := mock_sender.NewMockEmailSender(ctrl)
	svc := auth.NewAuthService(mockAuthRepo, mockEmailSender, nil)
	ctx := context.Background()

	mockAuthRepo.EXPECT().GetUserByEmail(ctx, "@example.com").Return(&userEntity.User{ID: "1", Email: "@example.com", Password: "hash", IsActive: true}, nil)
	mockEmailSender.EXPECT().SendResetPasswordEmail("@example.com", gomock.Any()).Return(nil)
	err := svc.ForgotPassword(ctx, "@example.com")
	assert.NoError(t, err)
}
