package auth_tests

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/application/auth"
	authEntity "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/entity"
	mock_user_service "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/user/mocks"
	pb "gitlab.mai.ru/cicada-chess/backend/user-service/pkg/user"
)

func TestAuthService_ResetPassword_InvalidToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock_user_service.NewMockUserServiceClient(ctrl)
	svc := auth.NewAuthService(mockUserService, nil, nil)
	ctx := context.Background()

	err := svc.ResetPassword(ctx, "invalid_token", "new_password")
	assert.Equal(t, auth.ErrTokenInvalidOrExpired, err)
}

func TestAuthService_ResetPassword_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock_user_service.NewMockUserServiceClient(ctrl)
	svc := auth.NewAuthService(mockUserService, nil, nil)
	ctx := context.Background()

	resetToken, err := authEntity.GenerateResetToken("1", 1)
	assert.NoError(t, err)
	request := &pb.UpdateUserPasswordRequest{Id: "1", Password: "new_password"}
	response := &pb.UpdateUserPasswordResponse{Status: "success"}
	mockUserService.EXPECT().UpdateUserPassword(ctx, request).Return(response, nil)
	err = svc.ResetPassword(ctx, resetToken, "new_password")
	assert.NoError(t, err)
}
