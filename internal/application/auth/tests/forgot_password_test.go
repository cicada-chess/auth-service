package auth_tests

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/application/auth"
	mock_user_service "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/user/mocks"
	pb "gitlab.mai.ru/cicada-chess/backend/user-service/pkg/user"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAuthService_ForgotPassword_UserNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock_user_service.NewMockUserServiceClient(ctrl)
	svc := auth.NewAuthService(mockUserService, nil)
	ctx := context.Background()
	request := &pb.ForgotPasswordRequest{Email: "@example.com"}
	mockUserService.EXPECT().ForgotPassword(ctx, request).Return(nil, status.Error(codes.NotFound, "user not found"))
	err := svc.ForgotPassword(ctx, "@example.com")
	assert.Equal(t, auth.ErrUserNotFound, err)
}

func TestAuthService_ForgotPassword_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock_user_service.NewMockUserServiceClient(ctrl)
	svc := auth.NewAuthService(mockUserService, nil)
	ctx := context.Background()
	request := &pb.ForgotPasswordRequest{Email: "@example.com"}
	mockUserService.EXPECT().ForgotPassword(ctx, request).Return(&pb.ForgotPasswordResponse{}, nil)
	err := svc.ForgotPassword(ctx, "@example.com")
	assert.NoError(t, err)
}
