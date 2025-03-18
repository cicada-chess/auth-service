package auth_tests

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/application/auth"
	mock_sender "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/application/sender/mocks"
	mock_user_service "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/user/mocks"
	pb "gitlab.mai.ru/cicada-chess/backend/user-service/pkg/user"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAuthService_ForgotPassword_UserNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock_user_service.NewMockUserServiceClient(ctrl)
	svc := auth.NewAuthService(mockUserService, nil, nil)
	ctx := context.Background()
	request := &pb.GetUserByEmailRequest{Email: ""}
	mockUserService.EXPECT().GetUserByEmail(ctx, request).Return(nil, status.Error(codes.NotFound, "user not found"))
	err := svc.ForgotPassword(ctx, "")
	assert.Equal(t, auth.ErrUserNotFound, err)

}

func TestAuthService_ForgotPassword_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock_user_service.NewMockUserServiceClient(ctrl)
	mockEmailSender := mock_sender.NewMockEmailSender(ctrl)
	svc := auth.NewAuthService(mockUserService, nil, mockEmailSender)
	ctx := context.Background()
	request := &pb.GetUserByEmailRequest{Email: "@example.com"}
	response := &pb.GetUserByEmailResponse{Id: "1", Email: "@example.com", Password: "hash", IsActive: true}
	mockUserService.EXPECT().GetUserByEmail(ctx, request).Return(response, nil)
	mockEmailSender.EXPECT().SendResetPasswordEmail("@example.com", gomock.Any()).Return(nil)
	err := svc.ForgotPassword(ctx, "@example.com")
	assert.NoError(t, err)
}
