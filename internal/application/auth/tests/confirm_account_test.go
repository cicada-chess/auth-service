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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAuthService_ConfirmAccount_UserNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock_user_service.NewMockUserServiceClient(ctrl)
	svc := auth.NewAuthService(mockUserService, nil)
	ctx := context.Background()

	token, err := authEntity.GenerateAccountConfirmationToken("404")
	assert.NoError(t, err)

	mockUserService.EXPECT().ConfirmAccount(ctx, &pb.ConfirmAccountRequest{Id: "404"}).Return(nil, status.Error(codes.NotFound, "not found"))
	err = svc.ConfirmAccount(ctx, token)
	assert.Equal(t, auth.ErrUserNotFound, err)
}

func TestAuthService_ConfirmAccount_InvalidToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock_user_service.NewMockUserServiceClient(ctrl)
	svc := auth.NewAuthService(mockUserService, nil)
	ctx := context.Background()

	err := svc.ConfirmAccount(ctx, "invalid_token")
	assert.Equal(t, auth.ErrTokenInvalidOrExpired, err)
}

func TestAuthService_ConfirmAccount_InternalServerError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock_user_service.NewMockUserServiceClient(ctrl)
	svc := auth.NewAuthService(mockUserService, nil)
	ctx := context.Background()

	token, err := authEntity.GenerateAccountConfirmationToken("500")
	assert.NoError(t, err)

	mockUserService.EXPECT().ConfirmAccount(ctx, &pb.ConfirmAccountRequest{Id: "500"}).Return(nil, status.Error(codes.Internal, "internal"))
	err = svc.ConfirmAccount(ctx, token)
	assert.Equal(t, auth.ErrInternalServer, err)
}

func TestAuthService_ConfirmAccount_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock_user_service.NewMockUserServiceClient(ctrl)
	svc := auth.NewAuthService(mockUserService, nil)
	ctx := context.Background()

	token, err := authEntity.GenerateAccountConfirmationToken("1")
	assert.NoError(t, err)

	mockUserService.EXPECT().ConfirmAccount(ctx, &pb.ConfirmAccountRequest{Id: "1"}).Return(&pb.ConfirmAccountResponse{}, nil)
	err = svc.ConfirmAccount(ctx, token)
	assert.NoError(t, err)
}
