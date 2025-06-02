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

func TestAuthService_Register_AlreadyExists(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock_user_service.NewMockUserServiceClient(ctrl)
	svc := auth.NewAuthService(mockUserService, nil)
	ctx := context.Background()

	req := &pb.RegisterUserRequest{
		Email:    "exists@example.com",
		Username: "exists",
		Password: "password",
		IsActive: false,
	}
	mockUserService.EXPECT().RegisterUser(ctx, req).Return(nil, status.Error(codes.AlreadyExists, "already exists"))
	id, err := svc.Register(ctx, "exists@example.com", "exists", "password")
	assert.Nil(t, id)
	assert.Equal(t, auth.ErrAlreadyExists, err)
}

func TestAuthService_Register_InvalidCredentials(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock_user_service.NewMockUserServiceClient(ctrl)
	svc := auth.NewAuthService(mockUserService, nil)
	ctx := context.Background()

	req := &pb.RegisterUserRequest{
		Email:    "bademail",
		Username: "",
		Password: "",
		IsActive: false,
	}
	mockUserService.EXPECT().RegisterUser(ctx, req).Return(nil, status.Error(codes.InvalidArgument, "invalid"))
	id, err := svc.Register(ctx, "bademail", "", "")
	assert.Nil(t, id)
	assert.Equal(t, auth.ErrInvalidCredentials, err)
}

func TestAuthService_Register_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock_user_service.NewMockUserServiceClient(ctrl)
	svc := auth.NewAuthService(mockUserService, nil)
	ctx := context.Background()

	req := &pb.RegisterUserRequest{
		Email:    "test@example.com",
		Username: "testuser",
		Password: "password",
		IsActive: false,
	}
	resp := &pb.RegisterUserResponse{Id: "123"}
	mockUserService.EXPECT().RegisterUser(ctx, req).Return(resp, nil)
	id, err := svc.Register(ctx, "test@example.com", "testuser", "password")
	assert.NoError(t, err)
	assert.NotNil(t, id)
	assert.Equal(t, "123", *id)
}
