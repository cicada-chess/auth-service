package auth_tests

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/application/auth"
	userEntity "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/user/entity"
	mock_user_service "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/user/mocks"
	pb "gitlab.mai.ru/cicada-chess/backend/user-service/pkg/user"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAuthService_Login_InternalServerError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock_user_service.NewMockUserServiceClient(ctrl)
	svc := auth.NewAuthService(mockUserService, nil, nil)
	ctx := context.Background()
	request := &pb.GetUserByEmailRequest{Email: "repoError@example.com"}
	mockUserService.EXPECT().GetUserByEmail(ctx, request).Return(nil, status.Error(codes.Internal, "internal server error"))
	token, err := svc.Login(ctx, "repoError@example.com", "password")
	assert.Nil(t, token)
	assert.Equal(t, auth.ErrInternalServer, err)
}

func TestAuthService_Login_UserNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock_user_service.NewMockUserServiceClient(ctrl)
	svc := auth.NewAuthService(mockUserService, nil, nil)
	ctx := context.Background()
	request := &pb.GetUserByEmailRequest{Email: "nonexistent@example.com"}
	mockUserService.EXPECT().GetUserByEmail(ctx, request).Return(nil, status.Error(codes.NotFound, "user not found"))
	token, err := svc.Login(ctx, request.Email, "password")
	assert.Nil(t, token)
	assert.Equal(t, auth.ErrUserNotFound, err)
}

func TestAuthService_Login_UserIsBlocked(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockUserService := mock_user_service.NewMockUserServiceClient(ctrl)
	svc := auth.NewAuthService(mockUserService, nil, nil)
	ctx := context.Background()
	request := &pb.GetUserByEmailRequest{Email: "blocked@example.com"}
	response := &pb.GetUserByEmailResponse{Id: "1", Email: "blocked@example.com", Password: "hash_password", IsActive: false}
	mockUserService.EXPECT().GetUserByEmail(ctx, request).Return(response, nil)
	token, err := svc.Login(ctx, request.Email, "pass")
	assert.Nil(t, token)
	assert.Equal(t, auth.ErrUserBlocked, err)
}

func TestAuthService_Login_InvalidPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock_user_service.NewMockUserServiceClient(ctrl)
	svc := auth.NewAuthService(mockUserService, nil, nil)
	ctx := context.Background()
	request := &pb.GetUserByEmailRequest{Email: "activeUser@example.com"}
	response := &pb.GetUserByEmailResponse{Id: "1", Email: "activeUser@example.com", Password: "hash_password", IsActive: true}
	mockUserService.EXPECT().GetUserByEmail(ctx, request).Return(response, nil)
	token, err := svc.Login(ctx, request.Email, "wrongPass")
	assert.Nil(t, token)
	assert.Equal(t, auth.ErrInvalidCredentials, err)
}

func TestAuthService_Login_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock_user_service.NewMockUserServiceClient(ctrl)
	svc := auth.NewAuthService(mockUserService, nil, nil)
	ctx := context.Background()

	plainPass := "somePass"
	hashedPass, err := userEntity.HashPassword(plainPass)
	assert.NoError(t, err)

	activeUser := &userEntity.User{
		ID:       "3",
		Email:    "ok@example.com",
		Password: hashedPass,
		Role:     1,
		IsActive: true,
	}
	request := &pb.GetUserByEmailRequest{Email: activeUser.Email}
	response := &pb.GetUserByEmailResponse{
		Id:       activeUser.ID,
		Email:    activeUser.Email,
		Password: activeUser.Password,
		Role:     int32(activeUser.Role),
		IsActive: activeUser.IsActive,
	}
	mockUserService.EXPECT().GetUserByEmail(ctx, request).Return(response, nil)

	token, err := svc.Login(ctx, activeUser.Email, plainPass)
	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.NotEmpty(t, token.AccessToken)
	assert.NotEmpty(t, token.RefreshToken)
}
