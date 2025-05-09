package auth_tests

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/application/auth"
	authEntity "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/entity"
	mock_user_service "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/user/mocks"
	pb "gitlab.mai.ru/cicada-chess/backend/user-service/pkg/user"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAuthService_Me_UserNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	_ = os.Setenv("SECRET_KEY", "test_secret")

	mockUserService := mock_user_service.NewMockUserServiceClient(ctrl)
	svc := auth.NewAuthService(mockUserService, nil)
	ctx := context.Background()

	token, err := authEntity.GenerateAccessToken("404", 1)
	assert.NoError(t, err)

	mockUserService.EXPECT().GetUserById(ctx, &pb.GetUserByIdRequest{Id: "404"}).Return(nil, status.Error(codes.NotFound, "not found"))
	user, err := svc.Me(ctx, "Bearer "+token)
	assert.Nil(t, user)
	assert.Equal(t, auth.ErrUserNotFound, err)
}

func TestAuthService_Me_InternalServerError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	_ = os.Setenv("SECRET_KEY", "test_secret")

	mockUserService := mock_user_service.NewMockUserServiceClient(ctrl)
	svc := auth.NewAuthService(mockUserService, nil)
	ctx := context.Background()

	token, err := authEntity.GenerateAccessToken("500", 1)
	assert.NoError(t, err)

	mockUserService.EXPECT().GetUserById(ctx, &pb.GetUserByIdRequest{Id: "500"}).Return(nil, status.Error(codes.Internal, "internal"))
	user, err := svc.Me(ctx, "Bearer "+token)
	assert.Nil(t, user)
	assert.Equal(t, auth.ErrInternalServer, err)
}

func TestAuthService_Me_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	_ = os.Setenv("SECRET_KEY", "test_secret")

	mockUserService := mock_user_service.NewMockUserServiceClient(ctrl)
	svc := auth.NewAuthService(mockUserService, nil)
	ctx := context.Background()

	token, err := authEntity.GenerateAccessToken("42", 2)
	assert.NoError(t, err)

	now := time.Now()
	resp := &pb.GetUserByIdResponse{
		Id:        "42",
		Username:  "testuser",
		Email:     "test@example.com",
		Role:      2,
		Rating:    1500,
		CreatedAt: timestamppb.New(now),
		UpdatedAt: timestamppb.New(now),
		IsActive:  true,
	}
	mockUserService.EXPECT().GetUserById(ctx, &pb.GetUserByIdRequest{Id: "42"}).Return(resp, nil)
	user, err := svc.Me(ctx, "Bearer "+token)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "42", user.ID)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, 2, user.Role)
	assert.Equal(t, 1500, user.Rating)
	assert.True(t, user.IsActive)
}
