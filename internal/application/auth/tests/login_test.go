package auth_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/application/auth"
	mock_interfaces "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/mocks"
	userEntity "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/user/entity"
)

func TestAuthService_Login_InternalServerError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAuthRepo := mock_interfaces.NewMockAuthRepository(ctrl)
	svc := auth.NewAuthService(mockAuthRepo, nil, nil)
	ctx := context.Background()

	mockAuthRepo.EXPECT().GetUserByEmail(ctx, "repoError@example.com").Return(nil, auth.ErrInternalServer)
	token, err := svc.Login(ctx, "repoError@example.com", "pass")
	assert.Nil(t, token)
	assert.Equal(t, auth.ErrInternalServer, err)
}

func TestAuthService_Login_UserNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAuthRepo := mock_interfaces.NewMockAuthRepository(ctrl)
	svc := auth.NewAuthService(mockAuthRepo, nil, nil)
	ctx := context.Background()

	mockAuthRepo.EXPECT().GetUserByEmail(ctx, "nonexistent@example.com").Return(nil, nil)
	token, err := svc.Login(ctx, "nonexistent@example.com", "pass")
	assert.Nil(t, token)
	assert.Equal(t, auth.ErrInvalidCredentials, err)
}

func TestAuthService_Login_UserIsBlocked(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAuthRepo := mock_interfaces.NewMockAuthRepository(ctrl)
	svc := auth.NewAuthService(mockAuthRepo, nil, nil)
	ctx := context.Background()

	blockedUser := &userEntity.User{ID: "1", Email: "blocked@example.com", Password: "hash", IsActive: false}
	mockAuthRepo.EXPECT().GetUserByEmail(ctx, blockedUser.Email).Return(blockedUser, nil)
	token, err := svc.Login(ctx, blockedUser.Email, "pass")
	assert.Nil(t, token)
	assert.Equal(t, auth.ErrUserBlocked, err)
}

func TestAuthService_Login_InvalidPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAuthRepo := mock_interfaces.NewMockAuthRepository(ctrl)
	svc := auth.NewAuthService(mockAuthRepo, nil, nil)
	ctx := context.Background()

	activeUser := &userEntity.User{ID: "2", Email: "active@example.com", Password: "someHash", IsActive: true}
	mockAuthRepo.EXPECT().GetUserByEmail(ctx, activeUser.Email).Return(activeUser, nil)
	token, err := svc.Login(ctx, activeUser.Email, "wrongPass")
	assert.Nil(t, token)
	assert.Equal(t, auth.ErrInvalidCredentials, err)
}

func TestAuthService_Login_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAuthRepo := mock_interfaces.NewMockAuthRepository(ctrl)
	svc := auth.NewAuthService(mockAuthRepo, nil, nil)
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
	mockAuthRepo.EXPECT().GetUserByEmail(ctx, activeUser.Email).Return(activeUser, nil)

	token, err := svc.Login(ctx, activeUser.Email, plainPass)
	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.NotEmpty(t, token.AccessToken)
	assert.NotEmpty(t, token.RefreshToken)
}
