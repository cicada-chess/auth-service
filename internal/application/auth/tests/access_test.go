package auth_tests

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/application/auth"
	accessEntity "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/access/entity"
	mock_interfaces "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/access/mocks"
)

func TestAuthService_Access_PermissionGranted(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAccessRepo := mock_interfaces.NewMockAccessRepository(ctrl)
	svc := auth.NewAuthService(nil, mockAccessRepo, nil)
	ctx := context.Background()

	protectedUrl := &accessEntity.ProtectedUrl{
		Id:    "1",
		Url:   "/protected",
		Roles: []int{1, 2},
	}

	mockAccessRepo.EXPECT().GetProtectedUrl(ctx, "/protected").Return(protectedUrl, nil)
	err := svc.Access(ctx, 1, "/protected")
	assert.NoError(t, err)
}

func TestAuthService_Access_PermissionDenied(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAccessRepo := mock_interfaces.NewMockAccessRepository(ctrl)
	svc := auth.NewAuthService(nil, mockAccessRepo, nil)
	ctx := context.Background()

	protectedUrl := &accessEntity.ProtectedUrl{
		Id:    "1",
		Url:   "/protected",
		Roles: []int{1, 2},
	}

	mockAccessRepo.EXPECT().GetProtectedUrl(ctx, "/protected").Return(protectedUrl, nil)
	err := svc.Access(ctx, 3, "/protected")
	assert.Equal(t, auth.ErrPermissionDenied, err)
}

func TestAuthService_Access_UrlNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAccessRepo := mock_interfaces.NewMockAccessRepository(ctrl)
	svc := auth.NewAuthService(nil, mockAccessRepo, nil)
	ctx := context.Background()

	mockAccessRepo.EXPECT().GetProtectedUrl(ctx, "/nonexistent").Return(nil, auth.ErrUrlNotFound)
	err := svc.Access(ctx, 1, "/nonexistent")
	assert.Equal(t, auth.ErrUrlNotFound, err)
}
