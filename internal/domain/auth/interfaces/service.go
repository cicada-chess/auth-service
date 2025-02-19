package interfaces

import (
	"context"

	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/entity"
)

type AuthService interface {
	Login(ctx context.Context, email string, password string) (*entity.Token, error)
	Check(ctx context.Context, accessToken string) error
	Refresh(ctx context.Context, refreshToken string) (*entity.Token, error)
}
