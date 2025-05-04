package interfaces

import (
	"context"

	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/entity"
	userEntity "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/user/entity"
)

type AuthService interface {
	Register(ctx context.Context, email string, username string, password string) (*string, error)
	Login(ctx context.Context, email string, password string) (*entity.Token, error)
	Check(ctx context.Context, tokenHeader string) error
	Refresh(ctx context.Context, refreshToken string) (*entity.Token, error)
	ForgotPassword(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, resetToken string, newPassword string) error
	Access(ctx context.Context, role int, url string) error
	Me(ctx context.Context, tokenHeader string) (*userEntity.User, error)
}
