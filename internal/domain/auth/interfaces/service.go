package interfaces

import (
	"context"

	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/entity"
)

type AuthService interface {
	Login(ctx context.Context, email string, password string) (*entity.Token, error)
	Check(ctx context.Context, tokenHeader string) error
	Refresh(ctx context.Context, refreshToken string) (*entity.Token, error)
	ForgotPassword(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, resetToken string, newPassword string) error
	Access(ctx context.Context, role int, url string) error
}

type EmailSender interface {
	SendResetPasswordEmail(email, token string) error
}
