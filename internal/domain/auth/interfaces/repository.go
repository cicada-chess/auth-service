package interfaces

import (
	"context"

	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/user/entity"
)

type AuthRepository interface {
	GetUserByEmail(ctx context.Context, email string) (*entity.User, error)
	UpdateUserPassword(ctx context.Context, userID string, newPassword string) error
}
