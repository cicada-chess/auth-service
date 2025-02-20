package interfaces

import (
	"context"

	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/access/entity"
)

type AccessRepository interface {
	GetProtectedUrl(ctx context.Context, url string) (*entity.ProtectedUrl, error)
}
