package access

import (
	"context"

	"github.com/jmoiron/sqlx"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/access/entity"
)

type accessRepository struct {
	db *sqlx.DB
}

func NewAuthRepository(db *sqlx.DB) *accessRepository {
	return &accessRepository{db: db}
}

func (r *accessRepository) GetProtectedUrl(ctx context.Context, url string) (*entity.ProtectedUrl, error) {
	return nil, nil
}
