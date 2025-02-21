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
	var protectedUrl entity.ProtectedUrl

	query := `SELECT id, url, roles FROM protected_urls WHERE url = $1`

	if err := r.db.GetContext(ctx, &protectedUrl, query, url); err != nil {
		return nil, err
	}

	return &protectedUrl, nil
}
