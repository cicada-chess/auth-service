package access

import (
	"context"
	"database/sql"

	"github.com/jmoiron/sqlx"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/access/entity"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/infrastructure/repository/postgres/dto"
)

type accessRepository struct {
	db *sqlx.DB
}

func NewAccessRepository(db *sqlx.DB) *accessRepository {
	return &accessRepository{db: db}
}

func (r *accessRepository) GetProtectedUrl(ctx context.Context, url string) (*entity.ProtectedUrl, error) {
	var protectedUrl dto.ProtectedUrl

	query := `SELECT id, url, roles FROM protected_urls WHERE url = $1`

	err := r.db.Get(&protectedUrl, query, url)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	roles := make([]int, len(protectedUrl.Roles))
	for i, role := range protectedUrl.Roles {
		roles[i] = int(role)
	}

	protectedUrlEntity := entity.ProtectedUrl{
		Id:    protectedUrl.Id,
		Url:   protectedUrl.Url,
		Roles: roles,
	}

	return &protectedUrlEntity, nil
}
