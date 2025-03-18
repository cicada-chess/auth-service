package access

import (
	"context"
	"fmt"

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

	if err := r.db.GetContext(ctx, &protectedUrl, query, url); err != nil {
		return nil, err
	}
	roles := make([]int, len(protectedUrl.Roles))
	for i, role := range protectedUrl.Roles {
		roles[i] = int(role)
	}
	fmt.Println(protectedUrl.Id, protectedUrl.Url, protectedUrl.Roles)
	protectedUrlEntity := entity.ProtectedUrl{
		Id:    protectedUrl.Id,
		Url:   protectedUrl.Url,
		Roles: roles,
	}
	fmt.Println(protectedUrlEntity.Id, protectedUrlEntity.Url, protectedUrlEntity.Roles)

	return &protectedUrlEntity, nil
}
