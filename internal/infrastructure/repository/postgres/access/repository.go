package access

import "github.com/jmoiron/sqlx"

type accessRepository struct {
	db *sqlx.DB
}

func NewAuthRepository(db *sqlx.DB) *accessRepository {
	return &accessRepository{db: db}
}
