package auth

import (
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type authRepository struct {
	db *sqlx.DB
}

func NewAuthRepository(db *sqlx.DB) *authRepository {
	return &authRepository{db: db}
}
