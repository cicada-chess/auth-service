package user

import (
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/user/interfaces"
)

type authService struct {
	repo interfaces.AuthRepository
}

func NewAuthService(repo interfaces.AuthRepository) interfaces.AuthService {
	return &authService{
		repo: repo,
	}
}
