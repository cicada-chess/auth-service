package auth

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	auth "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/entity"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/interfaces"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/user/entity"
)

var (
	ErrInvalidCredentials    = errors.New("invalid credentials")
	ErrUserBlocked           = errors.New("user is blocked")
	ErrTokenInvalidOrExpired = errors.New("token is invalid or expired")
)

type authService struct {
	repo interfaces.AuthRepository
}

func NewAuthService(repo interfaces.AuthRepository) interfaces.AuthService {
	return &authService{
		repo: repo,
	}
}

func (s *authService) Login(ctx context.Context, email string, password string) (*auth.Token, error) {

	token := &auth.Token{}

	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if !user.IsActive {
		return nil, ErrUserBlocked
	}

	if !entity.ComparePasswords(user.Password, password) {
		return nil, ErrInvalidCredentials
	}

	token.RefreshToken, err = auth.GenerateRefreshToken(user.ID, user.Role)

	if err != nil {
		return nil, err
	}

	token.AccessToken, err = auth.GenerateAccessToken(user.ID, user.Role)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (s *authService) Check(ctx context.Context, accessToken string) error {
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrTokenInvalidOrExpired
		}
		return []byte(os.Getenv("SECRET_KEY")), nil
	})
	if err != nil || !token.Valid {
		return ErrTokenInvalidOrExpired
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		return ErrTokenInvalidOrExpired
	}

	expires_at, ok := claims["expires_at"].(int64)
	if !ok || expires_at < int64(time.Now().Unix()) {
		return ErrTokenInvalidOrExpired
	}

	return nil
}

func (s *authService) Refresh(ctx context.Context, refreshToken string) (*auth.Token, error) {
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrTokenInvalidOrExpired
		}
		return []byte(os.Getenv("SECRET_KEY")), nil
	})

	if err != nil || !token.Valid {
		return nil, ErrTokenInvalidOrExpired
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrTokenInvalidOrExpired
	}

	expires_at, ok := claims["expires_at"].(int64)
	if !ok || expires_at < int64(time.Now().Unix()) {
		return nil, ErrTokenInvalidOrExpired
	}

	accessToken, err := auth.GenerateAccessToken(claims["user_id"].(string), int(claims["role"].(float64)))

	if err != nil {
		return nil, err
	}

	return &auth.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
