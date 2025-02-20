package auth

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	senderInterface "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/application/sender"
	accessEntity "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/access/entity"
	accessInterfaces "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/access/interfaces"
	auth "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/entity"
	authInterfaces "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/interfaces"
	userEntity "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/user/entity"
)

var (
	ErrInvalidCredentials    = errors.New("invalid credentials")
	ErrUserBlocked           = errors.New("user is blocked")
	ErrTokenInvalidOrExpired = errors.New("token is invalid or expired")
	ErrUserNotFound          = errors.New("user not found")
	ErrUrlNotFound           = errors.New("url not found")
	ErrPermissionDenied      = errors.New("permission denied")
	ErrInternalServer        = errors.New("internal server error")
)

type authService struct {
	authRepo    authInterfaces.AuthRepository
	accessRepo  accessInterfaces.AccessRepository
	emailSender senderInterface.EmailSender // TODO: УДАЛИТЬ КОГДА ПОДКЛЮЧИМ GRPC
}

func NewAuthService(authRepo authInterfaces.AuthRepository, emailSender senderInterface.EmailSender, accessRepo accessInterfaces.AccessRepository) authInterfaces.AuthService {
	return &authService{
		authRepo:    authRepo,
		accessRepo:  accessRepo,
		emailSender: emailSender, // TODO: УДАЛИТЬ КОГДА ПОДКЛЮЧИМ GRPC
	}
}

func (s *authService) Login(ctx context.Context, email string, password string) (*auth.Token, error) {

	token := &auth.Token{}

	user, err := s.authRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, ErrInternalServer
	}

	if user == nil && errors.Is(err, nil) {
		return nil, ErrInvalidCredentials
	}

	if !user.IsActive {
		return nil, ErrUserBlocked
	}

	if !userEntity.ComparePasswords(password, user.Password) {
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

func (s *authService) Check(ctx context.Context, tokenHeader string) error {
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(tokenHeader, bearerPrefix) {
		return ErrTokenInvalidOrExpired
	}

	accessToken := strings.TrimPrefix(tokenHeader, bearerPrefix)
	if accessToken == "" {
		return ErrTokenInvalidOrExpired
	}

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

	expires_at, ok := claims["expires_at"].(float64)
	if !ok || expires_at < float64(time.Now().Unix()) {
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

	expires_at, ok := claims["expires_at"].(float64)
	if !ok || expires_at < float64(time.Now().Unix()) {
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

func (s *authService) ForgotPassword(ctx context.Context, email string) error {
	user, err := s.authRepo.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		return ErrUserNotFound
	}

	resetToken, err := auth.GenerateResetToken(user.ID, user.Role)
	if err != nil {
		return err
	}

	if err := s.emailSender.SendResetPasswordEmail(email, resetToken); err != nil {
		return err
	}
	return nil
}

func (s *authService) ResetPassword(ctx context.Context, resetToken string, newPassword string) error {
	token, err := jwt.Parse(resetToken, func(token *jwt.Token) (interface{}, error) {
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

	userID, ok := claims["user_id"].(string)
	if !ok {
		return ErrTokenInvalidOrExpired
	}

	return s.authRepo.UpdateUserPassword(ctx, userID, newPassword)
}

func (s *authService) Access(ctx context.Context, role int, url string) error {
	protectedUrl, err := s.accessRepo.GetProtectedUrl(ctx, url)
	if err != nil {
		return ErrUrlNotFound
	}
	if !accessEntity.CheckPermission(protectedUrl.Roles, role) {
		return ErrPermissionDenied
	}
	return nil

}
