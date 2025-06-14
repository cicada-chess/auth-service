package auth

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	accessEntity "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/access/entity"
	accessInterfaces "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/access/interfaces"
	auth "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/entity"
	authInterfaces "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/interfaces"
	userEntity "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/user/entity"
	pb "gitlab.mai.ru/cicada-chess/backend/user-service/pkg/user"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ErrInvalidCredentials    = errors.New("invalid credentials")
	ErrUserBlocked           = errors.New("user is blocked")
	ErrTokenInvalidOrExpired = errors.New("token is invalid or expired")
	ErrUserNotFound          = errors.New("user not found")
	ErrUrlNotFound           = errors.New("url not found")
	ErrPermissionDenied      = errors.New("permission denied")
	ErrInternalServer        = errors.New("internal server error")
	ErrAlreadyExists         = errors.New("user already exists")
)

type authService struct {
	client     pb.UserServiceClient
	accessRepo accessInterfaces.AccessRepository
}

func NewAuthService(client pb.UserServiceClient, accessRepo accessInterfaces.AccessRepository) authInterfaces.AuthService {
	return &authService{
		client:     client,
		accessRepo: accessRepo,
	}
}

func (s *authService) Register(ctx context.Context, email, username, password string) (*string, error) {
	req := &pb.RegisterUserRequest{
		Email:    email,
		Username: username,
		Password: password,
		IsActive: false,
	}
	pbId, err := s.client.RegisterUser(ctx, req)
	if err != nil {
		st, ok := status.FromError(err)
		if ok {
			switch st.Code() {
			case codes.AlreadyExists:
				return nil, ErrAlreadyExists
			case codes.InvalidArgument:
				return nil, ErrInvalidCredentials
			}
		}
	}

	return &pbId.Id, nil
}

func (s *authService) Login(ctx context.Context, email string, password string) (*auth.Token, error) {
	req := &pb.GetUserByEmailRequest{Email: email}
	user, err := s.client.GetUserByEmail(ctx, req)
	if err != nil {
		st, ok := status.FromError(err)
		if ok {
			switch st.Code() {
			case codes.NotFound:
				return nil, ErrUserNotFound
			default:
				return nil, ErrInternalServer
			}
		}
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

	token, err := auth.GenerateToken(user.Id, int(user.Role))
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

	_, err := auth.ValidateToken(accessToken, auth.AccessToken)
	if err != nil {
		return err
	}
	return nil
}

func (s *authService) Refresh(ctx context.Context, refreshToken string) (*auth.Token, error) {
	_, err := auth.ValidateToken(refreshToken, auth.RefreshToken)
	if err != nil {
		return nil, err
	}
	token, _ := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET_KEY")), nil
	})
	claims, _ := token.Claims.(jwt.MapClaims)

	accessToken, err := auth.GenerateAccessToken(claims["user_id"].(string), int(claims["role"].(float64)))

	if err != nil {
		return nil, err
	}

	return &auth.Token{
		AccessToken:     accessToken,
		AccessExpiresIn: int(auth.AccessTokenTTL.Seconds()),
		TokenType:       "Bearer",
	}, nil
}

func (s *authService) ForgotPassword(ctx context.Context, email string) error {
	req := &pb.ForgotPasswordRequest{Email: email}
	response, err := s.client.ForgotPassword(ctx, req)
	if err != nil && response == nil {
		st, ok := status.FromError(err)
		if ok {
			switch st.Code() {
			case codes.NotFound:
				return ErrUserNotFound
			case codes.InvalidArgument:
				return ErrInvalidCredentials
			default:
				return ErrInternalServer
			}
		}
	}

	return nil
}

func (s *authService) ResetPassword(ctx context.Context, token, newPassword string) error {
	userId, err := auth.ValidateToken(token, auth.PasswordReset)
	if err != nil {
		return err
	}

	req := &pb.UpdateUserPasswordRequest{Id: *userId, Password: newPassword}
	response, err := s.client.UpdateUserPassword(ctx, req)
	if err != nil && response == nil {
		st, ok := status.FromError(err)
		if ok {
			switch st.Code() {
			case codes.InvalidArgument:
				return ErrInvalidCredentials
			case codes.NotFound:
				return ErrUserNotFound
			case codes.Internal:
				return ErrInternalServer
			}
		}
	}

	return nil
}

func (s *authService) Access(ctx context.Context, role int, url string) error {
	protectedUrl, err := s.accessRepo.GetProtectedUrl(ctx, url)
	if err != nil {
		return err
	}
	if !accessEntity.CheckPermission(protectedUrl.Roles, role) {
		return ErrPermissionDenied
	}
	return nil

}

func (s *authService) Me(ctx context.Context, tokenHeader string) (*userEntity.User, error) {
	accessToken := strings.TrimPrefix(tokenHeader, "Bearer ")

	token, _ := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET_KEY")), nil
	})

	claims, _ := token.Claims.(jwt.MapClaims)
	userId, _ := claims["user_id"].(string)

	req := &pb.GetUserByIdRequest{Id: userId}
	user, err := s.client.GetUserById(ctx, req)
	if err != nil {
		st, ok := status.FromError(err)
		if ok {
			switch st.Code() {
			case codes.NotFound:
				return nil, ErrUserNotFound
			case codes.InvalidArgument:
				return nil, ErrInvalidCredentials
			case codes.Internal:
				return nil, ErrInternalServer
			}
		}
	}

	entityUser := &userEntity.User{
		ID:        user.Id,
		Username:  user.Username,
		Email:     user.Email,
		Role:      int(user.Role),
		Rating:    int(user.Rating),
		CreatedAt: user.CreatedAt.AsTime(),
		UpdatedAt: user.UpdatedAt.AsTime(),
		IsActive:  user.IsActive,
	}

	return entityUser, nil

}

func (s *authService) ConfirmAccount(ctx context.Context, token string) error {
	id, err := auth.ValidateToken(token, auth.AccountConfirmation)
	if err != nil {
		return err
	}

	req := &pb.ConfirmAccountRequest{Id: *id}

	response, err := s.client.ConfirmAccount(ctx, req)
	if err != nil && response == nil {
		st, ok := status.FromError(err)
		if ok {
			switch st.Code() {
			case codes.NotFound:
				return ErrUserNotFound
			case codes.InvalidArgument:
				return ErrInvalidCredentials
			case codes.Internal:
				return ErrInternalServer
			}
		}
	}

	return nil

}
