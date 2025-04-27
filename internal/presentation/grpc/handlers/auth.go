package handlers

import (
	"context"

	service "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/application/auth"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/interfaces"
	pb "gitlab.mai.ru/cicada-chess/backend/auth-service/pkg/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GRPCHandler struct {
	authService interfaces.AuthService
	pb.UnimplementedAuthServiceServer
}

func NewGRPCHandler(authService interfaces.AuthService) *GRPCHandler {
	return &GRPCHandler{
		authService: authService,
	}
}

func (h *GRPCHandler) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	err := h.authService.Check(ctx, req.Token)
	if err != nil {
		switch err {
		case service.ErrTokenInvalidOrExpired:
			return nil, status.Error(codes.PermissionDenied, err.Error())
		default:
			return nil, status.Error(codes.Internal, err.Error())
		}
	}

	return &pb.ValidateTokenResponse{
		IsValid: true,
	}, nil
}
