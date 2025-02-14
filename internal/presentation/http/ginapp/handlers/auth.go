package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/user/interfaces"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/infrastructure/response"
)

type AuthHandler struct {
	Service interfaces.AuthService
}

func (h *AuthHandler) Ping(c *gin.Context) {
	response.NewSuccessResponse(c, http.StatusOK, "pong", nil)
}
