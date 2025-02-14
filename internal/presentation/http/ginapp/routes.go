package ginapp

import (
	"github.com/gin-gonic/gin"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/user/interfaces"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/presentation/http/ginapp/handlers"
)

func InitRoutes(r *gin.Engine, service interfaces.AuthService) {
	handler := &handlers.AuthHandler{Service: service}

	api := r.Group("/auth")
	{
		api.POST("/ping", handler.Ping)
	}
}
