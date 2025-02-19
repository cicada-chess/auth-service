package ginapp

import (
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/interfaces"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/presentation/http/ginapp/handlers"
)

func InitRoutes(r *gin.Engine, service interfaces.AuthService, logger *logrus.Logger) {
	handler := &handlers.AuthHandler{Service: service, Logger: logger}

	api := r.Group("/auth")
	{
		api.POST("/login", handler.Login)
		api.POST("/logout", handler.Logout)
		api.POST("/refresh", handler.Refresh)
		api.GET("/check", handler.Check)
		api.POST("/forgot-password", handler.ForgotPassword)
		api.POST("/reset-password", handler.ResetPassword)
		api.GET("/me", handler.Me)
	}
}
