package ginapp

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	_ "gitlab.mai.ru/cicada-chess/backend/auth-service/docs"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/interfaces"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/presentation/http/ginapp/handlers"
)

func InitRoutes(r *gin.Engine, service interfaces.AuthService, logger *logrus.Logger) {
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000", "https://cikada-inky.vercel.app", "https://cicada-chess.ru"}, // Разрешенные источники
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		AllowCredentials: true,
	}))
	handler := handlers.NewAuthHandler(service, logger)
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	api := r.Group("/auth")
	{
		api.POST("/register", handler.Register)
		api.POST("/login", handler.Login)
		api.GET("/logout", handler.Logout)
		api.POST("/refresh", handler.Refresh)
		api.GET("/check", handler.Check)
		api.POST("/forgot-password", handler.ForgotPassword)
		api.POST("/reset-password", handler.ResetPassword)
		api.POST("/confirm-account", handler.ConfirmAccount)
		api.POST("/access", handler.Access)
		api.GET("/me", handler.Me)

	}
}
