package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	service "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/application/auth"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/infrastructure/db/postgres"
	infrastructure "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/infrastructure/repository/postgres/access"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/presentation/http/ginapp"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/logger"
	pb "gitlab.mai.ru/cicada-chess/backend/user-service/pkg/user"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	logger := logger.New()

	conn, err := grpc.NewClient("user-service:9090", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()

	client := pb.NewUserServiceClient(conn)

	cfgToDB := postgres.GetDBConfig()
	dbConn, err := postgres.NewPostgresDB(cfgToDB)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer dbConn.Close()

	accessRepo := infrastructure.NewAccessRepository(dbConn)

	userService := service.NewAuthService(client, accessRepo, nil /* EmailSender */)

	r := gin.Default()
	ginapp.InitRoutes(r, userService, logger)

	server := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	go func() {
		log.Println("Starting server on :8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server stopped")
}
