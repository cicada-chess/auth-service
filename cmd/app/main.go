package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	service "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/application/auth"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/infrastructure/db/postgres"
	infrastructure "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/infrastructure/repository/postgres/access"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/presentation/grpc/handlers"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/presentation/http/ginapp"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/logger"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/pkg/auth"
	pb "gitlab.mai.ru/cicada-chess/backend/user-service/pkg/user"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
)

// @title Auth API
// @version 1.0
// @description API для аутентификации пользователей

// @host cicada-chess.ru:8081
// @BasePath /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

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

	authService := service.NewAuthService(client, accessRepo)

	r := gin.Default()
	ginapp.InitRoutes(r, authService, logger)

	server := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	grpcServer := grpc.NewServer()
	grpcHandler := handlers.NewGRPCHandler(authService)
	auth.RegisterAuthServiceServer(grpcServer, grpcHandler)
	reflection.Register(grpcServer)

	go func() {
		log.Println("Starting server on :8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	go func() {
		lis, err := net.Listen("tcp", ":9090")
		if err != nil {
			log.Fatalf("Failed to listen on :9090: %v", err)
		}
		log.Println("Starting gRPC server on :9090")
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to start gRPC server: %v", err)
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

	grpcServer.GracefulStop()

	log.Println("Server stopped")
}
