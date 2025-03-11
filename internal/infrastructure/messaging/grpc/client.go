// // filepath: /home/sauron/Projects/auth-service/internal/infrastructure/grpc/client.go
package grpcclient

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func NewClient(target string) (*grpc.ClientConn, error) {
	return grpc.Dial(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
}
