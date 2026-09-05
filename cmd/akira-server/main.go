package main

import (
	"log"
	"net"
	"os"

	"google.golang.org/grpc"

	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connectionPool"
	connectionserver "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connectionServer"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()

	addr := os.Getenv("AKIRA_LISTEN")
	if addr == "" {
		addr = ":5000"
	}

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}

	// Пул активных подключений: через pool.SendTask любые объекты
	// сервера отправляют задачи клиентам по id подключения.
	pool := connectionpool.New()

	grpcServer := grpc.NewServer()
	pb.RegisterConnectionServiceServer(grpcServer, connectionserver.New(pool))

	log.Printf("akira-server listening on %s", addr)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatal(err)
	}
}
