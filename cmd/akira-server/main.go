package main

import (
	"log/slog"
	"net"
	"os"
	"strings"

	"google.golang.org/grpc"

	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/pool"
	connectionserver "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/server"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
	"github.com/joho/godotenv"
)

// newLogger собирает slog-логгер из переменных окружения:
// LOG_LEVEL (debug|info|warn|error, по умолчанию info)
// и LOG_FORMAT (text|json, по умолчанию text).
func newLogger() *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if strings.ToLower(os.Getenv("LOG_FORMAT")) == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	return slog.New(handler)
}

// fatalf логирует ошибку и завершает процесс.
func fatalf(logger *slog.Logger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}

func main() {
	_ = godotenv.Load()

	logger := newLogger()
	slog.SetDefault(logger)

	addr := os.Getenv("LISTEN")
	if addr == "" {
		addr = ":5000"
	}

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		fatalf(logger, "listen failed", "addr", addr, "err", err)
	}

	// Пул активных подключений: через pool.SendTask любые объекты
	// сервера отправляют задачи клиентам по id подключения.
	pool := connectionpool.New()

	grpcServer := grpc.NewServer()
	pb.RegisterConnectionServiceServer(grpcServer, connectionserver.New(pool))

	logger.Info("akira-server listening", "addr", addr)
	if err := grpcServer.Serve(lis); err != nil {
		fatalf(logger, "serve failed", "err", err)
	}
}
