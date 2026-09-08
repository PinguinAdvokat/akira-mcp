package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/pool"
	connectionserver "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/server"
	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
	authstorepostgres "github.com/PinguinAdvokat/akira-mcp/internal/auth/store/postgres"
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

// storeLookup адаптирует authstore.Store к узкому интерфейсу
// connectionserver.UserLookup: серверу нужен только поиск по connect_key.
type storeLookup struct {
	store authstore.Store
}

// LookupConnectKey находит пользователя по ключу подключения.
// «Пользователь не найден» транслируется в сентинель сервера
// (ErrUnknownConnectKey): Connect отвечает Unauthenticated, и клиент
// с заведомо неверным ключом завершается. Прочие ошибки хранилища
// возвращаются как есть — Connect отвечает Internal, клиент пережидает
// и пробует снова (например, при недоступной БД).
func (l storeLookup) LookupConnectKey(ctx context.Context, connectKey string) (string, bool, error) {
	user, err := l.store.GetUserByConnectKey(ctx, connectKey)
	if err != nil {
		if errors.Is(err, authstore.ErrUserNotFound) {
			return "", false, connectionserver.ErrUnknownConnectKey
		}
		return "", false, err
	}
	return user.ID, user.EmailVerified, nil
}

// maxConnections читает MAX_CONNECTIONS (лимит одновременных подключений
// на пользователя); пустое значение — 5, 0 — без лимита.
func maxConnections(logger *slog.Logger) int {
	raw := os.Getenv("MAX_CONNECTIONS")
	if raw == "" {
		return 5
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		fatalf(logger, "invalid MAX_CONNECTIONS", "value", raw, "err", err)
	}
	return n
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

	// Пользователи — в общей БД с auth-сервисом: сервер находит
	// владельца подключения по connect_key.
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		fatalf(logger, "DATABASE_URL is required")
	}
	logger.Info("connecting to postgres", "migrations", "applying at startup")
	store, err := authstorepostgres.New(context.Background(), databaseURL)
	if err != nil {
		fatalf(logger, "postgres store init failed", "err", err)
	}
	defer store.Close()

	// Пул активных подключений: через pool.SendTask любые объекты
	// сервера отправляют задачи клиентам по connection_id.
	maxConns := maxConnections(logger)
	pool := connectionpool.New(maxConns)

	// gRPC-сервер с keepalive (см. connectionserver.NewGRPCServer):
	// полумёртвые соединения закрываются, не блокируя переподключение.
	grpcServer := connectionserver.NewGRPCServer(pool, storeLookup{store: store})

	logger.Info("akira-server listening", "addr", addr, "max_connections", maxConns)
	if err := grpcServer.Serve(lis); err != nil {
		fatalf(logger, "serve failed", "err", err)
	}
}
