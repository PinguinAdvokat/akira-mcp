package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/pool"
	connectionserver "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/server"
	akiramcp "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/mcp"
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

// envOr возвращает значение переменной окружения или значение
// по умолчанию, если переменная пуста.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envMs читает переменную окружения с числом миллисекунд;
// непустое некорректное значение фатально (как MAX_CONNECTIONS —
// молчаливый отход к умолчанию скрыл бы опечатку).
func envMs(key string, def int, logger *slog.Logger) int {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		fatalf(logger, "invalid "+key, "value", raw, "err", err)
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

	// MCP-сервер — второй листенер того же процесса: LLM через него
	// управляет машинами пользователей (tools exec/write_file,
	// ресурсы akira://machines и akira://file/...). Авторизация —
	// access-токены auth-сервиса, проверяемые по его JWKS; OAuth-флоу
	// начинается с 401 + resource_metadata (RFC 9728), поэтому нужны
	// публичные адреса MCP-листенера и auth-сервиса.
	mcpAddr := envOr("MCP_LISTEN", ":7000")
	mcpTaskTimeoutMs := envMs("MCP_TASK_TIMEOUT_MS", 120_000, logger)
	mcpReadMaxBytes := envMs("MCP_READ_MAX_BYTES", 1<<20, logger)
	mcpPublicURL := envOr("MCP_PUBLIC_URL", "http://127.0.0.1:7000")
	mcpAuthServerURL := envOr("MCP_AUTH_SERVER_URL", "http://127.0.0.1:6000")
	validator, err := akiramcp.NewTokenValidator(context.Background(),
		envOr("MCP_JWKS_URL", "http://127.0.0.1:6000/jwks.json"),
		envOr("MCP_AUTH_ISSUER", "akira"),
	)
	if err != nil {
		fatalf(logger, "mcp token validator init failed", "err", err)
	}
	mcpHandler, err := akiramcp.New(akiramcp.Config{
		Pool:          pool,
		Validator:     validator,
		TaskTimeoutMs: mcpTaskTimeoutMs,
		ReadMaxBytes:  mcpReadMaxBytes,
		PublicURL:     mcpPublicURL,
		AuthServerURL: mcpAuthServerURL,
		Logger:        logger,
	})
	if err != nil {
		fatalf(logger, "mcp server init failed", "err", err)
	}
	mcpLis, err := net.Listen("tcp", mcpAddr)
	if err != nil {
		fatalf(logger, "mcp listen failed", "addr", mcpAddr, "err", err)
	}
	mcpHTTP := &http.Server{
		Handler: mcpHandler,
		// Таймауты по образцу cmd/auth: краткие запросы (initialize,
		// tools/list) укладываются легко; долгие задачи (exec) идут
		// внутри одного POST и могут занять таймаут задачи — поэтому
		// WriteTimeout щедрее задачного лимита.
		ReadTimeout:  15 * time.Second,
		WriteTimeout: time.Duration(mcpTaskTimeoutMs)*time.Millisecond + 15*time.Second,
		IdleTimeout:  60 * time.Second,
	}
	go func() {
		if err := mcpHTTP.Serve(mcpLis); err != nil {
			fatalf(logger, "mcp serve failed", "err", err)
		}
	}()

	logger.Info("akira-server listening", "addr", addr, "mcp_addr", mcpAddr, "max_connections", maxConns)
	if err := grpcServer.Serve(lis); err != nil {
		fatalf(logger, "serve failed", "err", err)
	}
}
