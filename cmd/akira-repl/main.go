package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"strconv"

	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/pool"
	connectionserver "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/server"
	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
	authstorepostgres "github.com/PinguinAdvokat/akira-mcp/internal/auth/store/postgres"
	"github.com/joho/godotenv"
)

// repl — ручная проверка сервера: поднимает gRPC-сервер
// (как akira-server) и читает команды из stdin.
//
// Команды:
//
//	list                       — активные подключения (connection_id)
//	use <connection-id>        — выбрать активное подключение
//	exec <conn> <cmd...>       — выполнить команду на клиенте
//	read <conn> <path>         — прочитать файл
//	write <conn> <path> <text...> — записать текст в файл
//	timeout <ms>               — таймаут задач для последующих команд
//	help                       — список команд
//	quit                       — выход
func main() {
	_ = godotenv.Load()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	addr := os.Getenv("LISTEN")
	if addr == "" {
		addr = ":5000"
	}

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("listen failed", "addr", addr, "err", err)
		os.Exit(1)
	}

	// Пользователи — в общей БД с auth-сервисом: как и akira-server,
	// repl находит владельца подключения по connect_key.
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		logger.Error("DATABASE_URL is required")
		os.Exit(1)
	}
	logger.Info("connecting to postgres", "migrations", "applying at startup")
	store, err := authstorepostgres.New(context.Background(), databaseURL)
	if err != nil {
		logger.Error("postgres store init failed", "err", err)
		os.Exit(1)
	}
	defer store.Close()

	// Некорректное значение — ошибка конфигурации: молчаливый отход
	// к умолчанию скрывал бы опечатку (лимит незаметно менялся на 5).
	maxConns := 5
	if raw := os.Getenv("MAX_CONNECTIONS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			logger.Error("invalid MAX_CONNECTIONS", "value", raw, "err", err)
			os.Exit(1)
		}
		maxConns = n
	}

	pool := connectionpool.New(maxConns)

	// gRPC-сервер с keepalive (см. connectionserver.NewGRPCServer):
	// полумёртвые соединения закрываются, не блокируя переподключение.
	grpcServer := connectionserver.NewGRPCServer(pool, storeLookup{store: store})

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			logger.Error("serve failed", "err", err)
			os.Exit(1)
		}
	}()
	logger.Info("akira-repl listening", "addr", addr)

	repl(logger, pool)
}

// storeLookup адаптирует authstore.Store к узкому интерфейсу
// connectionserver.UserLookup.
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
