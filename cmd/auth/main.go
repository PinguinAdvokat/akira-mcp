package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	authhttp "github.com/PinguinAdvokat/akira-mcp/internal/auth/httpapi"
	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
	authstorememory "github.com/PinguinAdvokat/akira-mcp/internal/auth/store/memory"
	authtoken "github.com/PinguinAdvokat/akira-mcp/internal/auth/token"
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

// envDuration читает переменную окружения как duration; пустое или
// отсутствующее значение — fallback.
func envDuration(logger *slog.Logger, name string, fallback time.Duration) time.Duration {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		fatalf(logger, "invalid duration env", "var", name, "value", raw, "err", err)
	}
	return d
}

// bootstrapUser создаёт стартового пользователя из AUTH_BOOTSTRAP_*
// (пароль хешируется bcrypt). Уже существующий — не ошибка.
func bootstrapUser(ctx context.Context, logger *slog.Logger, store authstore.Store) {
	username := os.Getenv("AUTH_BOOTSTRAP_USERNAME")
	password := os.Getenv("AUTH_BOOTSTRAP_PASSWORD")
	if username == "" || password == "" {
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fatalf(logger, "hash bootstrap password", "err", err)
	}
	if _, err := store.CreateUser(ctx, username, hash); err != nil {
		if !errors.Is(err, authstore.ErrUserExists) {
			fatalf(logger, "create bootstrap user", "err", err)
		}
		logger.Info("bootstrap user already exists", "username", username)
		return
	}
	logger.Info("bootstrap user created", "username", username)
}

func main() {
	_ = godotenv.Load()

	logger := newLogger()
	slog.SetDefault(logger)

	addr := os.Getenv("AUTH_LISTEN")
	if addr == "" {
		addr = ":6000"
	}

	issuer := os.Getenv("AUTH_ISSUER")
	if issuer == "" {
		issuer = "akira"
	}
	accessTTL := envDuration(logger, "AUTH_ACCESS_TTL", 15*time.Minute)
	refreshTTL := envDuration(logger, "AUTH_REFRESH_TTL", 720*time.Hour)

	// Ключи генерируются на старте и живут в памяти: после рестарта
	// kid меняется и все старые токены невалидны (см. пакет authtoken).
	tokens, err := authtoken.NewManager(issuer, accessTTL, refreshTTL)
	if err != nil {
		fatalf(logger, "token manager init failed", "err", err)
	}

	store := authstorememory.New()
	bootstrapUser(context.Background(), logger, store)

	srv := &http.Server{
		Addr:              addr,
		Handler:           authhttp.New(tokens, store),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	logger.Info("auth server listening",
		"addr", addr,
		"issuer", issuer,
		"access_ttl", accessTTL.String(),
		"refresh_ttl", refreshTTL.String(),
	)
	if err := srv.ListenAndServe(); err != nil {
		fatalf(logger, "serve failed", "err", err)
	}
}
