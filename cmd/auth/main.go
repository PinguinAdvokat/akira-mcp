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
	authmail "github.com/PinguinAdvokat/akira-mcp/internal/auth/mail"
	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
	authstorepostgres "github.com/PinguinAdvokat/akira-mcp/internal/auth/store/postgres"
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

// envOr читает переменную окружения; пустое или отсутствующее
// значение — fallback.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// bootstrapUser создаёт стартового пользователя из AUTH_BOOTSTRAP_*
// (пароль хешируется bcrypt), сразу с подтверждённым email и выданным
// connect_key. Если имя или email заняты — это либо наш пользователь
// с прошлого запуска, либо чужой аккаунт: сверяем пароль и email
// и при несовпадении отказываемся стартовать, чтобы оператор молча
// не работал с чужой учётной записью.
func bootstrapUser(ctx context.Context, logger *slog.Logger, store authstore.Store) {
	username := strings.TrimSpace(os.Getenv("AUTH_BOOTSTRAP_USERNAME"))
	password := os.Getenv("AUTH_BOOTSTRAP_PASSWORD")
	email := strings.ToLower(strings.TrimSpace(os.Getenv("AUTH_BOOTSTRAP_EMAIL")))
	if username == "" || password == "" {
		return
	}
	if email == "" {
		email = username + "@bootstrap.local"
	}
	// bcrypt молча обрезает пароль до 72 байт — явный отказ честнее.
	if len(password) > 72 {
		fatalf(logger, "AUTH_BOOTSTRAP_PASSWORD must be at most 72 bytes", "len", len(password))
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fatalf(logger, "hash bootstrap password", "err", err)
	}

	u, err := store.CreateUser(ctx, username, email, hash)
	switch {
	case err == nil:
		// Новый пользователь: подтверждаем email и выдаём connect_key.
		if err := store.VerifyEmail(ctx, u.ID); err != nil {
			fatalf(logger, "verify bootstrap user email", "err", err)
		}
		if err := assignConnectKey(ctx, store, u.ID); err != nil {
			fatalf(logger, "assign bootstrap connect key", "err", err)
		}
		logger.Info("bootstrap user created", "username", username, "email", email)
	case errors.Is(err, authstore.ErrUserExists), errors.Is(err, authstore.ErrEmailExists):
		ensureBootstrapUser(ctx, logger, store, username, email, password)
	default:
		fatalf(logger, "create bootstrap user", "err", err)
	}
}

// ensureBootstrapUser разбирает занятое имя/email при старте. Имя ищется
// в хранилище: если его нет — конфликт был по email (он принадлежит
// другому аккаунту), это фатально. Найденный пользователь обязан
// совпадать по паролю и email с AUTH_BOOTSTRAP_* — тогда это наш
// пользователь с прошлого запуска и недостающее (подтверждение email,
// connect_key — например, оставшийся пустым до этой правки) доводится
// до конца. Пароль или email не совпали — чужой сквоттер, отказ.
func ensureBootstrapUser(ctx context.Context, logger *slog.Logger, store authstore.Store, username, email, password string) {
	u, err := store.GetUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, authstore.ErrUserNotFound) {
			// Имя свободно — значит, занят email.
			fatalf(logger, "AUTH_BOOTSTRAP_EMAIL is already taken by another account", "email", email)
		}
		fatalf(logger, "load existing bootstrap user", "err", err)
	}
	if bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(password)) != nil {
		fatalf(logger, "bootstrap username is taken by an account with a different password (squatting?): refusing to start; change AUTH_BOOTSTRAP_USERNAME or remove the existing account", "username", username)
	}
	if u.Email != email {
		fatalf(logger, "bootstrap username exists with a different email", "username", username, "existing_email", u.Email, "configured_email", email)
	}
	if !u.EmailVerified {
		if err := store.VerifyEmail(ctx, u.ID); err != nil {
			fatalf(logger, "verify bootstrap user email", "err", err)
		}
	}
	if u.ConnectKey == "" {
		if err := assignConnectKey(ctx, store, u.ID); err != nil {
			fatalf(logger, "assign bootstrap connect key", "err", err)
		}
	}
	logger.Info("bootstrap user already exists", "username", username, "email", email)
}

// assignConnectKey генерирует и сохраняет connect_key пользователя.
func assignConnectKey(ctx context.Context, store authstore.Store, userID string) error {
	key, err := authstore.GenerateConnectKey()
	if err != nil {
		return err
	}
	return store.SetConnectKey(ctx, userID, key)
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
	emailTTL := envDuration(logger, "AUTH_EMAIL_TTL", 15*time.Minute)
	// Публичный URL — база абсолютных ссылок OAuth-метаданных;
	// фронтенд — куда /authorize редиректит на форму логина
	// (пустой → /authorize отвечает ошибкой; флоу можно гнать
	// через POST /authorize/confirm напрямую).
	publicURL := envOr("AUTH_PUBLIC_URL", "http://127.0.0.1:6000")
	frontendURL := os.Getenv("AUTH_FRONTEND_URL")
	codeTTL := envDuration(logger, "AUTH_CODE_TTL", 10*time.Minute)

	// Ключи генерируются на старте и живут в памяти: после рестарта
	// kid меняется и все старые токены невалидны (см. пакет authtoken).
	tokens, err := authtoken.NewManager(issuer, accessTTL, refreshTTL)
	if err != nil {
		fatalf(logger, "token manager init failed", "err", err)
	}

	// Хранилище — Postgres (схема создаётся миграциями при подключении).
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
	bootstrapUser(context.Background(), logger, store)

	// Отправитель писем: SMTP, если задан SMTP_HOST, иначе коды
	// подтверждения пишутся в лог (режим локальной разработки).
	mail := authmail.New(authmail.ConfigFromEnv(), logger)

	srv := &http.Server{
		Addr: addr,
		Handler: authhttp.New(tokens, store, authhttp.Config{
			Mail:        mail,
			EmailTTL:    emailTTL,
			PublicURL:   publicURL,
			FrontendURL: frontendURL,
			CodeTTL:     codeTTL,
		}),
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
