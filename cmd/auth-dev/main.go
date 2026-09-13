// Команда auth-dev — auth-сервис для локальной разработки
// фронтенда: то же HTTP-API (httpapi.New), но хранилище
// in-memory вместо Postgres и коды подтверждения пишутся в лог.
// После рестарта все данные (пользователи, токены) сбрасываются.
//
// Пример:
//
//	go run ./cmd/auth-dev
//
// Фронтенд: http://127.0.0.1:6000/ — вход/регистрация/дашборд,
// OAuth-флоу для MCP-хостов: /authorize ведёт на встроенную форму.
package main

import (
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	authhttp "github.com/PinguinAdvokat/akira-mcp/internal/auth/httpapi"
	authmail "github.com/PinguinAdvokat/akira-mcp/internal/auth/mail"
	authstorememory "github.com/PinguinAdvokat/akira-mcp/internal/auth/store/memory"
	authtoken "github.com/PinguinAdvokat/akira-mcp/internal/auth/token"
)

// newLogger — как в cmd/auth: LOG_LEVEL/LOG_FORMAT.
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
	if strings.ToLower(os.Getenv("LOG_FORMAT")) == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

func main() {
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
	publicURL := os.Getenv("AUTH_PUBLIC_URL")
	if publicURL == "" {
		publicURL = "http://127.0.0.1" + addrOrDefault(addr)
	}

	tokens, err := authtoken.NewManager(issuer, 15*time.Minute, 720*time.Hour)
	if err != nil {
		logger.Error("token manager init failed", "err", err)
		os.Exit(1)
	}

	// In-memory стор: без Postgres; mail — logSender (коды в лог).
	store := authstorememory.New()
	mail := authmail.New(authmail.ConfigFromEnv(), logger)

	srv := &http.Server{
		Addr: addr,
		Handler: authhttp.New(tokens, store, authhttp.Config{
			Mail:        mail,
			EmailTTL:    15 * time.Minute,
			PublicURL:   publicURL,
			FrontendURL: os.Getenv("AUTH_FRONTEND_URL"),
			CodeTTL:     10 * time.Minute,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	logger.Info("auth-dev listening (in-memory store, codes logged)",
		"addr", addr, "public_url", publicURL)
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("serve failed", "err", err)
		os.Exit(1)
	}
}

// addrOrDefault — суффикс адреса для публичного URL по умолчанию:
// ":6000" → ":6000", ":80" и пустое — не добавляются.
func addrOrDefault(addr string) string {
	switch addr {
	case "", ":80", ":443":
		return ""
	default:
		return addr
	}
}
