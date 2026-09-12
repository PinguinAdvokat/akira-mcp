package akiramcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/server"

	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/pool"
)

// Version — версия MCP-сервера (видна MCP-клиенту в initialize).
const Version = "0.1.0"

// Config — параметры MCP-сервера.
type Config struct {
	// Pool — пул активных подключений (общий с gRPC-сервером akira).
	Pool *connectionpool.ConnectionPool
	// Validator — проверка access-токенов auth-сервиса.
	Validator *TokenValidator
	// TaskTimeoutMs — таймаут задач по умолчанию и потолок
	// для аргумента timeout_ms инструмента exec.
	TaskTimeoutMs int
	// ReadMaxBytes — ограничение размера читаемых файлов.
	ReadMaxBytes int
	// PublicURL — публичный базовый URL этого MCP-листенера
	// (например, http://mcp.example.com). Из него строится resource
	// (RFC 8707) в protected resource metadata и resource_metadata
	// в WWW-Authenticate на 401 — по нему MCP-клиент дискаверит
	// auth-сервер (RFC 9728). Требование клиента mcp-go: URL обязан
	// делить scheme и host с адресом, к которому стучится клиент.
	PublicURL string
	// AuthServerURL — публичный базовый URL auth-сервиса
	// (authorization_servers в protected resource metadata).
	AuthServerURL string
	// ClientReleasesURL — база релизов, откуда скрипт /sh качает
	// бинарник akira-client (скрипт добавит /latest/download/…).
	// Пустая — defaultClientReleasesURL.
	ClientReleasesURL string
	// Logger — логгер сервера (nil — slog.Default()).
	Logger *slog.Logger
}

// userIDKey — ключ user_id в контексте HTTP-запроса: валидатор
// кладёт его после проверки Bearer-токена, handlers достают
// через ctxUserID.
type userIDKey struct{}

// ctxUserID возвращает user_id из контекста (пустая строка —
// если контекст прошёл мимо авторизации; в собранном New хендлере
// такого не бывает).
func ctxUserID(ctx context.Context) string {
	id, _ := ctx.Value(userIDKey{}).(string)
	return id
}

// mcpServer — синоним, чтобы tools.go/resources.go не зависели
// от пакета mcplib.
type mcpServer = mcplib.MCPServer

// New собирает HTTP-хендлер MCP-сервера: корневой mux с тремя путями —
// /mcp (stateless StreamableHTTP, обёрнутый в проверку Bearer-токенов),
// /.well-known/oauth-protected-resource/mcp (метаданные защищённого
// ресурса, RFC 9728 — публичический, без авторизации) и GET /sh
// (установочный скрипт akira-client — публичический, адрес сервера
// и TLS-флаги зашиты из PublicURL). Метаданные —
// входная точка OAuth-флоу: без токена клиент получает 401 с resource_metadata,
// по нему фетчит PRM и узнаёт адрес auth-сервера. Stateless-режим не требует
// закрепления сессий за инстансом — можно за балансировщиком.
func New(cfg Config) (http.Handler, error) {
	if cfg.Pool == nil {
		return nil, errors.New("akiramcp: Config.Pool is required")
	}
	if cfg.Validator == nil {
		return nil, errors.New("akiramcp: Config.Validator is required")
	}
	if cfg.PublicURL == "" {
		return nil, errors.New("akiramcp: Config.PublicURL is required")
	}
	if cfg.AuthServerURL == "" {
		return nil, errors.New("akiramcp: Config.AuthServerURL is required")
	}
	if cfg.TaskTimeoutMs <= 0 {
		cfg.TaskTimeoutMs = 120_000
	}
	if cfg.ReadMaxBytes <= 0 {
		cfg.ReadMaxBytes = 1 << 20
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With(slog.String("component", "akiraMCP"))

	// Установочный скрипт /sh: адрес сервера и TLS-флаги зашиваем
	// из PublicURL, рендерим один раз при старте — хендлер просто
	// отдаёт готовую строку.
	connAddr, tlsFlags, err := clientConnectParams(cfg.PublicURL)
	if err != nil {
		return nil, fmt.Errorf("akiramcp: %w", err)
	}
	releasesURL := cfg.ClientReleasesURL
	if releasesURL == "" {
		releasesURL = defaultClientReleasesURL
	}
	installSh, err := renderInstallScript(installParams{
		ReleasesURL: strings.TrimSuffix(releasesURL, "/"),
		ServerAddr:  connAddr,
		TLSFlags:    tlsFlags,
	})
	if err != nil {
		return nil, fmt.Errorf("akiramcp: render install script: %w", err)
	}

	s := mcplib.NewMCPServer("akira", Version,
		mcplib.WithToolCapabilities(false),
		mcplib.WithResourceCapabilities(false, false),
		mcplib.WithRecovery(),
		mcplib.WithLogger(logger),
	)
	addTools(s, cfg)
	addResources(s, cfg)

	streamable := mcplib.NewStreamableHTTPServer(s,
		mcplib.WithEndpointPath("/mcp"),
		mcplib.WithStateLess(true),
		mcplib.WithStreamableHTTPLogger(logger),
	)

	mux := http.NewServeMux()
	mux.Handle("/mcp", &authHandler{
		validator: cfg.Validator,
		next:      streamable,
		publicURL: strings.TrimSuffix(cfg.PublicURL, "/"),
		logger:    logger,
	})
	// PRM-метаданные (RFC 9728): публичические, без авторизации —
	// это и есть вход в OAuth-флоу. Путь вычисляется из resource
	// (для https://host/mcp — /.well-known/oauth-protected-resource/mcp),
	// клиент mcp-go строит его тем же правилом.
	resource := strings.TrimSuffix(cfg.PublicURL, "/") + "/mcp"
	mux.Handle(mcplib.ProtectedResourceMetadataPath(resource),
		mcplib.NewProtectedResourceMetadataHandler(mcplib.ProtectedResourceMetadataConfig{
			Resource:               resource,
			AuthorizationServers:   []string{strings.TrimSuffix(cfg.AuthServerURL, "/")},
			BearerMethodsSupported: []string{"header"},
		}))
	// Установочный скрипт akira-client (bash <(curl -sL …/sh) KEY):
	// публичический, без авторизации — connect key скрипт спрашивает
	// у пользователя, а не получает от сервера.
	mux.HandleFunc("GET /sh", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		_, _ = w.Write([]byte(installSh))
	})
	return mux, nil
}

// authHandler — обёртка над MCP-хендлером: проверяет Bearer-токен
// каждого запроса и кладёт user_id в контекст. Отказ — 401 c
// WWW-Authenticate, где resource_metadata указывает на protected
// resource metadata этого сервера (RFC 9728): по нему MCP-клиент
// находит auth-сервер и проходит OAuth-флоу (authorization code +
// PKCE). Тело ответа минимальное, деталей ошибки наружу не отдаём.
type authHandler struct {
	validator *TokenValidator
	next      http.Handler
	publicURL string
	logger    *slog.Logger
}

func (h *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	userID, err := h.validator.Validate(r.Context(), r)
	if err != nil {
		if !errors.Is(err, ErrNoAuthorization) {
			// Причина отказа полезна в логах, но не в ответе.
			h.logger.Warn("mcp token rejected", "err", err)
		}
		w.Header().Set("WWW-Authenticate",
			fmt.Sprintf(`Bearer realm="akira", resource_metadata="%s/.well-known/oauth-protected-resource/mcp"`, h.publicURL))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	h.next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userIDKey{}, userID)))
}
