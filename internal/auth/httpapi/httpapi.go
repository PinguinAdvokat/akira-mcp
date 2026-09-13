// Пакет authhttp — HTTP-слой auth-сервиса: регистрация с подтверждением
// email коротким кодом из письма (код вводится вместе с email —
// верификация сразу выдаёт пару токенов, без отдельного логина),
// выдача пар токенов (password / refresh_token / authorization_code
// grants; authorization_code — с PKCE S256, тело /token принимается
// и как JSON, и как form-encoded), ротация и отзыв refresh-токенов,
// данные аккаунта и перегенерация connect_key, публикация JWKS,
// а также OAuth-часть для MCP-клиентов: метаданные авторизационного
// сервера (RFC 8414), dynamic client registration (RFC 7591),
// /authorize (редирект на форму логина — по умолчанию встроенный
// фронтенд этого же сервиса, web/) и /authorize/confirm
// (подтверждение логина, выдача кода).
//
// Файлы пакета: httpapi.go — маршруты и общие хелперы; token.go —
// выдача, ротация и отзыв токенов; register.go — регистрация
// и верификация email; account.go — маршруты под Bearer-токеном;
// oauth.go — authorization code flow с PKCE; web.go — раздача
// встроенного фронтенда (SPA без сборки, go:embed: web/).
//
// Фронтенд — часть этого сервиса (web/): вход, регистрация,
// подтверждение email, дашборд аккаунта с connect_key и форма
// OAuth-авторизации для MCP-хостов, куда ведёт /authorize.
//
// TLS-терминация и ограничение частоты запросов — на обратном
// прокси (nginx) перед сервисом; сам сервис слушает открытый HTTP.
package authhttp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	authmail "github.com/PinguinAdvokat/akira-mcp/internal/auth/mail"
	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
	authtoken "github.com/PinguinAdvokat/akira-mcp/internal/auth/token"
)

// connectKeyAttempts — предел попыток генерации connect_key при
// коллизии (ключи 22-символьные, вероятность коллизии исчезающе мала,
// попыток с запасом).
const connectKeyAttempts = 8

// maxBodyBytes — потолок размера JSON-тела запроса: без него тело
// неограниченного размера читается в память целиком.
const maxBodyBytes = 1 << 20 // 1 MiB

// dummyHash — bcrypt-хеш для сравнения при неизвестном пользователе:
// сравнение выполняется всегда, чтобы время ответа не выдавало,
// существует ли имя.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("akira-dummy-password"), bcrypt.DefaultCost)

// Config — параметры HTTP-слоя, не сводимые к стору и токенам.
type Config struct {
	// Mail — отправитель писем с кодом подтверждения.
	Mail authmail.Sender
	// EmailTTL — срок жизни кода подтверждения email.
	EmailTTL time.Duration
	// PublicURL — публичный базовый URL сервиса (например,
	// https://auth.example.com). Из него строятся абсолютные URL
	// в метаданных авторизационного сервера (RFC 8414). Пустой —
	// OAuth-эндпоинты не работают (ошибка 500).
	PublicURL string
	// FrontendURL — базовый URL фронтенд-приложения (форма логина).
	// /authorize редиректит на него, передавая OAuth-параметры
	// в query. Пустой (по умолчанию) — встроенный фронтенд этого
	// же сервиса: /authorize ведёт на /, форма логина внутри SPA.
	FrontendURL string
	// CodeTTL — срок жизни кода авторизации (default 10m, см. New).
	CodeTTL time.Duration
}

// handler — состояние HTTP-слоя auth-сервиса.
type handler struct {
	tokens *authtoken.Manager
	store  authstore.Store
	cfg    Config
	logger *slog.Logger
}

// New собирает http.Handler auth-сервиса.
func New(tokens *authtoken.Manager, store authstore.Store, cfg Config) http.Handler {
	if cfg.CodeTTL <= 0 {
		cfg.CodeTTL = 10 * time.Minute
	}
	h := &handler{
		tokens: tokens,
		store:  store,
		cfg:    cfg,
		logger: slog.Default().With(slog.String("component", "authHTTP")),
	}

	mux := http.NewServeMux()
	// Фронтенд (web.go): раздаётся этим же сервисом из go:embed,
	// /authorize по умолчанию ведёт на него (см. handleAuthorize).
	mux.HandleFunc("GET /{$}", h.handleIndex)
	mux.HandleFunc("GET /assets/", h.handleAsset)
	mux.HandleFunc("POST /register", h.handleRegister)
	mux.HandleFunc("POST /verify", h.handleVerify)
	mux.HandleFunc("POST /verify/resend", h.handleResend)
	mux.HandleFunc("POST /token", h.handleToken)
	mux.HandleFunc("POST /revoke", h.handleRevoke)
	mux.HandleFunc("GET /me", h.handleMe)
	mux.HandleFunc("POST /connect-key/regenerate", h.handleRegenerateConnectKey)
	mux.HandleFunc("GET /jwks.json", h.handleJWKS)
	mux.HandleFunc("GET /.well-known/jwks.json", h.handleJWKS)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", h.handleAuthServerMetadata)
	mux.HandleFunc("POST /oauth/register", h.handleOAuthRegister)
	mux.HandleFunc("GET /authorize", h.handleAuthorize)
	mux.HandleFunc("POST /authorize/confirm", h.handleAuthorizeConfirm)
	mux.HandleFunc("GET /healthz", h.handleHealthz)
	return mux
}

// errorResponse — OAuth2-стиль: {"error":"<код>","error_description":"…"}.
type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// decodeJSON читает и разбирает JSON-тело запроса с потолком
// maxBodyBytes. Ответ при ошибке пишет сам (400 — битый JSON,
// 413 — превышен лимит) и возвращает false, если обработку
// продолжать нельзя.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	body := http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(body).Decode(v); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return false
	}
	return true
}

// hashToken — sha256-хеш токена (кода подтверждения, refresh-токена)
// для ключа хранилища.
func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// handleJWKS отдаёт публичный набор ключей. Ключи меняются только при
// рестарте, поэтому набор кешируется на минуту.
func (h *handler) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(h.tokens.JWKS()); err != nil {
		h.logger.Error("write jwks", "err", err)
	}
}

func (h *handler) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("ok")); err != nil {
		h.logger.Error("write healthz", "err", err)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Заголовки уже записаны — ничего умнее логировать некуда.
		_ = err
	}
}

func writeError(w http.ResponseWriter, code int, errCode, description string) {
	writeJSON(w, code, errorResponse{Error: errCode, ErrorDescription: description})
}
