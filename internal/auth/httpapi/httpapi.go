// Пакет authhttp — HTTP-слой auth-сервиса: регистрация с подтверждением
// email коротким кодом из письма (код вводится вместе с email —
// верификация сразу выдаёт пару токенов, без отдельного логина),
// выдача пар токенов (password / refresh_token grants), ротация
// и отзыв refresh-токенов, данные аккаунта и перегенерация
// connect_key, публикация JWKS. JSON в формате, близком к OAuth2.
//
// Файлы пакета: httpapi.go — маршруты и общие хелперы; token.go —
// выдача, ротация и отзыв токенов; register.go — регистрация
// и верификация email; account.go — маршруты под Bearer-токеном.
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
	h := &handler{
		tokens: tokens,
		store:  store,
		cfg:    cfg,
		logger: slog.Default().With(slog.String("component", "authHTTP")),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", h.handleRegister)
	mux.HandleFunc("POST /verify", h.handleVerify)
	mux.HandleFunc("POST /verify/resend", h.handleResend)
	mux.HandleFunc("POST /token", h.handleToken)
	mux.HandleFunc("POST /revoke", h.handleRevoke)
	mux.HandleFunc("GET /me", h.handleMe)
	mux.HandleFunc("POST /connect-key/regenerate", h.handleRegenerateConnectKey)
	mux.HandleFunc("GET /jwks.json", h.handleJWKS)
	mux.HandleFunc("GET /.well-known/jwks.json", h.handleJWKS)
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
