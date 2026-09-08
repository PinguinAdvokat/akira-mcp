// Пакет authhttp — HTTP-слой auth-сервиса: выдача пар токенов
// (password / refresh_token grants), ротация и отзыв refresh-токенов,
// публикация JWKS. JSON в формате, близком к OAuth2.
package authhttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
	authtoken "github.com/PinguinAdvokat/akira-mcp/internal/auth/token"
)

// handler — состояние HTTP-слоя auth-сервиса.
type handler struct {
	tokens *authtoken.Manager
	store  authstore.Store
	logger *slog.Logger
}

// New собирает http.Handler auth-сервиса.
func New(tokens *authtoken.Manager, store authstore.Store) http.Handler {
	h := &handler{
		tokens: tokens,
		store:  store,
		logger: slog.Default().With(slog.String("component", "authHTTP")),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", h.handleToken)
	mux.HandleFunc("POST /revoke", h.handleRevoke)
	mux.HandleFunc("GET /jwks.json", h.handleJWKS)
	mux.HandleFunc("GET /.well-known/jwks.json", h.handleJWKS)
	mux.HandleFunc("GET /healthz", h.handleHealthz)
	return mux
}

// tokenRequest — тело POST /token.
type tokenRequest struct {
	GrantType    string `json:"grant_type"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	RefreshToken string `json:"refresh_token"`
}

// tokenResponse — успешный ответ POST /token.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

// errorResponse — OAuth2-стиль: {"error":"<код>","error_description":"…"}.
type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (h *handler) handleToken(w http.ResponseWriter, r *http.Request) {
	var req tokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}

	switch req.GrantType {
	case "password":
		h.grantPassword(w, r.Context(), req)
	case "refresh_token":
		h.grantRefresh(w, r.Context(), req)
	default:
		writeError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be password or refresh_token")
	}
}

// grantPassword проверяет учётные данные и выдаёт новую пару токенов.
func (h *handler) grantPassword(w http.ResponseWriter, ctx context.Context, req tokenRequest) {
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "username and password are required")
		return
	}

	user, err := h.store.GetUserByUsername(ctx, req.Username)
	if err != nil {
		// Одинаковый ответ для отсутствующего пользователя и неверного
		// пароля — против перечисления имён.
		h.logger.Warn("password grant failed", "username", req.Username)
		writeError(w, http.StatusUnauthorized, "invalid_grant", "invalid credentials")
		return
	}
	if bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(req.Password)) != nil {
		h.logger.Warn("password grant failed", "username", req.Username)
		writeError(w, http.StatusUnauthorized, "invalid_grant", "invalid credentials")
		return
	}

	h.issuePair(w, ctx, user.ID, user.Username)
}

// grantRefresh потребляет refresh-токен (одноразовый: ротация)
// и выдаёт новую пару. Истёкший или неизвестный токен — invalid_grant.
func (h *handler) grantRefresh(w http.ResponseWriter, ctx context.Context, req tokenRequest) {
	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	rec, err := h.store.ConsumeRefresh(ctx, hashRefresh(req.RefreshToken))
	if err != nil {
		h.logger.Warn("refresh grant failed", "reason", "unknown or already used token")
		writeError(w, http.StatusUnauthorized, "invalid_grant", "unknown, expired or already used refresh token")
		return
	}
	if time.Now().After(rec.ExpiresAt) {
		h.logger.Warn("refresh grant failed", "reason", "expired token", "user_id", rec.UserID)
		writeError(w, http.StatusUnauthorized, "invalid_grant", "unknown, expired or already used refresh token")
		return
	}

	h.issuePair(w, ctx, rec.UserID, "")
}

// issuePair выпускает access + refresh и сохраняет хеш refresh в стор.
func (h *handler) issuePair(w http.ResponseWriter, ctx context.Context, userID, username string) {
	access, err := h.tokens.NewAccessToken(userID)
	if err != nil {
		h.logger.Error("sign access token", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "failed to issue tokens")
		return
	}
	refreshRaw, refreshHash, err := h.tokens.NewRefreshToken()
	if err != nil {
		h.logger.Error("generate refresh token", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "failed to issue tokens")
		return
	}

	now := time.Now()
	if err := h.store.SaveRefresh(ctx, authstore.RefreshToken{
		TokenHash: refreshHash,
		UserID:    userID,
		ExpiresAt: now.Add(h.tokens.RefreshTTL()),
		CreatedAt: now,
	}); err != nil {
		h.logger.Error("save refresh token", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "failed to issue tokens")
		return
	}

	h.logger.Info("tokens issued", "user_id", userID, "username", username)
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int64(h.tokens.AccessTTL().Seconds()),
		RefreshToken: refreshRaw,
	})
}

// handleRevoke отзывает refresh-токен; идемпотентен.
func (h *handler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	if err := h.store.RevokeRefresh(r.Context(), hashRefresh(req.RefreshToken)); err != nil {
		h.logger.Error("revoke refresh token", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "revoke failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
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

// hashRefresh — хеш refresh-токена для ключа хранилища.
func hashRefresh(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
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
