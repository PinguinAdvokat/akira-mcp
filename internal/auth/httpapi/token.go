package authhttp

import (
	"context"
	"errors"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
)

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

func (h *handler) handleToken(w http.ResponseWriter, r *http.Request) {
	var req tokenRequest
	if !decodeJSON(w, r, &req) {
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
// Неподтверждённый email и неизвестное имя — тот же ответ и то же время
// работы, что и при неверном пароле (анти-энумерация): bcrypt-сравнение
// выполняется всегда, и до него проверяется пароль, а не верификация.
func (h *handler) grantPassword(w http.ResponseWriter, ctx context.Context, req tokenRequest) {
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "username and password are required")
		return
	}

	user, err := h.store.GetUserByUsername(ctx, req.Username)
	if err != nil {
		if !errors.Is(err, authstore.ErrUserNotFound) {
			// Сбой стора — не «неверные учётные данные»: наружу 500.
			h.logger.Error("password grant: lookup user", "err", err)
			writeError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
			return
		}
		// Неизвестное имя: то же bcrypt-сравнение, чтобы время ответа
		// не выдавало существование учётной записи.
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(req.Password))
		h.logger.Warn("password grant failed", "username", req.Username)
		writeError(w, http.StatusUnauthorized, "invalid_grant", "invalid credentials")
		return
	}
	if bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(req.Password)) != nil || !user.EmailVerified {
		h.logger.Warn("password grant failed", "username", req.Username, "verified", user.EmailVerified)
		writeError(w, http.StatusUnauthorized, "invalid_grant", "invalid credentials")
		return
	}

	h.issuePair(w, ctx, user.ID, user.Username)
}

// grantRefresh заменяет refresh-токен новым (одноразовость: ротация)
// и выдаёт новую пару. Неизвестный, истёкший или уже использованный
// токен — invalid_grant; сбой хранилища — server_error, при этом
// старый токен не сжигается (ротация атомарна).
func (h *handler) grantRefresh(w http.ResponseWriter, ctx context.Context, req tokenRequest) {
	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	// Ротация атомарна: потребление старого токена и сохранение нового —
	// одна операция стора. Раньше consume и save были раздельными, и
	// транзиентный сбой между ними уничтожал сессию. Подпись access —
	// уже поверх состоявшейся ротации (это чистая криптография в памяти,
	// она не падает от состояния БД).
	refreshRaw, refreshHash, err := h.tokens.NewRefreshToken()
	if err != nil {
		h.logger.Error("generate refresh token", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "failed to issue tokens")
		return
	}
	now := time.Now()
	rec, err := h.store.RotateRefresh(ctx, hashToken(req.RefreshToken), authstore.RefreshToken{
		TokenHash: refreshHash,
		ExpiresAt: now.Add(h.tokens.RefreshTTL()),
		CreatedAt: now,
	})
	if err != nil {
		if errors.Is(err, authstore.ErrRefreshNotFound) {
			h.logger.Warn("refresh grant failed", "reason", "unknown, expired or already used token")
			writeError(w, http.StatusUnauthorized, "invalid_grant", "unknown, expired or already used refresh token")
			return
		}
		h.logger.Error("rotate refresh token", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}

	access, err := h.tokens.NewAccessToken(rec.UserID)
	if err != nil {
		h.logger.Error("sign access token", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "failed to issue tokens")
		return
	}

	h.logger.Info("tokens issued", "user_id", rec.UserID, "grant", "refresh_token")
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int64(h.tokens.AccessTTL().Seconds()),
		RefreshToken: refreshRaw,
	})
}

// issuePair выпускает access + refresh и сохраняет хеш refresh в стор.
// Используется там, где старого refresh-токена нет (логин и верификация);
// ротация существующего — grantRefresh через RotateRefresh.
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
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	if err := h.store.RevokeRefresh(r.Context(), hashToken(req.RefreshToken)); err != nil {
		h.logger.Error("revoke refresh token", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "revoke failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
