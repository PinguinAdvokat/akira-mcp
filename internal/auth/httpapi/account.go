package authhttp

import (
	"context"
	"errors"
	"net/http"
	"strings"

	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
)

// handleMe отдаёт данные аккаунта владельца access-токена.
func (h *handler) handleMe(w http.ResponseWriter, r *http.Request) {
	user, ok := h.userFromBearer(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":     user.ID,
		"username":    user.Username,
		"email":       user.Email,
		"verified":    user.EmailVerified,
		"connect_key": user.ConnectKey,
	})
}

// handleRegenerateConnectKey заменяет connect_key владельца access-токена.
// Подключения, держащие старый ключ, продолжают работать до разрыва —
// ключ проверяется только при подключении.
func (h *handler) handleRegenerateConnectKey(w http.ResponseWriter, r *http.Request) {
	user, ok := h.userFromBearer(w, r)
	if !ok {
		return
	}
	key, err := h.assignConnectKey(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("regenerate connect key", "user_id", user.ID, "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "failed to regenerate connect key")
		return
	}
	h.logger.Info("connect key regenerated", "user_id", user.ID)
	writeJSON(w, http.StatusOK, map[string]string{"connect_key": key})
}

// userFromBearer достаёт пользователя из заголовка Authorization:
// Bearer <access-jwt>. При проблемах сам пишет ответ и возвращает false.
func (h *handler) userFromBearer(w http.ResponseWriter, r *http.Request) (authstore.User, bool) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		writeError(w, http.StatusUnauthorized, "invalid_token", "Authorization: Bearer <access_token> is required")
		return authstore.User{}, false
	}
	tok, err := h.tokens.ParseAccessToken([]byte(token))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token", "invalid or expired access token")
		return authstore.User{}, false
	}
	sub, ok := tok.Subject()
	if !ok || sub == "" {
		writeError(w, http.StatusUnauthorized, "invalid_token", "invalid or expired access token")
		return authstore.User{}, false
	}
	user, err := h.store.GetUserByID(r.Context(), sub)
	if err != nil {
		if !errors.Is(err, authstore.ErrUserNotFound) {
			// Токен валиден, но стор лежит — это не «невалидный токен».
			h.logger.Error("bearer: lookup user", "user_id", sub, "err", err)
			writeError(w, http.StatusInternalServerError, "server_error", "request failed")
			return authstore.User{}, false
		}
		// Токен валиден, а пользователя нет (например, удалён).
		h.logger.Warn("bearer user not found", "user_id", sub)
		writeError(w, http.StatusUnauthorized, "invalid_token", "invalid or expired access token")
		return authstore.User{}, false
	}
	return user, true
}

// assignConnectKey генерирует ключ и назначает его пользователю;
// при коллизии с чужим ключом генерирует заново.
func (h *handler) assignConnectKey(ctx context.Context, userID string) (string, error) {
	for attempt := 0; attempt < connectKeyAttempts; attempt++ {
		key, err := authstore.GenerateConnectKey()
		if err != nil {
			return "", err
		}
		err = h.store.SetConnectKey(ctx, userID, key)
		if errors.Is(err, authstore.ErrConnectKeyExists) {
			continue
		}
		if err != nil {
			return "", err
		}
		return key, nil
	}
	return "", errors.New("connect key space exhausted")
}
