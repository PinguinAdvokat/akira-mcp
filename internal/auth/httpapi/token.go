package authhttp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
)

// tokenRequest — тело POST /token: JSON (password/refresh_token
// grants, наш API) или form-encoded (authorization_code grant —
// так OAuth-клиенты по RFC 6749 §4.1.3, включая mcp-go).
type tokenRequest struct {
	GrantType    string `json:"grant_type"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	RefreshToken string `json:"refresh_token"`

	// Поля authorization_code grant.
	Code         string `json:"code"`
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	CodeVerifier string `json:"code_verifier"`
}

// tokenResponse — успешный ответ POST /token.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

func (h *handler) handleToken(w http.ResponseWriter, r *http.Request) {
	req, ok := parseTokenRequest(w, r)
	if !ok {
		return
	}

	switch req.GrantType {
	case "password":
		h.grantPassword(w, r.Context(), req)
	case "refresh_token":
		h.grantRefresh(w, r.Context(), req)
	case "authorization_code":
		h.grantAuthorizationCode(w, r.Context(), req)
	default:
		writeError(w, http.StatusBadRequest, "unsupported_grant_type",
			"grant_type must be authorization_code, password or refresh_token")
	}
}

// parseTokenRequest разбирает тело POST /token — form-encoded
// (OAuth-клиенты, RFC 6749) или JSON (наш собственный API). Лимит
// тела тот же, что у JSON-эндпоинтов (maxBodyBytes). Одинаковый
// параметр в обоих форматах — одно значение (form приоритетнее).
func parseTokenRequest(w http.ResponseWriter, r *http.Request) (tokenRequest, bool) {
	ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
	if strings.EqualFold(strings.TrimSpace(ct), "application/x-www-form-urlencoded") {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		if err := r.ParseForm(); err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large")
				return tokenRequest{}, false
			}
			writeError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
			return tokenRequest{}, false
		}
		return tokenRequest{
			GrantType:    r.PostFormValue("grant_type"),
			Username:     r.PostFormValue("username"),
			Password:     r.PostFormValue("password"),
			RefreshToken: r.PostFormValue("refresh_token"),
			Code:         r.PostFormValue("code"),
			ClientID:     r.PostFormValue("client_id"),
			RedirectURI:  r.PostFormValue("redirect_uri"),
			CodeVerifier: r.PostFormValue("code_verifier"),
			// resource (RFC 8707) шлют mcp-go-клиенты — принят и
			// игнорируется: ресурс один, аудит не ведём.
		}, true
	}

	var req tokenRequest
	if !decodeJSON(w, r, &req) {
		return tokenRequest{}, false
	}
	return req, true
}

// grantPassword проверяет учётные данные и выдаёт новую пару токенов.
// Проверка — общий с /authorize/confirm хелпер checkCredentials
// (анти-энумерация: одинаковый ответ и одинаковое время на неверное
// имя, неверный пароль и неподтверждённый email).
func (h *handler) grantPassword(w http.ResponseWriter, ctx context.Context, req tokenRequest) {
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "username and password are required")
		return
	}

	user, ok := h.checkCredentials(w, ctx, req.Username, req.Password)
	if !ok {
		return
	}
	h.issuePair(w, ctx, user.ID, user.Username)
}

// grantAuthorizationCode обменивает одноразовый код на пару токенов.
// Проверки: код существует и не истёк (ConsumeOAuthCode атомарен —
// повторное использование кода и конкурентный обмен побеждает ровно
// один вызов), client_id и redirect_uri совпадают с записью кода
// (иначе код, выданный для одного клиента, можно обменять другим),
// PKCE S256: base64url(sha256(code_verifier)) == code_challenge.
// Несовпадение — invalid_grant (единый ответ, деталей наружу нет).
func (h *handler) grantAuthorizationCode(w http.ResponseWriter, ctx context.Context, req tokenRequest) {
	if req.Code == "" || req.ClientID == "" || req.RedirectURI == "" || req.CodeVerifier == "" {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"code, client_id, redirect_uri and code_verifier are required")
		return
	}

	code, err := h.store.ConsumeOAuthCode(ctx, hashToken(req.Code))
	if err != nil {
		if errors.Is(err, authstore.ErrOAuthCodeNotFound) {
			h.logger.Warn("authorization code grant failed",
				"reason", "unknown, expired or already used code")
			writeError(w, http.StatusUnauthorized, "invalid_grant",
				"unknown, expired or already used authorization code")
			return
		}
		h.logger.Error("consume oauth code", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}

	if code.ClientID != req.ClientID || code.RedirectURI != req.RedirectURI {
		h.logger.Warn("authorization code grant failed", "reason", "client or redirect mismatch")
		writeError(w, http.StatusUnauthorized, "invalid_grant", "invalid authorization code")
		return
	}
	// PKCE S256 (plain запрещён ещё на /authorize). Верификатор
	// обязателен: без него публичический клиент беззащитен перед
	// перехватом кода.
	sum := sha256.Sum256([]byte(req.CodeVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != code.CodeChallenge {
		h.logger.Warn("authorization code grant failed", "reason", "pkce verification failed")
		writeError(w, http.StatusUnauthorized, "invalid_grant", "invalid authorization code")
		return
	}

	h.issuePair(w, ctx, code.UserID, "")
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
