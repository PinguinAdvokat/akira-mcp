package authhttp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
)

// pkceChallengeMin/PkceChallengeMax — границы длины code_challenge
// по RFC 7636 (43–128 символов).
const (
	pkceChallengeMin = 43
	pkceChallengeMax = 128
)

// authServerMetadata — метаданные авторизационного сервера (RFC 8414).
// Клиент mcp-go требует: все URL абсолютные http(s) с хостом (иначе
// metadata отвергается), grant authorization_code, PKCE S256,
// аутентификация клиента не требуется (публичические клиенты).
type authServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
}

// handleAuthServerMetadata отдаёт метаданные авторизационного сервера
// (RFC 8414). Формат фиксирован конфигурацией, тело кешировать можно
// на стороне клиента; no-store — чтобы смена схемы не протухала.
func (h *handler) handleAuthServerMetadata(w http.ResponseWriter, _ *http.Request) {
	base := strings.TrimSuffix(h.cfg.PublicURL, "/")
	if base == "" {
		writeError(w, http.StatusInternalServerError, "server_error", "public url is not configured")
		return
	}
	// Заголовок обязан быть выставлен до writeJSON: он вызывает
	// WriteHeader, после чего изменения заголовков игнорируются.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, authServerMetadata{
		Issuer:                            base,
		AuthorizationEndpoint:             base + "/authorize",
		TokenEndpoint:                     base + "/token",
		RegistrationEndpoint:              base + "/oauth/register",
		RevocationEndpoint:                base + "/revoke",
		JwksURI:                           base + "/jwks.json",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token", "password"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ScopesSupported:                   []string{},
	})
}

// registrationRequest — тело POST /oauth/register (RFC 7591). Лишние
// поля (scope, resource, client_uri…) принимаются и игнорируются.
type registrationRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
}

// registrationResponse — ответ POST /oauth/register. Секрета нет:
// клиент публичический (token_endpoint_auth_method=none).
type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// handleOAuthRegister — dynamic client registration (RFC 7591):
// MCP-клиент регистрируется сам перед первым authorization code flow.
// Публичический эндпоинт; ограничение частоты — на nginx.
func (h *handler) handleOAuthRegister(w http.ResponseWriter, r *http.Request) {
	var req registrationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_client_metadata", "redirect_uris is required")
		return
	}
	for _, uri := range req.RedirectURIs {
		if err := validateRedirectURI(uri); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
			return
		}
	}
	// Конфиденциальные клиенты не поддерживаются: секрета нет, обмен
	// аутентифицируется PKCE. Пустое значение трактуем как "none".
	switch req.TokenEndpointAuthMethod {
	case "", "none":
	default:
		writeError(w, http.StatusBadRequest, "invalid_client_metadata",
			"token_endpoint_auth_method must be \"none\"")
		return
	}

	clientID, err := authstore.GenerateOAuthClientID()
	if err != nil {
		h.logger.Error("generate oauth client id", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "registration failed")
		return
	}
	client := authstore.OAuthClient{
		ClientID:     clientID,
		ClientName:   req.ClientName,
		RedirectURIs: req.RedirectURIs,
		CreatedAt:    time.Now(),
	}
	if err := h.store.SaveOAuthClient(r.Context(), client); err != nil {
		h.logger.Error("save oauth client", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "registration failed")
		return
	}

	h.logger.Info("oauth client registered", "client_id", clientID, "client_name", req.ClientName)
	writeJSON(w, http.StatusCreated, registrationResponse{
		ClientID:                clientID,
		ClientName:              client.ClientName,
		RedirectURIs:            client.RedirectURIs,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
	})
}

// authorizeParams — параметры запроса авторизации, общие для
// GET /authorize и POST /authorize/confirm. Отдельно от JSON-структуры
// confirm: query и тело приходят из разных мест.
type authorizeParams struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// validateAuthorize проверяет параметры авторизации: клиент существует,
// redirect_uri совпадает с зарегистрированным (точное совпадение —
// это обязательная защита от open redirect), PKCE обязателен (S256).
// Возвращает клиента или пишет ошибку и возвращает nil.
func (h *handler) validateAuthorize(w http.ResponseWriter, ctx context.Context, p authorizeParams) *authstore.OAuthClient {
	if p.ResponseType != "code" {
		writeError(w, http.StatusBadRequest, "unsupported_response_type", "response_type must be \"code\"")
		return nil
	}
	if p.ClientID == "" || p.RedirectURI == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "client_id and redirect_uri are required")
		return nil
	}
	// code_challenge обязателен: публичические клиенты без секрета
	// без PKCE уязвимы к перехвату кода.
	if len(p.CodeChallenge) < pkceChallengeMin || len(p.CodeChallenge) > pkceChallengeMax {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"code_challenge is required and must be 43..128 characters")
		return nil
	}
	if p.CodeChallengeMethod != "S256" {
		// plain запрещён: challenge из него тривиально подменить.
		writeError(w, http.StatusBadRequest, "invalid_request", "code_challenge_method must be \"S256\"")
		return nil
	}

	client, err := h.store.GetOAuthClient(ctx, p.ClientID)
	if err != nil {
		if errors.Is(err, authstore.ErrOAuthClientNotFound) {
			writeError(w, http.StatusBadRequest, "invalid_client", "unknown client_id")
			return nil
		}
		h.logger.Error("lookup oauth client", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "authorization failed")
		return nil
	}
	// Точное совпадение с одним из зарегистрированных URI: редирект
	// на произвольный URL — открытый редиректор.
	known := false
	for _, uri := range client.RedirectURIs {
		if uri == p.RedirectURI {
			known = true
			break
		}
	}
	if !known {
		writeError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is not registered for this client")
		return nil
	}
	return &client
}

// handleAuthorize — точка входа authorization code flow. Формы логина
// в auth-сервисе нет (фронтенд — отдельный проект): после валидации
// запрос 302-редиректится на FrontendURL, передавая исходные
// OAuth-параметры в query — их фронтенд отправит обратно
// в POST /authorize/confirm.
func (h *handler) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	params := authorizeParams{
		ResponseType:        q.Get("response_type"),
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
	}
	if h.validateAuthorize(w, r.Context(), params) == nil {
		return
	}

	frontend := strings.TrimSuffix(h.cfg.FrontendURL, "/")
	if frontend == "" {
		writeError(w, http.StatusServiceUnavailable, "server_error",
			"authorization UI is not configured (AUTH_FRONTEND_URL is empty)")
		return
	}
	// Passthrough исходного query: параметры уже провалидированы,
	// дополнительные (кроме стандартных) фронтенд прочитает из URL.
	http.Redirect(w, r, frontend+"?"+r.URL.RawQuery, http.StatusFound)
}

// authorizeConfirmRequest — тело POST /authorize/confirm: учётные
// данные пользователя и все параметры авторизации из /authorize
// (фронтенд передаёт их обратно без изменений).
type authorizeConfirmRequest struct {
	Username            string `json:"username"`
	Password            string `json:"password"`
	ResponseType        string `json:"response_type"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// authorizeConfirmResponse — успешный ответ POST /authorize/confirm.
// Location — итоговый redirect_uri с code и state: фронтенд выполняет
// навигацию на него (или отдаёт ссылку пользователю).
type authorizeConfirmResponse struct {
	Location string `json:"location"`
}

// handleAuthorizeConfirm — подтверждение логина фронтендом: проверка
// учётных данных и параметров авторизации, выпуск одноразового кода.
// Ответ — location для навигации, не редирект сам по себе: эндпоинт
// зовётся из JavaScript фронтенда.
func (h *handler) handleAuthorizeConfirm(w http.ResponseWriter, r *http.Request) {
	var req authorizeConfirmRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	user, ok := h.checkCredentials(w, r.Context(), req.Username, req.Password)
	if !ok {
		return
	}
	params := authorizeParams{
		ResponseType:        req.ResponseType,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	}
	if h.validateAuthorize(w, r.Context(), params) == nil {
		return
	}

	codeRaw, codeHash, err := authstore.GenerateOAuthCode()
	if err != nil {
		h.logger.Error("generate oauth code", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "authorization failed")
		return
	}
	now := time.Now()
	if err := h.store.SaveOAuthCode(r.Context(), authstore.OAuthCode{
		CodeHash:            codeHash,
		UserID:              user.ID,
		ClientID:            params.ClientID,
		RedirectURI:         params.RedirectURI,
		Scope:               params.Scope,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		ExpiresAt:           now.Add(h.cfg.CodeTTL),
		CreatedAt:           now,
	}); err != nil {
		h.logger.Error("save oauth code", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "authorization failed")
		return
	}

	// redirect_uri уже провалидирован (точное совпадение с
	// зарегистрированным), конкатенация параметров безопасна.
	location := params.RedirectURI + "?code=" + url.QueryEscape(codeRaw)
	if params.State != "" {
		location += "&state=" + url.QueryEscape(params.State)
	}

	h.logger.Info("oauth code issued", "user_id", user.ID, "client_id", params.ClientID)
	writeJSON(w, http.StatusOK, authorizeConfirmResponse{Location: location})
}

// checkCredentials проверяет имя и пароль. Неподтверждённый email
// и неизвестное имя — тот же ответ и то же время работы, что и при
// неверном пароле (анти-энумерация): bcrypt-сравнение выполняется
// всегда. Возвращает пользователя или пишет 401 и возвращает nil.
func (h *handler) checkCredentials(w http.ResponseWriter, ctx context.Context, username, password string) (*authstore.User, bool) {
	if username == "" || password == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "username and password are required")
		return nil, false
	}

	user, err := h.store.GetUserByUsername(ctx, username)
	if err != nil {
		if !errors.Is(err, authstore.ErrUserNotFound) {
			// Сбой стора — не «неверные учётные данные»: наружу 500.
			h.logger.Error("authorize confirm: lookup user", "err", err)
			writeError(w, http.StatusInternalServerError, "server_error", "authorization failed")
			return nil, false
		}
		// Неизвестное имя: то же bcrypt-сравнение, чтобы время ответа
		// не выдавало существование учётной записи.
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		h.logger.Warn("authorize confirm failed", "username", username)
		writeError(w, http.StatusUnauthorized, "invalid_grant", "invalid credentials")
		return nil, false
	}
	if bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password)) != nil || !user.EmailVerified {
		h.logger.Warn("authorize confirm failed", "username", username, "verified", user.EmailVerified)
		writeError(w, http.StatusUnauthorized, "invalid_grant", "invalid credentials")
		return nil, false
	}
	return &user, true
}

// validateRedirectURI допускает только https или http на localhost
// (127.0.0.1, ::1) — как transport.ValidateRedirectURI у mcp-go:
// http на внешнем хосте означал бы код в открытом канале.
func validateRedirectURI(redirectURI string) error {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return errors.New("invalid redirect_uri")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return errors.New("http redirect_uri is only allowed for localhost")
	}
	return errors.New("redirect_uri must use http or https")
}
