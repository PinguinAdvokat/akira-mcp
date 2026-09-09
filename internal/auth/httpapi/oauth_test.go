package authhttp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
	authstorememory "github.com/PinguinAdvokat/akira-mcp/internal/auth/store/memory"
	authtoken "github.com/PinguinAdvokat/akira-mcp/internal/auth/token"
)

const (
	// testRedirectURI — зарегистрированный для тестовых клиентов URI.
	testRedirectURI = "http://127.0.0.1:8085/callback"
	// testCodeVerifier — фиксированный верификатор PKCE (43+ символа).
	testCodeVerifier = "test-verifier-test-verifier-test-verifier-1234"
)

// codeChallengeFor — S256-преобразование верификатора PKCE.
func codeChallengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// oauthEnv — auth-сервер, сконфигурированный для OAuth-тестов:
// публичный URL и фронтенд заданы, верифицированный пользователь
// создан. Возвращает также менеджера токенов — проверять выданные
// access-токены тем же путём, что внешний потребитель.
type oauthEnvResult struct {
	srv   *httpTestServer
	store *dbFailureStore
	mgr   *authtoken.Manager
	user  authstore.User
}

// httpTestServer — тонкая обёртка, чтобы не таскать httptest импорт
// в сигнатуры хелперов.
type httpTestServer = httptest.Server

// newOAuthEnv поднимает окружение OAuth-тестов.
func newOAuthEnv(t *testing.T) *oauthEnvResult {
	t.Helper()

	mgr, err := authtoken.NewManager(testIssuer, 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	store := &dbFailureStore{Store: authstorememory.New()}
	srv := httptest.NewServer(New(mgr, store, Config{
		Mail:        &captureMail{},
		EmailTTL:    time.Hour,
		PublicURL:   "http://auth.test",
		FrontendURL: "http://frontend.test/login",
		CodeTTL:     10 * time.Minute,
	}))
	t.Cleanup(srv.Close)

	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	ctx := context.Background()
	user, err := store.CreateUser(ctx, "oauthuser", "oauthuser@example.com", hash)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := store.VerifyEmail(ctx, user.ID); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	return &oauthEnvResult{srv: srv, store: store, mgr: mgr, user: user}
}

// registerClient проходит dynamic registration и возвращает client_id.
func registerClient(t *testing.T, srv *httpTestServer) string {
	t.Helper()
	body := map[string]any{
		"client_name":                "test-client",
		"redirect_uris":              []string{testRedirectURI},
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	}
	resp, m := postJSON(t, srv, "/oauth/register", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("registration: status %d, body %v", resp.StatusCode, m)
	}
	clientID, _ := m["client_id"].(string)
	if clientID == "" {
		t.Fatalf("registration: no client_id in %v", m)
	}
	return clientID
}

// authorizeQuery — query-строка запроса авторизации.
func authorizeQuery(clientID, challenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", testRedirectURI)
	q.Set("state", "xyz")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return q.Encode()
}

// confirmBody — тело POST /authorize/confirm.
func confirmBody(username, password, clientID, challenge string) map[string]any {
	return map[string]any{
		"username":              username,
		"password":              password,
		"response_type":         "code",
		"client_id":             clientID,
		"redirect_uri":          testRedirectURI,
		"scope":                 "",
		"state":                 "xyz",
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
	}
}

// confirmAuthorize проходит /authorize/confirm и возвращает код из location.
func confirmAuthorize(t *testing.T, srv *httpTestServer, username, password, clientID, challenge string) string {
	t.Helper()
	resp, m := postJSON(t, srv, "/authorize/confirm", confirmBody(username, password, clientID, challenge))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("confirm: status %d, body %v", resp.StatusCode, m)
	}
	location, _ := m["location"].(string)
	if location == "" {
		t.Fatalf("confirm: no location in %v", m)
	}
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("confirm: parse location %q: %v", location, err)
	}
	if u.Query().Get("state") != "xyz" {
		t.Fatalf("confirm: location state = %q, want xyz", u.Query().Get("state"))
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("confirm: no code in location %q", location)
	}
	if !strings.HasPrefix(location, testRedirectURI+"?") {
		t.Fatalf("confirm: location %q must start with redirect_uri", location)
	}
	return code
}

// postFormToken — POST /token с form-encoded телом (так шлют
// OAuth-клиенты, включая mcp-go).
func postFormToken(t *testing.T, srv *httpTestServer, form url.Values) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := srv.Client().Post(srv.URL+"/token",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp, m
}

// codeExchangeForm — form-тело обмена кода (grant_type, code, client_id,
// redirect_uri, code_verifier + игнорируемый resource RFC 8707).
func codeExchangeForm(code, clientID, verifier string) url.Values {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("redirect_uri", testRedirectURI)
	form.Set("code_verifier", verifier)
	form.Set("resource", "http://mcp.test/mcp")
	return form
}

// TestAuthServerMetadata — RFC 8414: поля, абсолютные URL, пути.
func TestAuthServerMetadata(t *testing.T) {
	env := newOAuthEnv(t)

	resp, err := env.srv.Client().Get(env.srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("GET metadata: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metadata status = %d", resp.StatusCode)
	}
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}

	for _, key := range []string{
		"issuer", "authorization_endpoint", "token_endpoint",
		"registration_endpoint", "revocation_endpoint", "jwks_uri",
	} {
		v, ok := m[key].(string)
		if !ok || !strings.HasPrefix(v, "http://auth.test") {
			t.Fatalf("metadata %s = %v, want absolute auth.test URL", key, m[key])
		}
	}
	if gts, ok := m["grant_types_supported"].([]any); !ok || len(gts) != 3 {
		t.Fatalf("metadata grant_types_supported = %v", m["grant_types_supported"])
	}
	if ccm, ok := m["code_challenge_methods_supported"].([]any); !ok || len(ccm) != 1 || ccm[0] != "S256" {
		t.Fatalf("metadata code_challenge_methods_supported = %v", m["code_challenge_methods_supported"])
	}
}

// TestOAuthRegister — dynamic registration: 201 + client_id,
// невалидные redirect_uri и конфиденциальные клиенты отклоняются.
func TestOAuthRegister(t *testing.T) {
	env := newOAuthEnv(t)

	clientID := registerClient(t, env.srv)
	if len(clientID) != authstore.OAuthClientLen {
		t.Fatalf("client_id length = %d, want %d", len(clientID), authstore.OAuthClientLen)
	}
	// Второй клиент с теми же redirect_uri — ок: redirect_uri
	// привязан к client_id, не глобально.
	if registerClient(t, env.srv) == "" {
		t.Fatal("second registration returned empty client_id")
	}

	// http на не-localhost — код уходил бы в открытом канале.
	resp, m := postJSON(t, env.srv, "/oauth/register", map[string]any{
		"redirect_uris": []string{"http://evil.example.com/cb"},
	})
	if resp.StatusCode != http.StatusBadRequest || m["error"] != "invalid_client_metadata" {
		t.Fatalf("insecure redirect_uri: status %d, error %v", resp.StatusCode, m["error"])
	}

	// Конфиденциальные клиенты не поддерживаются.
	resp, m = postJSON(t, env.srv, "/oauth/register", map[string]any{
		"redirect_uris":              []string{testRedirectURI},
		"token_endpoint_auth_method": "client_secret_post",
	})
	if resp.StatusCode != http.StatusBadRequest || m["error"] != "invalid_client_metadata" {
		t.Fatalf("confidential client: status %d, error %v", resp.StatusCode, m["error"])
	}
}

// TestAuthorizeRedirect — валидный /authorize редиректит на фронтенд,
// передавая query без изменений; ошибки — JSON 400 без редиректа.
func TestAuthorizeRedirect(t *testing.T) {
	env := newOAuthEnv(t)
	clientID := registerClient(t, env.srv)
	challenge := codeChallengeFor(testCodeVerifier)

	// Клиент без автоматических редиректов: смотрим Location руками.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(env.srv.URL + "/authorize?" + authorizeQuery(clientID, challenge))
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "http://frontend.test/login?") {
		t.Fatalf("authorize location = %q, want frontend URL with query", loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	q := u.Query()
	if q.Get("client_id") != clientID || q.Get("code_challenge") != challenge {
		t.Fatalf("authorize passthrough lost params: %v", q)
	}

	// Неизвестный клиент — JSON 400, не редирект.
	checkNoRedirect := func(label, query string) {
		t.Helper()
		resp, err := client.Get(env.srv.URL + "/authorize?" + query)
		if err != nil {
			t.Fatalf("GET /authorize (%s): %v", label, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: status %d, want 400", label, resp.StatusCode)
		}
		if resp.Header.Get("Location") != "" {
			t.Fatalf("%s: unexpected redirect to %q", label, resp.Header.Get("Location"))
		}
	}
	checkNoRedirect("unknown client", authorizeQuery("nonexistent", challenge))
	// Незарегистрированный redirect_uri — отказ (open redirect).
	foreignQuery := func(extra url.Values) string {
		t.Helper()
		q, err := url.ParseQuery(authorizeQuery(clientID, challenge))
		if err != nil {
			t.Fatalf("parse query: %v", err)
		}
		for k, vs := range extra {
			q[k] = vs // переопределяет исходные значения
		}
		return q.Encode()
	}
	checkNoRedirect("foreign redirect_uri", foreignQuery(url.Values{
		"redirect_uri": {"http://127.0.0.1:9999/other"},
	}))
	// PKCE plain запрещён.
	checkNoRedirect("plain PKCE", foreignQuery(url.Values{
		"code_challenge_method": {"plain"},
	}))
	// Отсутствующий code_challenge.
	checkNoRedirect("no PKCE", foreignQuery(url.Values{
		"code_challenge": {""},
	}))
	// Отсутствующий code_challenge_method (plain по умолчанию запрещён).
	checkNoRedirect("default PKCE method", foreignQuery(url.Values{
		"code_challenge_method": {""},
	}))
}

// TestAuthorizeConfirm — подтверждение логина: успешный location
// с кодом; неверный пароль и неверифицированный email — одинаковый 401.
func TestAuthorizeConfirm(t *testing.T) {
	env := newOAuthEnv(t)
	clientID := registerClient(t, env.srv)
	challenge := codeChallengeFor(testCodeVerifier)

	code := confirmAuthorize(t, env.srv, "oauthuser", "secret123", clientID, challenge)
	if code == "" {
		t.Fatal("no code in confirm location")
	}

	// Неверный пароль — 401.
	resp, m := postJSON(t, env.srv, "/authorize/confirm",
		confirmBody("oauthuser", "wrong", clientID, challenge))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: status %d, body %v", resp.StatusCode, m)
	}
	wrongPassword := m

	// Неверифицированный пользователь — тот же ответ (анти-энумерация).
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	if _, err := env.store.CreateUser(context.Background(), "unverified", "unverified@example.com", hash); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	resp, m = postJSON(t, env.srv, "/authorize/confirm",
		confirmBody("unverified", "secret123", clientID, challenge))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unverified: status %d, want 401", resp.StatusCode)
	}
	if m["error"] != wrongPassword["error"] || m["error_description"] != wrongPassword["error_description"] {
		t.Fatalf("unverified answer %v differs from wrong password %v", m, wrongPassword)
	}
}

// TestAuthorizationCodeGrant — полный обмен кода: form-encoded /token,
// PKCE S256, access верифицируется менеджером (sub — тот, что логинился);
// повторное использование кода — invalid_grant.
func TestAuthorizationCodeGrant(t *testing.T) {
	env := newOAuthEnv(t)
	clientID := registerClient(t, env.srv)
	challenge := codeChallengeFor(testCodeVerifier)

	code := confirmAuthorize(t, env.srv, "oauthuser", "secret123", clientID, challenge)

	resp, m := postFormToken(t, env.srv, codeExchangeForm(code, clientID, testCodeVerifier))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("code exchange: status %d, body %v", resp.StatusCode, m)
	}
	access, _ := m["access_token"].(string)
	refresh, _ := m["refresh_token"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("no tokens in %v", m)
	}
	if m["token_type"] != "Bearer" {
		t.Fatalf("token_type = %v", m["token_type"])
	}
	tok, err := env.mgr.ParseAccessToken([]byte(access))
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	if sub, _ := tok.Subject(); sub != env.user.ID {
		t.Fatalf("token sub = %q, want %q", sub, env.user.ID)
	}

	// Повторное использование кода — invalid_grant.
	resp, m = postFormToken(t, env.srv, codeExchangeForm(code, clientID, testCodeVerifier))
	if resp.StatusCode != http.StatusUnauthorized || m["error"] != "invalid_grant" {
		t.Fatalf("code replay: status %d, error %v", resp.StatusCode, m["error"])
	}
}

// TestAuthorizationCodeGrantMisuse — неверный PKCE-верификатор
// и чужой client_id — invalid_grant.
func TestAuthorizationCodeGrantMisuse(t *testing.T) {
	env := newOAuthEnv(t)
	clientID := registerClient(t, env.srv)
	otherClient := registerClient(t, env.srv)
	challenge := codeChallengeFor(testCodeVerifier)

	// Неверный verifier.
	code := confirmAuthorize(t, env.srv, "oauthuser", "secret123", clientID, challenge)
	resp, m := postFormToken(t, env.srv,
		codeExchangeForm(code, clientID, "wrong-verifier-wrong-verifier-wrong-verifier-123"))
	if resp.StatusCode != http.StatusUnauthorized || m["error"] != "invalid_grant" {
		t.Fatalf("wrong verifier: status %d, error %v", resp.StatusCode, m["error"])
	}

	// Чужой client_id: код выпущен для другого клиента.
	code2 := confirmAuthorize(t, env.srv, "oauthuser", "secret123", clientID, challenge)
	resp, m = postFormToken(t, env.srv, codeExchangeForm(code2, otherClient, testCodeVerifier))
	if resp.StatusCode != http.StatusUnauthorized || m["error"] != "invalid_grant" {
		t.Fatalf("foreign client: status %d, error %v", resp.StatusCode, m["error"])
	}
}

// TestTokenFormPasswordGrant — password grant работает и через
// form-encoded тело.
func TestTokenFormPasswordGrant(t *testing.T) {
	env := newOAuthEnv(t)

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "oauthuser")
	form.Set("password", "secret123")
	resp, m := postFormToken(t, env.srv, form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("form password grant: status %d, body %v", resp.StatusCode, m)
	}
	if m["access_token"] == nil {
		t.Fatalf("no access_token in %v", m)
	}
}

// TestAuthorizeStoreFailure — сбой стора в /authorize/confirm — 500,
// наружу не маскируется под 401 (состояние одноразовых кодов цело).
func TestAuthorizeStoreFailure(t *testing.T) {
	env := newOAuthEnv(t)
	clientID := registerClient(t, env.srv)
	challenge := codeChallengeFor(testCodeVerifier)

	env.store.failOn("GetUserByUsername")
	resp, m := postJSON(t, env.srv, "/authorize/confirm",
		confirmBody("oauthuser", "secret123", clientID, challenge))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("store failure: status %d, body %v", resp.StatusCode, m)
	}
	if m["error"] != "server_error" {
		t.Fatalf("store failure: error = %v", m["error"])
	}
}
