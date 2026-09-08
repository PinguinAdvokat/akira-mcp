package authhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"golang.org/x/crypto/bcrypt"

	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
	authstorememory "github.com/PinguinAdvokat/akira-mcp/internal/auth/store/memory"
	authtoken "github.com/PinguinAdvokat/akira-mcp/internal/auth/token"
)

const testIssuer = "akira-test"

// errDBDown — «транзиентный сбой БД» для обёртки dbFailureStore.
var errDBDown = errors.New("db: connection refused")

// captureMail — тестовый отправитель писем: запоминает коды
// подтверждения, чтобы тест мог «прочитать письмо»; по флагу fail
// имитирует отказ почты.
type captureMail struct {
	mu    sync.Mutex
	codes []string
	fail  bool
}

func (c *captureMail) SendCode(_ context.Context, _, code, _ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return errors.New("smtp: connection refused")
	}
	c.codes = append(c.codes, code)
	return nil
}

// setFail включает/выключает отказы отправки.
func (c *captureMail) setFail(on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fail = on
}

// lastCode возвращает последний отправленный код подтверждения.
func (c *captureMail) lastCode() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.codes) == 0 {
		return ""
	}
	return c.codes[len(c.codes)-1]
}

// count возвращает число отправленных писем.
func (c *captureMail) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.codes)
}

// dbFailureStore — обёртка над memory-стором: помеченные методы
// возвращают errDBDown, имитируя транзиентный сбой БД.
type dbFailureStore struct {
	authstore.Store

	mu     sync.Mutex
	broken map[string]bool
}

func (s *dbFailureStore) failOn(method string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken == nil {
		s.broken = make(map[string]bool)
	}
	s.broken[method] = true
}

func (s *dbFailureStore) fix(method string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.broken, method)
}

func (s *dbFailureStore) down(method string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.broken[method]
}

func (s *dbFailureStore) GetUserByUsername(ctx context.Context, username string) (authstore.User, error) {
	if s.down("GetUserByUsername") {
		return authstore.User{}, errDBDown
	}
	return s.Store.GetUserByUsername(ctx, username)
}

func (s *dbFailureStore) GetUserByEmail(ctx context.Context, email string) (authstore.User, error) {
	if s.down("GetUserByEmail") {
		return authstore.User{}, errDBDown
	}
	return s.Store.GetUserByEmail(ctx, email)
}

func (s *dbFailureStore) GetUserByID(ctx context.Context, userID string) (authstore.User, error) {
	if s.down("GetUserByID") {
		return authstore.User{}, errDBDown
	}
	return s.Store.GetUserByID(ctx, userID)
}

func (s *dbFailureStore) RotateRefresh(ctx context.Context, oldTokenHash string, newTok authstore.RefreshToken) (authstore.RefreshToken, error) {
	if s.down("RotateRefresh") {
		return authstore.RefreshToken{}, errDBDown
	}
	return s.Store.RotateRefresh(ctx, oldTokenHash, newTok)
}

// newTestEnv поднимает хендлер над in-memory стором и менеджером
// токенов; возвращает сервер, функцию для создания пользователя
// (сразу с подтверждённым email — иначе password grant запрещён)
// и тестовый отправитель писем.
func newTestEnv(t *testing.T) (*httptest.Server, func(username, password string), *captureMail) {
	t.Helper()
	srv, _, createUser, mail := newTestEnvStore(t)
	return srv, createUser, mail
}

// newTestEnvStore — как newTestEnv, но с прямым доступом к стору
// (тесты «роняют БД» через failOn) и счётчиком писем.
func newTestEnvStore(t *testing.T) (*httptest.Server, *dbFailureStore, func(username, password string), *captureMail) {
	t.Helper()

	mgr, err := authtoken.NewManager(testIssuer, 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	store := &dbFailureStore{Store: authstorememory.New()}
	mail := &captureMail{}
	srv := httptest.NewServer(New(mgr, store, Config{
		Mail:     mail,
		EmailTTL: time.Hour,
	}))
	t.Cleanup(srv.Close)

	createUser := func(username, password string) {
		t.Helper()
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("bcrypt: %v", err)
		}
		ctx := context.Background()
		u, err := store.CreateUser(ctx, username, username+"@example.com", hash)
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if err := store.VerifyEmail(ctx, u.ID); err != nil {
			t.Fatalf("VerifyEmail: %v", err)
		}
	}
	return srv, store, createUser, mail
}

// postJSONAuth — postJSON с заголовком Authorization.
func postJSONAuth(t *testing.T, srv *httptest.Server, path string, body any, bearer string) (*http.Response, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp, m
}

func postJSON(t *testing.T, srv *httptest.Server, path string, body any) (*http.Response, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := srv.Client().Post(srv.URL+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	var m map[string]any
	// У 204 (revoke) тела нет — пустой ответ валиден.
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp, m
}

func TestPasswordGrantEndToEnd(t *testing.T) {
	srv, createUser, _ := newTestEnv(t)
	createUser("alice", "secret")

	resp, body := postJSON(t, srv, "/token", map[string]string{
		"grant_type": "password",
		"username":   "alice",
		"password":   "secret",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %v", resp.StatusCode, body)
	}
	access, _ := body["access_token"].(string)
	refresh, _ := body["refresh_token"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("missing tokens in response: %v", body)
	}
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", body["token_type"])
	}
	if exp, _ := body["expires_in"].(float64); exp != 900 {
		t.Errorf("expires_in = %v, want 900", exp)
	}

	// Проверяем access-токен как внешний потребитель: JWKS + подпись.
	jwksResp, err := srv.Client().Get(srv.URL + "/jwks.json")
	if err != nil {
		t.Fatalf("GET /jwks.json: %v", err)
	}
	defer jwksResp.Body.Close()
	jwksBytes, err := io.ReadAll(jwksResp.Body)
	if err != nil {
		t.Fatalf("read jwks body: %v", err)
	}
	set, err := jwk.Parse(jwksBytes)
	if err != nil {
		t.Fatalf("jwk.Parse: %v", err)
	}

	parsed, err := jwt.Parse([]byte(access),
		jwt.WithKeySet(set, jws.WithRequireKid(true)),
		jwt.WithValidate(true),
		jwt.WithIssuer(testIssuer),
	)
	if err != nil {
		t.Fatalf("consumer-side token verification failed: %v", err)
	}
	if sub, _ := parsed.Subject(); sub == "" {
		t.Fatal("sub is empty")
	}
	var typ string
	if err := parsed.Get("typ", &typ); err != nil || typ != "access" {
		t.Fatalf("typ = %q (err %v), want access", typ, err)
	}
}

func TestRefreshRotationAndReplay(t *testing.T) {
	srv, createUser, _ := newTestEnv(t)
	createUser("alice", "secret")

	_, first := postJSON(t, srv, "/token", map[string]string{
		"grant_type": "password", "username": "alice", "password": "secret",
	})
	oldRefresh, _ := first["refresh_token"].(string)

	// Ротация: старый refresh обменивается на новую пару.
	resp, rotated := postJSON(t, srv, "/token", map[string]string{
		"grant_type": "refresh_token", "refresh_token": oldRefresh,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh grant status = %d, body = %v", resp.StatusCode, rotated)
	}
	newRefresh, _ := rotated["refresh_token"].(string)
	if newRefresh == "" || newRefresh == oldRefresh {
		t.Fatalf("rotation must issue a new refresh token, got %q", newRefresh)
	}

	// Replay старого: он уже потреблён — 401.
	resp, body := postJSON(t, srv, "/token", map[string]string{
		"grant_type": "refresh_token", "refresh_token": oldRefresh,
	})
	if resp.StatusCode != http.StatusUnauthorized || body["error"] != "invalid_grant" {
		t.Fatalf("replayed refresh: status = %d, body = %v", resp.StatusCode, body)
	}

	// Новый refresh продолжает работать.
	resp, body = postJSON(t, srv, "/token", map[string]string{
		"grant_type": "refresh_token", "refresh_token": newRefresh,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("new refresh status = %d, body = %v", resp.StatusCode, body)
	}
}

func TestRevoke(t *testing.T) {
	srv, createUser, _ := newTestEnv(t)
	createUser("alice", "secret")

	_, pair := postJSON(t, srv, "/token", map[string]string{
		"grant_type": "password", "username": "alice", "password": "secret",
	})
	refresh, _ := pair["refresh_token"].(string)

	resp, _ := postJSON(t, srv, "/revoke", map[string]string{"refresh_token": refresh})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke status = %d, want 204", resp.StatusCode)
	}

	// Повторный revoke того же токена — тоже 204 (идемпотентность).
	resp, _ = postJSON(t, srv, "/revoke", map[string]string{"refresh_token": refresh})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("second revoke status = %d, want 204", resp.StatusCode)
	}

	resp, body := postJSON(t, srv, "/token", map[string]string{
		"grant_type": "refresh_token", "refresh_token": refresh,
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked refresh: status = %d, body = %v", resp.StatusCode, body)
	}
}

func TestGrantErrors(t *testing.T) {
	srv, createUser, _ := newTestEnv(t)
	createUser("alice", "secret")

	cases := []struct {
		name    string
		body    map[string]string
		status  int
		errCode string
	}{
		{
			name:    "wrong password",
			body:    map[string]string{"grant_type": "password", "username": "alice", "password": "wrong"},
			status:  http.StatusUnauthorized,
			errCode: "invalid_grant",
		},
		{
			name:    "unknown user",
			body:    map[string]string{"grant_type": "password", "username": "mallory", "password": "x"},
			status:  http.StatusUnauthorized,
			errCode: "invalid_grant",
		},
		{
			name:    "unsupported grant",
			body:    map[string]string{"grant_type": "client_credentials"},
			status:  http.StatusBadRequest,
			errCode: "unsupported_grant_type",
		},
		{
			name:    "unknown refresh",
			body:    map[string]string{"grant_type": "refresh_token", "refresh_token": "garbage"},
			status:  http.StatusUnauthorized,
			errCode: "invalid_grant",
		},
		{
			name:    "missing username",
			body:    map[string]string{"grant_type": "password", "password": "x"},
			status:  http.StatusBadRequest,
			errCode: "invalid_request",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := postJSON(t, srv, "/token", tc.body)
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d, body = %v", resp.StatusCode, tc.status, body)
			}
			if body["error"] != tc.errCode {
				t.Fatalf("error = %v, want %s", body["error"], tc.errCode)
			}
		})
	}

	// Некорректный JSON — invalid_request.
	resp, err := srv.Client().Post(srv.URL+"/token", "application/json", bytes.NewReader([]byte("{not json")))
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_request" {
		t.Fatalf("malformed JSON: status = %d, body = %v", resp.StatusCode, body)
	}
}

// TestRequestBodyTooLarge: тело свыше лимита — 413, а не чтение
// неограниченного объёма в память.
func TestRequestBodyTooLarge(t *testing.T) {
	srv, _, _ := newTestEnv(t)

	big := strings.NewReader(`{"grant_type":"password","username":"` + strings.Repeat("a", 1<<20+1024) + `"}`)
	resp, err := srv.Client().Post(srv.URL+"/token", "application/json", big)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: status = %d, body = %v", resp.StatusCode, body)
	}
}

// TestPasswordTooLong: bcrypt принимает максимум 72 байта пароля —
// длина проверяется сразу с понятным 400, а не падает 500-м при
// хешировании.
func TestPasswordTooLong(t *testing.T) {
	srv, _, _ := newTestEnv(t)

	resp, body := postJSON(t, srv, "/register", map[string]string{
		"username": "long", "email": "long@example.com", "password": strings.Repeat("x", 73),
	})
	if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_request" {
		t.Fatalf("73-byte password: status = %d, body = %v", resp.StatusCode, body)
	}
}

// TestGrantStoreFailureIsServerError: сбой БД при password grant — 500,
// а не «неверные учётные данные»; анти-энумерация при этом сохраняется
// (неизвестный пользователь — по-прежнему одинаковый 401).
func TestGrantStoreFailureIsServerError(t *testing.T) {
	srv, store, createUser, _ := newTestEnvStore(t)
	createUser("alice", "secret")

	store.failOn("GetUserByUsername")
	resp, body := postJSON(t, srv, "/token", map[string]string{
		"grant_type": "password", "username": "alice", "password": "secret",
	})
	if resp.StatusCode != http.StatusInternalServerError || body["error"] != "server_error" {
		t.Fatalf("store failure: status = %d, body = %v", resp.StatusCode, body)
	}
	store.fix("GetUserByUsername")

	resp, body = postJSON(t, srv, "/token", map[string]string{
		"grant_type": "password", "username": "ghost", "password": "secret",
	})
	if resp.StatusCode != http.StatusUnauthorized || body["error"] != "invalid_grant" {
		t.Fatalf("unknown user after store failure: status = %d, body = %v", resp.StatusCode, body)
	}
}

// TestRefreshRotationStoreFailureKeepsOldToken: транзиентный сбой БД
// в момент ротации не сжигает refresh-токен — после восстановления
// старый токен по-прежнему ротируется (раньше consume и save были
// раздельными, и сбой между ними терял сессию).
func TestRefreshRotationStoreFailureKeepsOldToken(t *testing.T) {
	srv, store, createUser, _ := newTestEnvStore(t)
	createUser("alice", "secret")

	_, first := postJSON(t, srv, "/token", map[string]string{
		"grant_type": "password", "username": "alice", "password": "secret",
	})
	oldRefresh, _ := first["refresh_token"].(string)

	store.failOn("RotateRefresh")
	resp, body := postJSON(t, srv, "/token", map[string]string{
		"grant_type": "refresh_token", "refresh_token": oldRefresh,
	})
	if resp.StatusCode != http.StatusInternalServerError || body["error"] != "server_error" {
		t.Fatalf("rotation with broken store: status = %d, body = %v", resp.StatusCode, body)
	}
	store.fix("RotateRefresh")

	resp, body = postJSON(t, srv, "/token", map[string]string{
		"grant_type": "refresh_token", "refresh_token": oldRefresh,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("old refresh must survive a transient store failure: status = %d, body = %v", resp.StatusCode, body)
	}
}

// TestVerifyStoreFailureIsServerError: сбой БД в /verify и
// /verify/resend — 500; код при этом не сжигается и остаётся
// рабочим после восстановления.
func TestVerifyStoreFailureIsServerError(t *testing.T) {
	srv, store, _, mail := newTestEnvStore(t)

	resp, _ := postJSON(t, srv, "/register", map[string]string{
		"username": "bob", "email": "bob@example.com", "password": "longenough",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status = %d", resp.StatusCode)
	}
	code := mail.lastCode()

	store.failOn("GetUserByEmail")
	resp, body := postJSON(t, srv, "/verify", map[string]string{"email": "bob@example.com", "code": code})
	if resp.StatusCode != http.StatusInternalServerError || body["error"] != "server_error" {
		t.Fatalf("verify with broken store: status = %d, body = %v", resp.StatusCode, body)
	}
	resp, body = postJSON(t, srv, "/verify/resend", map[string]string{"email": "bob@example.com"})
	if resp.StatusCode != http.StatusInternalServerError || body["error"] != "server_error" {
		t.Fatalf("resend with broken store: status = %d, body = %v", resp.StatusCode, body)
	}
	store.fix("GetUserByEmail")

	resp, body = postJSON(t, srv, "/verify", map[string]string{"email": "bob@example.com", "code": code})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("code must survive a transient store failure: status = %d, body = %v", resp.StatusCode, body)
	}
}

// TestResendMailFailureKeepsOldCode: сбой почты при resend не сжигает
// прежний код — письмо отправляется до записи нового кода в стор.
func TestResendMailFailureKeepsOldCode(t *testing.T) {
	srv, _, _, mail := newTestEnvStore(t)

	resp, _ := postJSON(t, srv, "/register", map[string]string{
		"username": "bob", "email": "bob@example.com", "password": "longenough",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status = %d", resp.StatusCode)
	}
	code := mail.lastCode()

	mail.setFail(true)
	resp, body := postJSON(t, srv, "/verify/resend", map[string]string{"email": "bob@example.com"})
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("resend with broken mail: status = %d, body = %v", resp.StatusCode, body)
	}
	mail.setFail(false)

	resp, body = postJSON(t, srv, "/verify", map[string]string{"email": "bob@example.com", "code": code})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("old code must survive a mail failure: status = %d, body = %v", resp.StatusCode, body)
	}
}

// TestMeStoreFailureIsServerError: валидный access-токен при упавшей
// БД — 500, а не «invalid token».
func TestMeStoreFailureIsServerError(t *testing.T) {
	srv, store, createUser, _ := newTestEnvStore(t)
	createUser("alice", "secret")

	_, pair := postJSON(t, srv, "/token", map[string]string{
		"grant_type": "password", "username": "alice", "password": "secret",
	})
	access, _ := pair["access_token"].(string)

	store.failOn("GetUserByID")
	resp, body := postJSONAuth(t, srv, "/connect-key/regenerate", map[string]string{}, access)
	if resp.StatusCode != http.StatusInternalServerError || body["error"] != "server_error" {
		t.Fatalf("regenerate with broken store: status = %d, body = %v", resp.StatusCode, body)
	}
	store.fix("GetUserByID")

	resp, body = postJSONAuth(t, srv, "/connect-key/regenerate", map[string]string{}, access)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("regenerate after store recovery: status = %d, body = %v", resp.StatusCode, body)
	}
}

func TestJWKSAndHealthz(t *testing.T) {
	srv, _, _ := newTestEnv(t)

	for _, path := range []string{"/jwks.json", "/.well-known/jwks.json"} {
		resp, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status = %d", path, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("GET %s: Content-Type = %q", path, ct)
		}
		var set map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		if _, ok := set["keys"]; !ok {
			t.Errorf("GET %s: no keys field", path)
		}
	}

	resp, err := srv.Client().Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz: status = %d", resp.StatusCode)
	}
}

// TestRegisterVerifyFlow: регистрация → письмо с кодом → верификация
// сразу выдаёт токены (без отдельного логина); логин до верификации
// запрещён; неверный и чужой код — одинаковый отказ.
func TestRegisterVerifyFlow(t *testing.T) {
	srv, _, mail := newTestEnv(t)

	// Слабый пароль отклоняется.
	resp, body := postJSON(t, srv, "/register", map[string]string{
		"username": "bob", "email": "bob@example.com", "password": "short",
	})
	if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_request" {
		t.Fatalf("weak password: status = %d, body = %v", resp.StatusCode, body)
	}

	// Регистрация.
	resp, body = postJSON(t, srv, "/register", map[string]string{
		"username": "bob", "email": "bob@example.com", "password": "longenough",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status = %d, body = %v", resp.StatusCode, body)
	}

	// Дубликат username и email — 409.
	resp, _ = postJSON(t, srv, "/register", map[string]string{
		"username": "bob", "email": "other@example.com", "password": "longenough",
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate username: status = %d", resp.StatusCode)
	}
	resp, _ = postJSON(t, srv, "/register", map[string]string{
		"username": "bob2", "email": "bob@example.com", "password": "longenough",
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate email: status = %d", resp.StatusCode)
	}

	// Логин до верификации запрещён (тот же invalid_grant).
	resp, body = postJSON(t, srv, "/token", map[string]string{
		"grant_type": "password", "username": "bob", "password": "longenough",
	})
	if resp.StatusCode != http.StatusUnauthorized || body["error"] != "invalid_grant" {
		t.Fatalf("login before verification: status = %d, body = %v", resp.StatusCode, body)
	}

	// «Письмо» доставлено: достаём код.
	code := mail.lastCode()
	if code == "" {
		t.Fatal("verification email was not sent")
	}
	if len(code) != 6 {
		t.Fatalf("code = %q, want 6 digits", code)
	}

	// Неверный код — 401; неизвестный email — тот же ответ
	// (анти-энумерация).
	resp, body = postJSON(t, srv, "/verify", map[string]string{"email": "bob@example.com", "code": "000000"})
	if resp.StatusCode != http.StatusUnauthorized || body["error"] != "invalid_code" {
		t.Fatalf("wrong code: status = %d, body = %v", resp.StatusCode, body)
	}
	resp, body = postJSON(t, srv, "/verify", map[string]string{"email": "ghost@example.com", "code": "123456"})
	if resp.StatusCode != http.StatusUnauthorized || body["error"] != "invalid_code" {
		t.Fatalf("unknown email: status = %d, body = %v", resp.StatusCode, body)
	}

	// Верификация верным кодом — сразу пара токенов, connect_key
	// в ответ не входит.
	resp, body = postJSON(t, srv, "/verify", map[string]string{"email": "bob@example.com", "code": code})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify: status = %d, body = %v", resp.StatusCode, body)
	}
	access, _ := body["access_token"].(string)
	refresh, _ := body["refresh_token"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("verify must issue tokens, got: %v", body)
	}
	if _, hasKey := body["connect_key"]; hasKey {
		t.Fatalf("verify must not return connect_key, got: %v", body)
	}

	// Выданный access работает как после обычного логина (GET /me).
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/me", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+access)
	meResp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /me: %v", err)
	}
	defer meResp.Body.Close()
	var me map[string]any
	_ = json.NewDecoder(meResp.Body).Decode(&me)
	if meResp.StatusCode != http.StatusOK || me["username"] != "bob" {
		t.Fatalf("GET /me with verify-issued token: status = %d, body = %v", meResp.StatusCode, me)
	}

	// Логин по паролю после верификации тоже работает.
	resp, body = postJSON(t, srv, "/token", map[string]string{
		"grant_type": "password", "username": "bob", "password": "longenough",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login after verification: status = %d, body = %v", resp.StatusCode, body)
	}
}

// TestVerifyAttemptsExhaustedAndResend: исчерпание попыток неверными
// кодами блокирует верный код; resend выдаёт новый (старый невалиден,
// счётчик сброшен); resend для неизвестного/подтверждённого email —
// тот же ответ без письма (анти-энумерация).
func TestVerifyAttemptsExhaustedAndResend(t *testing.T) {
	srv, _, mail := newTestEnv(t)

	resp, _ := postJSON(t, srv, "/register", map[string]string{
		"username": "erin", "email": "erin@example.com", "password": "longenough",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status = %d", resp.StatusCode)
	}
	code := mail.lastCode()
	if code == "" {
		t.Fatal("verification email was not sent")
	}

	// Исчерпание попыток: MaxVerificationAttempts промахов — после
	// этого верный код не принимается.
	for i := 0; i < authstore.MaxVerificationAttempts; i++ {
		resp, body := postJSON(t, srv, "/verify", map[string]string{"email": "erin@example.com", "code": "000000"})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong code #%d: status = %d, body = %v", i+1, resp.StatusCode, body)
		}
	}
	resp, body := postJSON(t, srv, "/verify", map[string]string{"email": "erin@example.com", "code": code})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("right code after attempts exhausted: status = %d, body = %v", resp.StatusCode, body)
	}

	// Resend: код заменён, счётчик сброшен — новый код работает.
	sent := mail.count()
	resp, _ = postJSON(t, srv, "/verify/resend", map[string]string{"email": "erin@example.com"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resend: status = %d", resp.StatusCode)
	}
	if mail.count() != sent+1 {
		t.Fatalf("resend must send exactly one email, sent %d", mail.count()-sent)
	}
	newCode := mail.lastCode()
	if newCode == "" || newCode == code {
		t.Fatalf("resend must issue a new code, got %q", newCode)
	}
	resp, body = postJSON(t, srv, "/verify", map[string]string{"email": "erin@example.com", "code": newCode})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify with resent code: status = %d, body = %v", resp.StatusCode, body)
	}

	// Resend для неизвестного email — тот же 200, письмо не уходит.
	sent = mail.count()
	resp, _ = postJSON(t, srv, "/verify/resend", map[string]string{"email": "ghost@example.com"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resend unknown email: status = %d", resp.StatusCode)
	}
	if mail.count() != sent {
		t.Fatalf("resend for unknown email must not send mail, sent %d", mail.count()-sent)
	}

	// Resend для уже подтверждённого email — тот же 200, письмо не уходит.
	sent = mail.count()
	resp, _ = postJSON(t, srv, "/verify/resend", map[string]string{"email": "erin@example.com"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resend verified email: status = %d", resp.StatusCode)
	}
	if mail.count() != sent {
		t.Fatalf("resend for verified email must not send mail, sent %d", mail.count()-sent)
	}
}

// TestMeAndConnectKeyRegenerate: токены из /verify, /me отдаёт
// connect_key, перегенерация меняет его.
func TestMeAndConnectKeyRegenerate(t *testing.T) {
	srv, _, mail := newTestEnv(t)

	// Регистрируем пользователя «письменным» путём, чтобы получить ключ.
	resp, _ := postJSON(t, srv, "/register", map[string]string{
		"username": "carol", "email": "carol@example.com", "password": "longenough",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status = %d", resp.StatusCode)
	}
	code := mail.lastCode()
	resp, body := postJSON(t, srv, "/verify", map[string]string{"email": "carol@example.com", "code": code})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify: status = %d, body = %v", resp.StatusCode, body)
	}
	access, _ := body["access_token"].(string)

	// /me отдаёт данные аккаунта и connect_key (выдан при верификации).
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/me", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+access)
	meResp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /me: %v", err)
	}
	defer meResp.Body.Close()
	var me map[string]any
	_ = json.NewDecoder(meResp.Body).Decode(&me)
	if meResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /me: status = %d, body = %v", meResp.StatusCode, me)
	}
	firstKey, _ := me["connect_key"].(string)
	if firstKey == "" {
		t.Fatalf("GET /me: connect_key missing: %v", me)
	}
	if len(firstKey) != authstore.ConnectKeyLen {
		t.Fatalf("connect_key length = %d, want %d (full-entropy key)", len(firstKey), authstore.ConnectKeyLen)
	}

	// /me без токена — 401.
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/me", nil)
	unauthResp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /me without token: %v", err)
	}
	unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /me without token: status = %d", unauthResp.StatusCode)
	}

	// Перегенерация ключа.
	resp, body = postJSONAuth(t, srv, "/connect-key/regenerate", map[string]string{}, access)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("regenerate: status = %d, body = %v", resp.StatusCode, body)
	}
	regenKey, _ := body["connect_key"].(string)
	if regenKey == "" || regenKey == firstKey {
		t.Fatalf("regenerated key = %q, want a new key", regenKey)
	}
}
