package authhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"golang.org/x/crypto/bcrypt"

	authstorememory "github.com/PinguinAdvokat/akira-mcp/internal/auth/store/memory"
	authtoken "github.com/PinguinAdvokat/akira-mcp/internal/auth/token"
)

const testIssuer = "akira-test"

// newTestEnv поднимает хендлер над in-memory стором и менеджером
// токенов; возвращает сервер и функция для создания пользователя.
func newTestEnv(t *testing.T) (*httptest.Server, func(username, password string)) {
	t.Helper()

	mgr, err := authtoken.NewManager(testIssuer, 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	store := authstorememory.New()
	srv := httptest.NewServer(New(mgr, store))
	t.Cleanup(srv.Close)

	createUser := func(username, password string) {
		t.Helper()
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("bcrypt: %v", err)
		}
		if _, err := store.CreateUser(context.Background(), username, hash); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
	}
	return srv, createUser
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
	srv, createUser := newTestEnv(t)
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
	srv, createUser := newTestEnv(t)
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
	srv, createUser := newTestEnv(t)
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
	srv, createUser := newTestEnv(t)
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

func TestJWKSAndHealthz(t *testing.T) {
	srv, _ := newTestEnv(t)

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
