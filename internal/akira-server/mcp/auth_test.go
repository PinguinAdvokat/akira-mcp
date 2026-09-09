package akiramcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authtoken "github.com/PinguinAdvokat/akira-mcp/internal/auth/token"
)

// newJWKSServer поднимает httptest-сервер, раздающий JWKS настоящего
// менеджера токенов, и возвращает его URL.
func newJWKSServer(t *testing.T, m *authtoken.Manager) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(m.JWKS())
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// newValidator создаёт валидатор поверх JWKS-сервера менеджера m.
func newValidator(t *testing.T, m *authtoken.Manager, issuer string) *TokenValidator {
	t.Helper()
	v, err := NewTokenValidator(context.Background(), newJWKSServer(t, m), issuer)
	if err != nil {
		t.Fatalf("NewTokenValidator: %v", err)
	}
	return v
}

// authedRequest собирает запрос с Bearer-токеном.
func authedRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func TestTokenValidatorValid(t *testing.T) {
	m, err := authtoken.NewManager("akira", time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	userID := "0123456789abcdef0123456789abcdef"
	access, err := m.NewAccessToken(userID)
	if err != nil {
		t.Fatalf("NewAccessToken: %v", err)
	}

	v := newValidator(t, m, "akira")
	got, err := v.Validate(context.Background(), authedRequest(access))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got != userID {
		t.Fatalf("userID = %q, want %q", got, userID)
	}
}

func TestTokenValidatorRejects(t *testing.T) {
	m, err := authtoken.NewManager("akira", time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	v := newValidator(t, m, "akira")
	valid, err := m.NewAccessToken("user1")
	if err != nil {
		t.Fatalf("NewAccessToken: %v", err)
	}

	foreign, err := authtoken.NewManager("akira", time.Minute, time.Hour) // другой issuer-ключ
	if err != nil {
		t.Fatalf("NewManager (foreign): %v", err)
	}
	foreignTok, err := foreign.NewAccessToken("user1")
	if err != nil {
		t.Fatalf("NewAccessToken (foreign): %v", err)
	}

	tests := []struct {
		name string
		req  *http.Request
	}{
		{"no authorization header", authedRequest("")},
		{"garbage token", authedRequest("not.a.jwt")},
		{"token from another key set", authedRequest(foreignTok)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := v.Validate(context.Background(), tt.req); err == nil {
				t.Fatal("Validate succeeded, want error")
			}
		})
	}

	// Чужой iss: валидатор ждёт "other", токен выпущен "akira".
	vOther := newValidator(t, m, "other")
	if _, err := vOther.Validate(context.Background(), authedRequest(valid)); err == nil {
		t.Fatal("Validate with wrong issuer succeeded, want error")
	}
}

// TestTokenValidatorExpired — просроченный токен отклоняется
// (WithValidate проверяет exp).
func TestTokenValidatorExpired(t *testing.T) {
	// TTL много меньше секунды: к моменту проверки токен протух.
	m, err := authtoken.NewManager("akira", -time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	access, err := m.NewAccessToken("user1")
	if err != nil {
		t.Fatalf("NewAccessToken: %v", err)
	}
	v := newValidator(t, m, "akira")
	if _, err := v.Validate(context.Background(), authedRequest(access)); err == nil {
		t.Fatal("Validate expired token succeeded, want error")
	}
}
