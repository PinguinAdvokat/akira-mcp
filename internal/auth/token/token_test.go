package authtoken

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jws"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager("akira-test", 15*time.Minute, 720*time.Hour)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func TestAccessTokenRoundtrip(t *testing.T) {
	m := newTestManager(t)

	signed, err := m.NewAccessToken("user-42")
	if err != nil {
		t.Fatalf("NewAccessToken: %v", err)
	}

	parsed, err := m.ParseAccessToken([]byte(signed))
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	if sub, _ := parsed.Subject(); sub != "user-42" {
		t.Fatalf("sub = %q, want user-42", sub)
	}
	if iss, _ := parsed.Issuer(); iss != "akira-test" {
		t.Fatalf("iss = %q, want akira-test", iss)
	}
	var typ string
	if err := parsed.Get("typ", &typ); err != nil || typ != "access" {
		t.Fatalf("typ = %q (err %v), want access", typ, err)
	}
	if jti, _ := parsed.JwtID(); jti == "" {
		t.Fatal("jti is empty")
	}
	if _, ok := parsed.Expiration(); !ok {
		t.Fatal("exp missing")
	}
}

func TestParseRejectsWrongIssuer(t *testing.T) {
	m := newTestManager(t)

	signed, err := m.NewAccessToken("user-42")
	if err != nil {
		t.Fatalf("NewAccessToken: %v", err)
	}

	other, err := NewManager("someone-else", time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if _, err := other.ParseAccessToken([]byte(signed)); err == nil {
		t.Fatal("token signed by another key/issuer must not verify")
	}
}

func TestJWKSShape(t *testing.T) {
	m := newTestManager(t)

	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(m.JWKS(), &set); err != nil {
		t.Fatalf("JWKS is not valid JSON: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(set.Keys))
	}
	k := set.Keys[0]
	if k["kty"] != "RSA" {
		t.Errorf("kty = %v, want RSA", k["kty"])
	}
	if k["e"] != "AQAB" {
		t.Errorf("e = %v, want AQAB", k["e"])
	}
	if k["alg"] != "RS256" {
		t.Errorf("alg = %v, want RS256", k["alg"])
	}
	if k["use"] != "sig" {
		t.Errorf("use = %v, want sig", k["use"])
	}
	kid, _ := k["kid"].(string)
	if len(kid) != 32 { // 16 байт hex
		t.Errorf("kid = %q, want 32-char hex", kid)
	}
	if _, hasD := k["d"]; hasD {
		t.Error("JWKS must not contain private exponent d")
	}
}

func TestKidMatchesHeader(t *testing.T) {
	m := newTestManager(t)

	signed, err := m.NewAccessToken("user-42")
	if err != nil {
		t.Fatalf("NewAccessToken: %v", err)
	}

	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(m.JWKS(), &set); err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	jwksKid, _ := set.Keys[0]["kid"].(string)

	hdrs, err := jws.Parse([]byte(signed))
	if err != nil {
		t.Fatalf("jws.Parse: %v", err)
	}
	var headerKid string
	if err := hdrs.Signatures()[0].ProtectedHeaders().Get("kid", &headerKid); err != nil {
		t.Fatalf("header kid: %v", err)
	}
	if headerKid != jwksKid {
		t.Fatalf("header kid %q != JWKS kid %q", headerKid, jwksKid)
	}
}

// TestTamperedPayload: изменение payload ломает подпись.
func TestTamperedPayload(t *testing.T) {
	m := newTestManager(t)

	signed, err := m.NewAccessToken("user-42")
	if err != nil {
		t.Fatalf("NewAccessToken: %v", err)
	}

	parts := strings.Split(signed, ".")
	fakePayload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"attacker"}`))
	tampered := parts[0] + "." + fakePayload + "." + parts[2]

	if _, err := m.ParseAccessToken([]byte(tampered)); err == nil {
		t.Fatal("tampered token must not verify")
	}
}

// TestExpiredToken: истёкший токен отбрасывается валидацией.
func TestExpiredToken(t *testing.T) {
	m, err := NewManager("akira-test", -time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	signed, err := m.NewAccessToken("user-42")
	if err != nil {
		t.Fatalf("NewAccessToken: %v", err)
	}
	if _, err := m.ParseAccessToken([]byte(signed)); err == nil {
		t.Fatal("expired token must not verify")
	}
}

func TestRefreshToken(t *testing.T) {
	m := newTestManager(t)

	raw, hash, err := m.NewRefreshToken()
	if err != nil {
		t.Fatalf("NewRefreshToken: %v", err)
	}
	if len(raw) != 43 { // 32 байта base64url без padding
		t.Errorf("raw len = %d, want 43", len(raw))
	}
	if len(hash) != 64 { // sha256 hex
		t.Errorf("hash len = %d, want 64", len(hash))
	}

	// Разные вызовы дают разные токены.
	raw2, hash2, err := m.NewRefreshToken()
	if err != nil {
		t.Fatalf("NewRefreshToken: %v", err)
	}
	if raw == raw2 || hash == hash2 {
		t.Fatal("refresh tokens must be unique")
	}

	if m.RefreshTTL() != 720*time.Hour || m.AccessTTL() != 15*time.Minute {
		t.Fatalf("TTLs mismatch: access=%v refresh=%v", m.AccessTTL(), m.RefreshTTL())
	}
}
