package akiramcp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authtoken "github.com/PinguinAdvokat/akira-mcp/internal/auth/token"

	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/pool"
)

// newInstallEnv собирает хендлер с заданным PublicURL (newTestEnv
// хардкодит свой) и поднимает его на httptest-сервере.
func newInstallEnv(t *testing.T, publicURL, releasesURL string) *httptest.Server {
	t.Helper()
	m, err := authtoken.NewManager("akira", time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	handler, err := New(Config{
		Pool:              connectionpool.New(0),
		Validator:         newValidator(t, m, "akira"),
		TaskTimeoutMs:     5_000,
		ReadMaxBytes:      1 << 20,
		PublicURL:         publicURL,
		AuthServerURL:     "http://auth.test",
		ClientReleasesURL: releasesURL,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// getInstallScript забирает /sh без токена и возвращает тело.
func getInstallScript(t *testing.T, srv *httptest.Server) (string, http.Header) {
	t.Helper()
	resp, err := srv.Client().Get(srv.URL + "/sh")
	if err != nil {
		t.Fatalf("GET /sh: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	return string(body), resp.Header
}

// TestMCPInstallScript — публичический GET /sh отдаёт сгенерированный
// скрипт с зашитыми адресом сервера и TLS-флагами из PublicURL.
// Подстроки сверяем целыми токенами: "-tls" — префикс "-tls-insecure",
// поэтому с пробелом ("-tls ") или в составе пары флагов.
func TestMCPInstallScript(t *testing.T) {
	tests := []struct {
		name        string
		publicURL   string
		releasesURL string // "" — дефолт
		want        []string
		notWant     []string
	}{
		{
			name:      "http no port",
			publicURL: "http://mcp.test",
			want:      []string{`-server "mcp.test:80"`, "releases/latest/download/akira-client-"},
			notWant:   []string{"-tls "},
		},
		{
			name:      "https no port",
			publicURL: "https://mcp.test",
			want:      []string{`-server "mcp.test:443"`, "-tls "},
		},
		{
			name:      "https explicit port",
			publicURL: "https://mcp.test:8443",
			want:      []string{`-server "mcp.test:8443"`, "-tls "},
		},
		{
			name:      "http explicit port",
			publicURL: "http://mcp.test:8080",
			want:      []string{`-server "mcp.test:8080"`},
			notWant:   []string{"-tls "},
		},
		{
			// Сертификат по bare IP не проверить — скрипт включает -tls-insecure.
			name:      "https bare ip",
			publicURL: "https://203.0.113.7",
			want:      []string{`-server "203.0.113.7:443"`, "-tls -tls-insecure"},
		},
		{
			name:        "custom releases url",
			publicURL:   "https://mcp.test",
			releasesURL: "https://releases.example.com/akira/",
			want:        []string{"https://releases.example.com/akira/latest/download/akira-client-"},
			notWant:     []string{"github.com/PinguinAdvokat"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newInstallEnv(t, tt.publicURL, tt.releasesURL)
			body, header := getInstallScript(t, srv)

			if ct := header.Get("Content-Type"); ct != "text/x-shellscript; charset=utf-8" {
				t.Fatalf("Content-Type = %q, want text/x-shellscript; charset=utf-8", ct)
			}
			if !strings.HasPrefix(body, "#!/usr/bin/env bash\n") {
				t.Fatalf("script does not start with shebang:\n%s", body[:min(len(body), 80)])
			}
			if !strings.Contains(body, "set -euo pipefail") {
				t.Fatal("script missing set -euo pipefail")
			}
			for _, w := range tt.want {
				if !strings.Contains(body, w) {
					t.Errorf("script missing %q", w)
				}
			}
			for _, w := range tt.notWant {
				if strings.Contains(body, w) {
					t.Errorf("script contains unexpected %q", w)
				}
			}
		})
	}
}

// TestMCPInstallScriptPostRejected — метод-паттерн "GET /sh":
// не-GET получает 405.
func TestMCPInstallScriptPostRejected(t *testing.T) {
	srv := newInstallEnv(t, "http://mcp.test", "")
	resp, err := srv.Client().Post(srv.URL+"/sh", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("POST /sh: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// TestClientConnectParams — прямые проверки вывода адреса и флагов
// из PublicURL, включая ошибки.
func TestClientConnectParams(t *testing.T) {
	tests := []struct {
		publicURL string
		wantAddr  string
		wantTLS   string
		wantErr   bool
	}{
		{"http://mcp.test", "mcp.test:80", "", false},
		{"https://mcp.test", "mcp.test:443", "-tls", false},
		{"https://mcp.test:8443", "mcp.test:8443", "-tls", false},
		{"http://127.0.0.1:8080", "127.0.0.1:8080", "", false},
		{"https://203.0.113.7", "203.0.113.7:443", "-tls -tls-insecure", false},
		{"ftp://mcp.test", "", "", true}, // неподдерживаемая scheme
		{"http://", "", "", true},        // без host
		{"mcp.test", "", "", true},       // без scheme url.Parse не видит host
	}
	for _, tt := range tests {
		t.Run(tt.publicURL, func(t *testing.T) {
			addr, tlsFlags, err := clientConnectParams(tt.publicURL)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("clientConnectParams(%q) succeeded, want error", tt.publicURL)
				}
				return
			}
			if err != nil {
				t.Fatalf("clientConnectParams(%q): %v", tt.publicURL, err)
			}
			if addr != tt.wantAddr {
				t.Errorf("addr = %q, want %q", addr, tt.wantAddr)
			}
			if tlsFlags != tt.wantTLS {
				t.Errorf("tlsFlags = %q, want %q", tlsFlags, tt.wantTLS)
			}
		})
	}
}
