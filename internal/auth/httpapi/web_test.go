package authhttp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	authstorememory "github.com/PinguinAdvokat/akira-mcp/internal/auth/store/memory"
	authtoken "github.com/PinguinAdvokat/akira-mcp/internal/auth/token"
)

// newWebEnv — сервер без FrontendURL (конфигурация по умолчанию):
// /authorize обязан вести на встроенный фронтенд — корень этого
// же сервиса.
func newWebEnv(t *testing.T) *httpTestServer {
	t.Helper()
	mgr, err := authtoken.NewManager(testIssuer, 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	srv := httptest.NewServer(New(mgr, authstorememory.New(), Config{
		Mail:     &captureMail{},
		EmailTTL: time.Hour,
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestWebIndexServed — GET / отдаёт HTML встроенного фронтенда
// с защитными заголовками (CSP — внешний скрипт не подключить,
// токены в localStorage этого SPA).
func TestWebIndexServed(t *testing.T) {
	srv := newWebEnv(t)

	resp, err := srv.Client().Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("index status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("index content-type = %q", ct)
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "script-src 'self'") {
		t.Fatalf("index CSP = %q, want default-src 'none' + script-src 'self'", csp)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("index missing nosniff")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read index body: %v", err)
	}
	html := string(body)
	if !strings.Contains(html, `id="app"`) {
		t.Fatalf("index.html has no #app mount point")
	}
	if !strings.Contains(html, "/assets/app.js") || !strings.Contains(html, "/assets/styles.css") {
		t.Fatalf("index.html does not reference the assets")
	}
}

// TestWebAssets — известные ассеты отдаются с правильным
// content-type; неизвестные пути — 404 (белый список, не FileServer).
func TestWebAssets(t *testing.T) {
	srv := newWebEnv(t)

	cases := []struct {
		path        string
		contentType string
	}{
		{"/assets/app.js", "application/javascript"},
		{"/assets/styles.css", "text/css"},
	}
	for _, c := range cases {
		resp, err := srv.Client().Get(srv.URL + c.path)
		if err != nil {
			t.Fatalf("GET %s: %v", c.path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status = %d", c.path, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, c.contentType) {
			t.Fatalf("%s: content-type = %q, want %s", c.path, ct, c.contentType)
		}
		if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: missing nosniff", c.path)
		}
	}

	for _, path := range []string{"/assets/nope.js", "/assets/", "/assets/../index.html"} {
		resp, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		// ServeMux чистит путь с ".." редиректом (301 на /index.html),
		// поэтому допустимы 301/308 и 404 — но не 200 с чужим файлом.
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("%s: unexpected 200", path)
		}
	}
}

// TestWebAssetsComplete — каждый ассет, на который ссылается
// index.html, есть в белом списке knownAssets (рассинхрон
// раздачи и HTML — сломанный фронтенд).
func TestWebAssetsComplete(t *testing.T) {
	data, err := webFS.ReadFile("web/index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	re := regexp.MustCompile(`/assets/([A-Za-z0-9._-]+)`)
	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(data), -1) {
		seen[m[1]] = true
	}
	if len(seen) == 0 {
		t.Fatal("index.html references no assets")
	}
	for name := range seen {
		if _, ok := knownAssets[name]; !ok {
			t.Errorf("index.html references /assets/%s, not in knownAssets", name)
		}
	}
	// И наоборот: каждый известный ассет реально используется.
	for name := range knownAssets {
		if !seen[name] {
			t.Errorf("knownAssets contains %s, but index.html does not reference it", name)
		}
	}
}

// TestAuthorizeRedirectsToEmbeddedFrontend — без AUTH_FRONTEND_URL
// /authorize ведёт на встроенный фронтенд: корень того же сервиса
// с исходным query (раньше в этой конфигурации был JSON 503).
func TestAuthorizeRedirectsToEmbeddedFrontend(t *testing.T) {
	srv := newWebEnv(t)
	clientID := registerClient(t, srv)
	challenge := codeChallengeFor(testCodeVerifier)

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(srv.URL + "/authorize?" + authorizeQuery(clientID, challenge))
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location %q: %v", loc, err)
	}
	if u.Path != "/" {
		t.Fatalf("authorize location path = %q, want / (embedded frontend)", u.Path)
	}
	if u.RawQuery == "" {
		t.Fatalf("authorize location lost the query: %q", loc)
	}
	q := u.Query()
	if q.Get("client_id") != clientID || q.Get("code_challenge") != challenge {
		t.Fatalf("authorize passthrough lost params: %v", q)
	}
}
