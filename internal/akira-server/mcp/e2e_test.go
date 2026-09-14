package akiramcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	grpcclient "github.com/PinguinAdvokat/akira-mcp/internal/akira-client/connection"
	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/pool"
	connectionserver "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/server"
	authstorememory "github.com/PinguinAdvokat/akira-mcp/internal/auth/store/memory"
	authtoken "github.com/PinguinAdvokat/akira-mcp/internal/auth/token"
)

// memLookup — authstorememory-стойка под connectionserver.UserLookup
// (как storeLookup в cmd, но для in-memory стора и с ключом-константой).
type memLookup struct {
	store *authstorememory.Store
}

func (l memLookup) LookupConnectKey(ctx context.Context, connectKey string) (string, bool, error) {
	user, err := l.store.GetUserByConnectKey(ctx, connectKey)
	if err != nil {
		return "", false, connectionserver.ErrUnknownConnectKey
	}
	return user.ID, user.EmailVerified, nil
}

// e2eEnv — полный стек: настоящий gRPC-сервер (NewGRPCServer) +
// настоящий akira-client (connection.Run) + MCP-хендлер. Клиент
// подключается по gRPC и исполняет задачи настоящим executor'ом —
// файлы читаются/пишутся на локальной машине теста.
type e2eEnv struct {
	mcp    *httptest.Server
	token  string
	client string // client_id
}

// newE2EEnv поднимает стек: верифицированный пользователь в memory-сторе,
// gRPC-сервер на случайном порту, клиент connection.Run в горутине,
// MCP-хендлер поверх того же пула.
func newE2EEnv(t *testing.T) *e2eEnv {
	t.Helper()

	const (
		clientID   = "e2e-laptop"
		connectKey = "e2e-connect-key"
	)

	store := authstorememory.New()
	user, err := store.CreateUser(context.Background(), "e2euser", "e2e@example.com", []byte("hash"))
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := store.VerifyEmail(context.Background(), user.ID); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if err := store.SetConnectKey(context.Background(), user.ID, connectKey); err != nil {
		t.Fatalf("SetConnectKey: %v", err)
	}

	pool := connectionpool.New(0)
	grpcServer := connectionserver.NewGRPCServer(pool, memLookup{store: store})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	// Настоящий клиент: переподключается сам, исполняет задачи
	// настоящим executor'ом (файлы — на машине теста).
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = grpcclient.Run(ctx, grpcclient.Config{
			ServerAddr: lis.Addr().String(),
			ClientID:   clientID,
			ConnectKey: connectKey,
		})
	}()
	t.Cleanup(cancel)

	// Токен и валидатор: manager того же issuer, JWKS отдаёт httptest.
	mgr, err := authtoken.NewManager("akira", time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("token manager: %v", err)
	}
	token, err := mgr.NewAccessToken(user.ID)
	if err != nil {
		t.Fatalf("NewAccessToken: %v", err)
	}
	validator, err := NewTokenValidator(ctx, newJWKSServer(t, mgr), "akira")
	if err != nil {
		t.Fatalf("NewTokenValidator: %v", err)
	}

	handler, err := New(Config{
		Pool:          pool,
		Validator:     validator,
		TaskTimeoutMs: 10_000,
		ReadMaxBytes:  1 << 20,
		PublicURL:     "http://mcp.test",
		AuthServerURL: "http://auth.test",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	// Клиенту нужно время на регистрацию: ждём появления в пуле.
	deadline := time.Now().Add(10 * time.Second)
	connectionID := user.ID + ":" + clientID
	for !pool.Has(connectionID) {
		if time.Now().After(deadline) {
			t.Fatal("client did not register in time")
		}
		time.Sleep(20 * time.Millisecond)
	}

	return &e2eEnv{mcp: srv, token: token, client: clientID}
}

// callRPC шлёт JSON-RPC POST на /mcp с Bearer-токеном.
func (e *e2eEnv) callRPC(t *testing.T, method string, params map[string]any) map[string]any {
	t.Helper()
	body := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
	}
	if params != nil {
		body["params"] = params
	}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, e.mcp.URL+"/mcp", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.token)

	resp, err := e.mcp.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: status %d", method, resp.StatusCode)
	}
	out := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("%s: decode response: %v", method, err)
	}
	return out
}

// callTool — initialize не нужен (stateless), шлём tools/call.
func (e *e2eEnv) callTool(t *testing.T, name string, args map[string]any) map[string]any {
	t.Helper()
	return e.callRPC(t, "tools/call", map[string]any{
		"name":      name,
		"arguments": args,
	})
}

// TestE2ETools — полный цикл всех инструментов через MCP: write →
// read (окно строк) → edit (одиночная замена, неоднозначная, replace_all)
// → glob → list → exec cat. Файлы пишет настоящий executor
// на локальной машине.
func TestE2ETools(t *testing.T) {
	e := newE2EEnv(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "hello.txt")
	const content = "line one\nline two\nline three\nline four\nline five\n"

	// 1. write во вложенный путь: родительские каталоги создаются сами.
	body := e.callTool(t, "write", map[string]any{
		"host":    e.client,
		"path":    path,
		"content": content,
	})
	if isToolError(t, body) {
		t.Fatalf("write failed: %v", body)
	}

	// Файл действительно на диске (писал настоящий executor).
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read from disk: %v", err)
	}
	if string(disk) != content {
		t.Fatalf("disk content = %q, want %q", disk, content)
	}

	// 2. read целиком — нумерация строк в стиле cat -n.
	body = e.callTool(t, "read", map[string]any{
		"host": e.client,
		"path": path,
	})
	if isToolError(t, body) {
		t.Fatalf("read failed: %v", body)
	}
	if text := toolResultText(t, body); !strings.Contains(text, "  1\tline one") {
		t.Fatalf("read output = %q, want cat -n numbering", text)
	}

	// 3. read окно строк 2–3.
	body = e.callTool(t, "read", map[string]any{
		"host":   e.client,
		"path":   path,
		"offset": 2,
		"limit":  2,
	})
	if isToolError(t, body) {
		t.Fatalf("read window failed: %v", body)
	}
	if text, want := toolResultText(t, body), "  2\tline two\n  3\tline three\n[2-3 of 5 lines]\n"; text != want {
		t.Fatalf("read window = %q, want %q", text, want)
	}

	// 4. read с offset за концом файла — ошибка.
	body = e.callTool(t, "read", map[string]any{
		"host":   e.client,
		"path":   path,
		"offset": 99,
	})
	if !isToolError(t, body) {
		t.Fatalf("read beyond EOF must fail, got %v", body)
	}

	// 5. edit уникальной строки.
	body = e.callTool(t, "edit", map[string]any{
		"host":    e.client,
		"path":    path,
		"old_str": "line three",
		"new_str": "LINE THREE",
	})
	if isToolError(t, body) {
		t.Fatalf("edit failed: %v", body)
	}
	disk, _ = os.ReadFile(path)
	if !strings.Contains(string(disk), "LINE THREE") {
		t.Fatalf("disk content after edit = %q, missing LINE THREE", disk)
	}

	// 6. edit строки, встречающейся дважды: без replace_all — ошибка,
	// с replace_all — заменяются обе.
	body = e.callTool(t, "edit", map[string]any{
		"host":    e.client,
		"path":    path,
		"old_str": "line f",
		"new_str": "LINE F",
	})
	if !isToolError(t, body) {
		t.Fatalf("ambiguous edit must fail, got %v", body)
	}
	body = e.callTool(t, "edit", map[string]any{
		"host":        e.client,
		"path":        path,
		"old_str":     "line f",
		"new_str":     "LINE F",
		"replace_all": true,
	})
	if isToolError(t, body) {
		t.Fatalf("edit replace_all failed: %v", body)
	}
	disk, _ = os.ReadFile(path)
	if n := strings.Count(string(disk), "LINE F"); n != 2 {
		t.Fatalf("after replace_all: %d occurrences of LINE F, want 2 (content %q)", n, disk)
	}

	// 7. glob по **/*.txt от dir.
	body = e.callTool(t, "glob", map[string]any{
		"host":    e.client,
		"pattern": "**/*.txt",
		"path":    dir,
	})
	if isToolError(t, body) {
		t.Fatalf("glob failed: %v", body)
	}
	if text := toolResultText(t, body); !strings.Contains(text, path) {
		t.Fatalf("glob output = %q, want it to contain %q", text, path)
	}

	// 8. list dir на глубину 1: подкаталог sub/ с суффиксом '/'.
	body = e.callTool(t, "list", map[string]any{
		"host": e.client,
		"path": dir,
	})
	if isToolError(t, body) {
		t.Fatalf("list failed: %v", body)
	}
	if text := toolResultText(t, body); !strings.Contains(text, "sub/") {
		t.Fatalf("list output = %q, want it to contain sub/", text)
	}

	// 9. exec cat файла.
	body = e.callTool(t, "exec", map[string]any{
		"host": e.client,
		"cmd":  "cat " + path,
	})
	if isToolError(t, body) {
		t.Fatalf("exec failed: %v", body)
	}
	if text := toolResultText(t, body); !strings.Contains(text, "LINE THREE") {
		t.Fatalf("exec output = %q, want it to contain LINE THREE", text)
	}
}

// TestE2EMachines — ресурс machines показывает машину клиента
// (настоящий hostname/platform из RegisterRequest).
func TestE2EMachines(t *testing.T) {
	e := newE2EEnv(t)

	res := e.callRPC(t, "resources/read", map[string]any{"uri": "akira://machines"})
	text := resourceText(t, res)
	if !strings.Contains(text, e.client) {
		t.Fatalf("machines = %q, want it to contain client_id %q", text, e.client)
	}
	// platform присутствует (клиент шлёт runtime.GOOS).
	if !strings.Contains(text, "platform") {
		t.Fatalf("machines = %q, want platform field", text)
	}
}

// isToolError сообщает, завершился ли tools/call ошибкой.
func isToolError(t *testing.T, body map[string]any) bool {
	t.Helper()
	res, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result in response: %v", body)
	}
	isErr, _ := res["isError"].(bool)
	return isErr
}
