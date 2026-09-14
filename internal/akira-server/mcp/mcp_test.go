package akiramcp

import (
	"bytes"
	"context"
	"encoding/json"

	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/pool"
	authtoken "github.com/PinguinAdvokat/akira-mcp/internal/auth/token"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
)

// testEnv — собранный MCP-сервер над пулом с одним «фейковым клиентом»:
// горутина читает задачи из conn.Out() и отвечает через pool.HandleResult.
type testEnv struct {
	srv    *httptest.Server
	pool   *connectionpool.ConnectionPool
	mgr    *authtoken.Manager
	userID string
	token  string // access-токен userID
}

// newTestEnv регистрирует машину clientID (hostname, platform)
// за пользователем userID и поднимает MCP-хендлер поверх httptest.
func newTestEnv(t *testing.T, userID, clientID, hostname, platform string) *testEnv {
	t.Helper()

	mgr, err := authtoken.NewManager("akira", time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	token, err := mgr.NewAccessToken(userID)
	if err != nil {
		t.Fatalf("NewAccessToken: %v", err)
	}

	pool := connectionpool.New(0)
	if clientID != "" {
		registerFakeClient(t, pool, userID, clientID, hostname, platform)
	}

	v, err := NewTokenValidator(context.Background(), newJWKSServer(t, mgr), "akira")
	if err != nil {
		t.Fatalf("NewTokenValidator: %v", err)
	}
	handler, err := New(Config{
		Pool:          pool,
		Validator:     v,
		TaskTimeoutMs: 5_000,
		ReadMaxBytes:  1 << 20,
		PublicURL:     "http://mcp.test",
		AuthServerURL: "http://auth.test",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return &testEnv{srv: srv, pool: pool, mgr: mgr, userID: userID, token: token}
}

// registerFakeClient регистрирует подключение в пуле и запускает
// «клиента»: goroutine вычитывает задачи из очереди и возвращает
// результаты в пул. Поведение эмулирует executor: exec отвечает
// эхом с exit_code=0, read_file — фиксированными строками, edit —
// ошибкой для old_str="missing", glob/list — фиксированными списками.
func registerFakeClient(t *testing.T, pool *connectionpool.ConnectionPool, userID, clientID, hostname, platform string) {
	t.Helper()
	conn, err := pool.Register(userID+":"+clientID, userID, connectionpool.ClientInfo{
		Hostname: hostname,
		Platform: platform,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	go func() {
		for msg := range conn.Out() {
			task := msg.GetTask()
			if task == nil {
				continue
			}
			pool.HandleResult(fakeExecute(task, conn.ClientID))
		}
	}()
	t.Cleanup(func() { pool.Disconnect(userID + ":" + clientID) })
}

// fakeReadLines — файл из пяти строк, который отдаёт fakeExecute
// для read_file.
const fakeReadLines = "l1\nl2\nl3\nl4\nl5\n"

// fakeExecute — эмуляция executor.Execute для тестов.
func fakeExecute(task *pb.Task, owner string) *pb.TaskResult {
	res := &pb.TaskResult{
		TaskId:     task.GetId(),
		Status:     pb.TaskResult_STATUS_OK,
		DurationMs: 1,
		ClientId:   owner,
	}
	switch p := task.Payload.(type) {
	case *pb.Task_Exec:
		res.Stdout = []byte("echo:" + p.Exec.Cmd)
		res.ExitCode = 0
	case *pb.Task_ReadFile:
		lines := strings.Split(fakeReadLines, "\n")
		if n := len(lines); n > 0 && lines[n-1] == "" {
			lines = lines[:n-1]
		}
		if p.ReadFile.Offset > 1 || p.ReadFile.Limit > 0 {
			off := int(p.ReadFile.Offset)
			if off < 1 {
				off = 1
			}
			if off > len(lines) {
				lines = nil
			} else {
				lines = lines[off-1:]
				if p.ReadFile.Limit > 0 && int(p.ReadFile.Limit) < len(lines) {
					lines = lines[:p.ReadFile.Limit]
				}
			}
		}
		res.Stdout = []byte(strings.Join(lines, "\n"))
		if len(lines) > 0 {
			res.Stdout = append(res.Stdout, '\n')
		}
		res.TotalLines = 5
	case *pb.Task_WriteFile:
		// успех без содержимого
	case *pb.Task_EditFile:
		if p.EditFile.OldStr == "missing" {
			res.Status = pb.TaskResult_STATUS_ERROR
			res.Error = "old_str not found in " + p.EditFile.Path
		} else {
			res.Stdout = []byte("replaced 1 occurrence(s)")
		}
	case *pb.Task_Glob:
		res.Stdout = []byte("/a.go\n/b/c.go\n")
		res.TotalLines = 2
	case *pb.Task_List:
		res.Stdout = []byte("sub/\nfile.txt\n")
		res.TotalLines = 2
	default:
		res.Status = pb.TaskResult_STATUS_ERROR
		res.Error = "unknown task type"
	}
	return res
}

// mcpRequest шлёт JSON-RPC POST на /mcp с Bearer-токеном
// и разбирает ответ в map.
func (e *testEnv) mcpRequest(t *testing.T, token string, body map[string]any) (int, map[string]any) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+"/mcp", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	if resp.StatusCode == http.StatusOK {
		_ = json.NewDecoder(resp.Body).Decode(&out)
	}
	return resp.StatusCode, out
}

// initMCP выполняет handshake initialize и возвращает протоколную
// версию из ответа (нужна в Accept-Protocol-Version для последующих
// запросов в stateless-режиме).
func (e *testEnv) initMCP(t *testing.T) string {
	t.Helper()
	code, body := e.mcpRequest(t, e.token, map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "test", "version": "0"},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("initialize: status %d, body %v", code, body)
	}
	// Протоколная версия, которую выбрал сервер.
	if res, ok := body["result"].(map[string]any); ok {
		if v, ok := res["protocolVersion"].(string); ok {
			return v
		}
	}
	return "2025-03-26"
}

// rpc шлёт запрос с актуальной протоколной версией.
func (e *testEnv) rpc(t *testing.T, token, protocol string, method string, params map[string]any) (int, map[string]any) {
	t.Helper()
	if params == nil {
		params = map[string]any{}
	}
	body := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	}
	// В stateless-режиме сервер требует версию протокола в заголовке
	// после initialize — прокидываем её параметром запроса нельзя,
	// поэтому mcpRequest расширен заголовком ниже.
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/mcp", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if protocol != "" {
		req.Header.Set("MCP-Protocol-Version", protocol)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	if resp.StatusCode == http.StatusOK {
		_ = json.NewDecoder(resp.Body).Decode(&out)
	}
	return resp.StatusCode, out
}

func TestMCPToolsList(t *testing.T) {
	e := newTestEnv(t, "user1", "laptop1", "host1", "linux")
	proto := e.initMCP(t)

	code, body := e.rpc(t, e.token, proto, "tools/list", nil)
	if code != http.StatusOK {
		t.Fatalf("tools/list: status %d, body %v", code, body)
	}
	names := toolNames(body)
	for _, want := range []string{"exec", "read", "edit", "write", "glob", "list"} {
		if !names[want] {
			t.Errorf("tools/list: want %q, got %v", want, names)
		}
	}
	if len(names) != 6 {
		t.Errorf("tools/list: want exactly 6 tools, got %d (%v)", len(names), names)
	}
}

func TestMCPExecTool(t *testing.T) {
	e := newTestEnv(t, "user1", "laptop1", "host1", "linux")
	proto := e.initMCP(t)

	code, body := e.rpc(t, e.token, proto, "tools/call", map[string]any{
		"name": "exec",
		"arguments": map[string]any{
			"host": "laptop1",
			"cmd":  "echo hi",
		},
	})
	if code != http.StatusOK {
		t.Fatalf("tools/call: status %d, body %v", code, body)
	}
	text := toolResultText(t, body)
	if !strings.Contains(text, "echo:echo hi") {
		t.Fatalf("exec result text = %q, want echo:echo hi", text)
	}
	if !strings.Contains(text, "exit_code=0") {
		t.Fatalf("exec result text = %q, want exit_code=0", text)
	}
}

func TestMCPWriteTool(t *testing.T) {
	e := newTestEnv(t, "user1", "laptop1", "host1", "linux")
	proto := e.initMCP(t)

	code, body := e.rpc(t, e.token, proto, "tools/call", map[string]any{
		"name": "write",
		"arguments": map[string]any{
			"host":    "laptop1",
			"path":    "/tmp/x.txt",
			"content": "hello",
		},
	})
	if code != http.StatusOK {
		t.Fatalf("tools/call: status %d, body %v", code, body)
	}
	if !strings.Contains(toolResultText(t, body), "/tmp/x.txt") {
		t.Fatalf("write result should mention path")
	}
}

// TestMCPReadTool — read отдаёт содержимое с нумерацией строк cat -n:
// ширина номера — max(3, разрядов последней строки), затем таб.
func TestMCPReadTool(t *testing.T) {
	e := newTestEnv(t, "user1", "laptop1", "host1", "linux")
	proto := e.initMCP(t)

	t.Run("full", func(t *testing.T) {
		code, body := e.rpc(t, e.token, proto, "tools/call", map[string]any{
			"name": "read",
			"arguments": map[string]any{
				"host": "laptop1",
				"path": "/etc/hostname",
			},
		})
		if code != http.StatusOK {
			t.Fatalf("tools/call: status %d, body %v", code, body)
		}
		text := toolResultText(t, body)
		if !strings.HasPrefix(text, "  1\tl1\n") {
			t.Fatalf("read result = %q, want cat -n numbering", text)
		}
		if !strings.Contains(text, "[1-5 of 5 lines]") {
			t.Fatalf("read result = %q, want footer [1-5 of 5 lines]", text)
		}
	})

	t.Run("window", func(t *testing.T) {
		code, body := e.rpc(t, e.token, proto, "tools/call", map[string]any{
			"name": "read",
			"arguments": map[string]any{
				"host":   "laptop1",
				"path":   "/etc/hostname",
				"offset": 2,
				"limit":  2,
			},
		})
		if code != http.StatusOK {
			t.Fatalf("tools/call: status %d, body %v", code, body)
		}
		text := toolResultText(t, body)
		if text != "  2\tl2\n  3\tl3\n[2-3 of 5 lines]\n" {
			t.Fatalf("read window = %q", text)
		}
	})

	t.Run("offset_beyond_eof", func(t *testing.T) {
		code, body := e.rpc(t, e.token, proto, "tools/call", map[string]any{
			"name": "read",
			"arguments": map[string]any{
				"host":   "laptop1",
				"path":   "/etc/hostname",
				"offset": 99,
			},
		})
		if code != http.StatusOK {
			t.Fatalf("tools/call: status %d, body %v", code, body)
		}
		if !toolIsError(t, body) {
			t.Fatalf("offset beyond EOF must be an error, got %v", body)
		}
		if msg := toolResultText(t, body); !strings.Contains(msg, "only 5 lines") {
			t.Fatalf("error text = %q, want 'only 5 lines'", msg)
		}
	})

	t.Run("offset_zero_is_error", func(t *testing.T) {
		code, body := e.rpc(t, e.token, proto, "tools/call", map[string]any{
			"name": "read",
			"arguments": map[string]any{
				"host":   "laptop1",
				"path":   "/etc/hostname",
				"offset": 0,
			},
		})
		if code != http.StatusOK {
			t.Fatalf("tools/call: status %d, body %v", code, body)
		}
		if !toolIsError(t, body) {
			t.Fatalf("offset 0 must be an error, got %v", body)
		}
	})
}

func TestMCPEditTool(t *testing.T) {
	e := newTestEnv(t, "user1", "laptop1", "host1", "linux")
	proto := e.initMCP(t)

	t.Run("success", func(t *testing.T) {
		code, body := e.rpc(t, e.token, proto, "tools/call", map[string]any{
			"name": "edit",
			"arguments": map[string]any{
				"host":    "laptop1",
				"path":    "/etc/app.conf",
				"old_str": "debug=false",
				"new_str": "debug=true",
			},
		})
		if code != http.StatusOK {
			t.Fatalf("tools/call: status %d, body %v", code, body)
		}
		text := toolResultText(t, body)
		if !strings.Contains(text, "edited /etc/app.conf") || !strings.Contains(text, "replaced 1 occurrence(s)") {
			t.Fatalf("edit result = %q", text)
		}
	})

	t.Run("not_found", func(t *testing.T) {
		code, body := e.rpc(t, e.token, proto, "tools/call", map[string]any{
			"name": "edit",
			"arguments": map[string]any{
				"host":    "laptop1",
				"path":    "/etc/app.conf",
				"old_str": "missing",
				"new_str": "x",
			},
		})
		if code != http.StatusOK {
			t.Fatalf("tools/call: status %d, body %v", code, body)
		}
		if !toolIsError(t, body) {
			t.Fatalf("edit with missing old_str must be an error, got %v", body)
		}
		if msg := toolResultText(t, body); !strings.Contains(msg, "old_str not found") {
			t.Fatalf("error text = %q, want 'old_str not found'", msg)
		}
	})
}

func TestMCPGlobListTools(t *testing.T) {
	e := newTestEnv(t, "user1", "laptop1", "host1", "linux")
	proto := e.initMCP(t)

	t.Run("glob", func(t *testing.T) {
		code, body := e.rpc(t, e.token, proto, "tools/call", map[string]any{
			"name": "glob",
			"arguments": map[string]any{
				"host":    "laptop1",
				"pattern": "**/*.go",
				"path":    "/src",
			},
		})
		if code != http.StatusOK {
			t.Fatalf("tools/call: status %d, body %v", code, body)
		}
		if text := toolResultText(t, body); text != "/a.go\n/b/c.go" {
			t.Fatalf("glob result = %q", text)
		}
	})

	t.Run("list", func(t *testing.T) {
		code, body := e.rpc(t, e.token, proto, "tools/call", map[string]any{
			"name": "list",
			"arguments": map[string]any{
				"host":  "laptop1",
				"path":  "/src",
				"depth": 2,
			},
		})
		if code != http.StatusOK {
			t.Fatalf("tools/call: status %d, body %v", code, body)
		}
		if text := toolResultText(t, body); text != "sub/\nfile.txt" {
			t.Fatalf("list result = %q", text)
		}
	})
}

func TestMCPMachinesResource(t *testing.T) {
	e := newTestEnv(t, "user1", "laptop1", "host1", "linux")
	proto := e.initMCP(t)

	// Список ресурсов: только статический machines, шаблонов нет.
	code, body := e.rpc(t, e.token, proto, "resources/list", nil)
	if code != http.StatusOK {
		t.Fatalf("resources/list: status %d, body %v", code, body)
	}
	res, _ := body["result"].(map[string]any)
	items, _ := res["resources"].([]any)
	if len(items) != 1 {
		t.Fatalf("resources/list: want 1 resource, got %d (%v)", len(items), items)
	}
	if item, ok := items[0].(map[string]any); !ok || item["uri"] != machinesResourceURI {
		t.Fatalf("resources/list: want %s, got %v", machinesResourceURI, items)
	}

	code, body = e.rpc(t, e.token, proto, "resources/read", map[string]any{
		"uri": "akira://machines",
	})
	if code != http.StatusOK {
		t.Fatalf("resources/read machines: status %d, body %v", code, body)
	}
	text := resourceText(t, body)
	want := `[{"client_id":"laptop1","hostname":"host1","platform":"linux"}]`
	if text != want {
		t.Fatalf("machines = %q, want %q", text, want)
	}
}

func TestMCPUnauthorized(t *testing.T) {
	e := newTestEnv(t, "user1", "laptop1", "host1", "linux")

	for _, tt := range []struct {
		name  string
		token string
	}{
		{"no token", ""},
		{"garbage token", "garbage"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			code, _ := e.mcpRequest(t, tt.token, map[string]any{
				"jsonrpc": "2.0", "id": 1, "method": "tools/list",
			})
			if code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", code)
			}
		})
	}
}

// TestMCPOAuthDiscovery — вход в OAuth-флоу: 401 без токена несёт
// WWW-Authenticate с resource_metadata, а PRM-эндпоинт (RFC 9728)
// публичичен и отдаёт resource + authorization_servers.
func TestMCPOAuthDiscovery(t *testing.T) {
	e := newTestEnv(t, "user1", "laptop1", "host1", "linux")

	// 401 с resource_metadata на том же хосте, что MCP-сервер.
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+"/mcp", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	wa := resp.Header.Get("WWW-Authenticate")
	want := `Bearer realm="akira", resource_metadata="http://mcp.test/.well-known/oauth-protected-resource/mcp"`
	if wa != want {
		t.Fatalf("WWW-Authenticate = %q, want %q", wa, want)
	}

	// PRM-метаданные доступны без токена и указывают на auth-сервер.
	prm, err := e.srv.Client().Get(e.srv.URL + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatalf("get PRM: %v", err)
	}
	defer prm.Body.Close()
	if prm.StatusCode != http.StatusOK {
		t.Fatalf("PRM status = %d, want 200", prm.StatusCode)
	}
	var meta struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.NewDecoder(prm.Body).Decode(&meta); err != nil {
		t.Fatalf("decode PRM: %v", err)
	}
	if meta.Resource != "http://mcp.test/mcp" {
		t.Fatalf("PRM resource = %q, want http://mcp.test/mcp", meta.Resource)
	}
	if len(meta.AuthorizationServers) != 1 || meta.AuthorizationServers[0] != "http://auth.test" {
		t.Fatalf("PRM authorization_servers = %v, want [http://auth.test]", meta.AuthorizationServers)
	}

	// Неизвестный путь — 404.
	other, err := e.srv.Client().Get(e.srv.URL + "/other")
	if err != nil {
		t.Fatalf("get /other: %v", err)
	}
	defer other.Body.Close()
	if other.StatusCode != http.StatusNotFound {
		t.Fatalf("/other status = %d, want 404", other.StatusCode)
	}
}

// TestMCPUserIsolation — пользователь user2 не видит машины user1
// и не может отправить на них задачу (exec по client_id user1
// завершается «client not connected»).
func TestMCPUserIsolation(t *testing.T) {
	e := newTestEnv(t, "user1", "laptop1", "host1", "linux")
	proto := e.initMCP(t)

	// Токен другого пользователя.
	otherToken, err := e.mgr.NewAccessToken("user2")
	if err != nil {
		t.Fatalf("NewAccessToken: %v", err)
	}

	// machines для user2 пуст.
	code, body := e.rpc(t, otherToken, proto, "resources/read", map[string]any{
		"uri": "akira://machines",
	})
	if code != http.StatusOK {
		t.Fatalf("resources/read machines: status %d, body %v", code, body)
	}
	if got := resourceText(t, body); got != "[]" {
		t.Fatalf("machines for user2 = %q, want []", got)
	}

	// exec на машину user1 от user2: подключение {user2:laptop1}
	// не существует — ошибка, а не исполнение на чужой машине.
	code, body = e.rpc(t, otherToken, proto, "tools/call", map[string]any{
		"name": "exec",
		"arguments": map[string]any{
			"host": "laptop1",
			"cmd":  "echo pwned",
		},
	})
	if code != http.StatusOK {
		t.Fatalf("tools/call: status %d, body %v", code, body)
	}
	res, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", body)
	}
	isErr, _ := res["isError"].(bool)
	if !isErr {
		t.Fatalf("exec from user2 to user1's machine must fail, got %v", body)
	}

	// Подделка connection_id через ':' в host — тоже отказ.
	code, body = e.rpc(t, otherToken, proto, "tools/call", map[string]any{
		"name": "exec",
		"arguments": map[string]any{
			"host": "user1:laptop1",
			"cmd":  "echo pwned",
		},
	})
	if code != http.StatusOK {
		t.Fatalf("tools/call: status %d, body %v", code, body)
	}
	res, _ = body["result"].(map[string]any)
	isErr, _ = res["isError"].(bool)
	if !isErr {
		t.Fatalf("host with ':' must be rejected, got %v", body)
	}
}

// toolNames собирает имена инструментов из ответа tools/list.
func toolNames(body map[string]any) map[string]bool {
	names := map[string]bool{}
	res, _ := body["result"].(map[string]any)
	tools, _ := res["tools"].([]any)
	for _, tl := range tools {
		if tm, ok := tl.(map[string]any); ok {
			if n, ok := tm["name"].(string); ok {
				names[n] = true
			}
		}
	}
	return names
}

// toolResultText достаёт текст первого контента из CallToolResult.
func toolResultText(t *testing.T, body map[string]any) string {
	t.Helper()
	res, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", body)
	}
	contents, _ := res["content"].([]any)
	for _, c := range contents {
		if cm, ok := c.(map[string]any); ok {
			if txt, ok := cm["text"].(string); ok {
				return txt
			}
		}
	}
	return ""
}

// toolIsError сообщает, помечен ли CallToolResult как isError.
func toolIsError(t *testing.T, body map[string]any) bool {
	t.Helper()
	res, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", body)
	}
	isErr, _ := res["isError"].(bool)
	return isErr
}

// resourceText достаёт текст первого TextResourceContents.
func resourceText(t *testing.T, body map[string]any) string {
	t.Helper()
	res, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", body)
	}
	contents, _ := res["contents"].([]any)
	for _, c := range contents {
		if cm, ok := c.(map[string]any); ok {
			if txt, ok := cm["text"].(string); ok {
				return txt
			}
		}
	}
	return ""
}
