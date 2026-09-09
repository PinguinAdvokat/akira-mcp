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
// эхом с exit_code=0, read_file — фиксированным содержимым,
// write_file — успехом.
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
		res.Stdout = []byte("content of " + p.ReadFile.Path)
	case *pb.Task_WriteFile:
		// успех без содержимого
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
	if !names["exec"] || !names["write_file"] {
		t.Fatalf("tools/list: want exec and write_file, got %v", names)
	}
}

func TestMCPExecTool(t *testing.T) {
	e := newTestEnv(t, "user1", "laptop1", "host1", "linux")
	proto := e.initMCP(t)

	code, body := e.rpc(t, e.token, proto, "tools/call", map[string]any{
		"name": "exec",
		"arguments": map[string]any{
			"client_id": "laptop1",
			"cmd":       "echo hi",
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

func TestMCPWriteFileTool(t *testing.T) {
	e := newTestEnv(t, "user1", "laptop1", "host1", "linux")
	proto := e.initMCP(t)

	code, body := e.rpc(t, e.token, proto, "tools/call", map[string]any{
		"name": "write_file",
		"arguments": map[string]any{
			"client_id": "laptop1",
			"path":      "/tmp/x.txt",
			"content":   "hello",
		},
	})
	if code != http.StatusOK {
		t.Fatalf("tools/call: status %d, body %v", code, body)
	}
	if !strings.Contains(toolResultText(t, body), "/tmp/x.txt") {
		t.Fatalf("write_file result should mention path")
	}
}

func TestMCPMachinesResource(t *testing.T) {
	e := newTestEnv(t, "user1", "laptop1", "host1", "linux")
	proto := e.initMCP(t)

	// Список ресурсов: ресурс machines заявлен.
	code, body := e.rpc(t, e.token, proto, "resources/list", nil)
	if code != http.StatusOK {
		t.Fatalf("resources/list: status %d, body %v", code, body)
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

func TestMCPFileResource(t *testing.T) {
	e := newTestEnv(t, "user1", "laptop1", "host1", "linux")
	proto := e.initMCP(t)

	code, body := e.rpc(t, e.token, proto, "resources/read", map[string]any{
		"uri": "akira://file/laptop1/etc/hostname",
	})
	if code != http.StatusOK {
		t.Fatalf("resources/read file: status %d, body %v", code, body)
	}
	// {+path} пропускает слэши: путь многоуровневый.
	if got := resourceText(t, body); got != "content of etc/hostname" {
		t.Fatalf("file content = %q, want %q", got, "content of etc/hostname")
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
			"client_id": "laptop1",
			"cmd":       "echo pwned",
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

	// Подделка connection_id через ':' в client_id — тоже отказ.
	code, body = e.rpc(t, otherToken, proto, "tools/call", map[string]any{
		"name": "exec",
		"arguments": map[string]any{
			"client_id": "user1:laptop1",
			"cmd":       "echo pwned",
		},
	})
	if code != http.StatusOK {
		t.Fatalf("tools/call: status %d, body %v", code, body)
	}
	res, _ = body["result"].(map[string]any)
	isErr, _ = res["isError"].(bool)
	if !isErr {
		t.Fatalf("client_id with ':' must be rejected, got %v", body)
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
