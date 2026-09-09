package akiramcp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection"
	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/pool"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
)

// ErrBadClientID — client_id не годится для адресации машины:
// пустой или содержит ':' (двоеточие — разделитель {user_id}:{client_id};
// с ним caller мог бы подделать чужой connection_id).
var ErrBadClientID = errors.New("akiramcp: client_id must be non-empty and contain no ':'")

// addTools регистрирует инструменты exec и write_file.
func addTools(s *mcpServer, cfg Config) {
	s.AddTool(mcp.NewTool("exec",
		mcp.WithDescription("Execute a shell command on the user's machine identified by client_id "+
			"(see akira://machines resource for connected machines) and return stdout, stderr and exit code."),
		mcp.WithString("client_id",
			mcp.Required(),
			mcp.Description("Machine to run the command on (client_id from akira://machines)"),
		),
		mcp.WithString("cmd",
			mcp.Required(),
			mcp.Description("Shell command to execute"),
		),
		mcp.WithNumber("timeout_ms",
			mcp.Description("Execution timeout in milliseconds; default and maximum are the server's configured limit"),
		),
	), execTool(cfg))

	s.AddTool(mcp.NewTool("write_file",
		mcp.WithDescription("Write a file on the user's machine identified by client_id "+
			"(see akira://machines resource for connected machines)."),
		mcp.WithString("client_id",
			mcp.Required(),
			mcp.Description("Machine to write the file on (client_id from akira://machines)"),
		),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path of the file to write"),
		),
		mcp.WithString("content",
			mcp.Required(),
			mcp.Description("File content (UTF-8 text)"),
		),
		mcp.WithBoolean("create_dirs",
			mcp.Description("Create parent directories if missing (default true)"),
		),
	), writeFileTool(cfg))
}

// execTool — обработчик инструмента exec: задача ExecTask на машину
// клиента, результат отдаётся текстом (status, exit_code, duration,
// stdout, stderr).
func execTool(cfg Config) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		clientID, err := request.RequireString("client_id")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		cmd, err := request.RequireString("cmd")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		timeoutMs := cfg.TaskTimeoutMs
		if raw := request.GetInt("timeout_ms", 0); raw > 0 {
			timeoutMs = min(raw, cfg.TaskTimeoutMs)
		}

		task := &pb.Task{
			Payload:   &pb.Task_Exec{Exec: &pb.ExecTask{Cmd: cmd}},
			TimeoutMs: int64(timeoutMs),
		}
		res, err := dispatch(ctx, ctxUserID(ctx), clientID, cfg.Pool, task)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("exec failed", err), nil
		}
		if res.Status != pb.TaskResult_STATUS_OK {
			return mcp.NewToolResultError(resultErrorText(res)), nil
		}

		var b strings.Builder
		fmt.Fprintf(&b, "exit_code=%d duration_ms=%d\n", res.ExitCode, res.DurationMs)
		if len(res.Stdout) > 0 {
			b.WriteString("--- stdout ---\n")
			b.Write(res.Stdout)
			b.WriteByte('\n')
		}
		if len(res.Stderr) > 0 {
			b.WriteString("--- stderr ---\n")
			b.Write(res.Stderr)
			b.WriteByte('\n')
		}
		return mcp.NewToolResultText(b.String()), nil
	}
}

// writeFileTool — обработчик инструмента write_file: задача
// WriteFileRequest на машину клиента.
func writeFileTool(cfg Config) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		clientID, err := request.RequireString("client_id")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		path, err := request.RequireString("path")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		content, err := request.RequireString("content")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		createDirs := request.GetBool("create_dirs", true)

		task := &pb.Task{
			Payload: &pb.Task_WriteFile{WriteFile: &pb.WriteFileRequest{
				Path:       path,
				Content:    []byte(content),
				CreateDirs: createDirs,
			}},
			// Чтение-запись файлов не исполняется бесконечно: таймаут
			// защищает ожидание от зависшего клиента.
			TimeoutMs: int64(cfg.TaskTimeoutMs),
		}
		res, err := dispatch(ctx, ctxUserID(ctx), clientID, cfg.Pool, task)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("write_file failed", err), nil
		}
		if res.Status != pb.TaskResult_STATUS_OK {
			return mcp.NewToolResultError(resultErrorText(res)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("written %s (%d ms)", path, res.DurationMs)), nil
	}
}

// dispatch отправляет задачу на машину clientID пользователя userID
// и ждёт результат. connection_id собирается из префикса пользователя:
// чужие машины адресовать нельзя (пул просто не найдёт подключение).
func dispatch(ctx context.Context, userID, clientID string, pool *connectionpool.ConnectionPool, task *pb.Task) (*pb.TaskResult, error) {
	if clientID == "" || strings.Contains(clientID, ":") {
		return nil, ErrBadClientID
	}
	connectionID := userID + ":" + clientID
	res, err := pool.SendTask(ctx, connectionID, task)
	if err != nil {
		// Отмена/дедлайн контекста HTTP-запроса: клиент MCP ушёл,
		// переводим в понятную ошибку.
		switch {
		case errors.Is(err, connection.ErrConnectionNotFound):
			return nil, fmt.Errorf("client %q is not connected", clientID)
		case errors.Is(err, connection.ErrConnectionClosed):
			return nil, fmt.Errorf("connection to client %q was lost", clientID)
		default:
			return nil, err
		}
	}
	return res, nil
}

// resultErrorText собирает описание неудачного TaskResult.
func resultErrorText(res *pb.TaskResult) string {
	msg := fmt.Sprintf("status=%s", res.Status)
	if res.ExitCode != 0 {
		msg += fmt.Sprintf(" exit_code=%d", res.ExitCode)
	}
	if res.Error != "" {
		msg += ": " + res.Error
	}
	if len(res.Stderr) > 0 {
		msg += "\n--- stderr ---\n" + string(res.Stderr)
	}
	return msg
}
