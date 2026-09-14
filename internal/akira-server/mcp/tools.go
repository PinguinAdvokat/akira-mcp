package akiramcp

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection"
	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/pool"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
)

// ErrBadClientID — host не годится для адресации машины: пустой или
// содержит ':' (двоеточие — разделитель {user_id}:{client_id}; с ним
// caller мог бы подделать чужой connection_id).
var ErrBadClientID = errors.New("akiramcp: host must be non-empty and contain no ':'")

// defaultReadLines — сколько строк инструмент read отдаёт без явного limit.
const defaultReadLines = 2000

// maxListDepth — потолок аргумента depth инструмента list.
const maxListDepth = 32

// hostArg описывает общий первый аргумент инструментов — машину,
// на которой выполняется действие.
func hostArg() mcp.ToolOption {
	return mcp.WithString("host",
		mcp.Required(),
		mcp.Description("Machine to run on (client_id from the akira://machines resource)"),
	)
}

// addTools регистрирует инструменты exec, read, edit, write, glob и list.
func addTools(s *mcpServer, cfg Config) {
	s.AddTool(mcp.NewTool("exec",
		mcp.WithDescription("Execute a shell command on the user's machine identified by host "+
			"(see the akira://machines resource for connected machines) and return stdout, stderr and exit code."),
		hostArg(),
		mcp.WithString("cmd",
			mcp.Required(),
			mcp.Description("Shell command to execute"),
		),
		mcp.WithNumber("timeout_ms",
			mcp.Description("Execution timeout in milliseconds; default and maximum are the server's configured limit"),
		),
	), execTool(cfg))

	s.AddTool(mcp.NewTool("read",
		mcp.WithDescription("Read a text file from the user's machine identified by host, "+
			"returning the content with line numbers (cat -n style). Reads a window of lines "+
			"starting at offset. Binary files are not supported — use exec with base64 for those."),
		hostArg(),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path of the file to read"),
		),
		mcp.WithNumber("offset",
			mcp.Description("Line number to start reading from (1-based; default 1)"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Number of lines to read (default 2000)"),
		),
		mcp.WithReadOnlyHintAnnotation(true),
	), readTool(cfg))

	s.AddTool(mcp.NewTool("edit",
		mcp.WithDescription("Replace an exact string in a file on the user's machine identified by host. "+
			"old_str must appear in the file exactly once, unless replace_all is set to replace every occurrence."),
		hostArg(),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path of the file to edit"),
		),
		mcp.WithString("old_str",
			mcp.Required(),
			mcp.Description("Exact text to replace (must be unique in the file unless replace_all is set)"),
		),
		mcp.WithString("new_str",
			mcp.Required(),
			mcp.Description("Replacement text"),
		),
		mcp.WithBoolean("replace_all",
			mcp.Description("Replace every occurrence of old_str (default false)"),
		),
		mcp.WithDestructiveHintAnnotation(true),
	), editTool(cfg))

	s.AddTool(mcp.NewTool("write",
		mcp.WithDescription("Write a file on the user's machine identified by host, creating parent "+
			"directories as needed. Existing files keep their permissions; new files are 0644."),
		hostArg(),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path of the file to write"),
		),
		mcp.WithString("content",
			mcp.Required(),
			mcp.Description("File content (UTF-8 text)"),
		),
		mcp.WithDestructiveHintAnnotation(true),
	), writeTool(cfg))

	s.AddTool(mcp.NewTool("glob",
		mcp.WithDescription("Find files on the user's machine identified by host by glob pattern "+
			"(supports **, *, ?, [class] and {a,b} brace expansion) and return the matching absolute paths."),
		hostArg(),
		mcp.WithString("pattern",
			mcp.Required(),
			mcp.Description("Glob pattern relative to path, e.g. \"**/*.go\""),
		),
		mcp.WithString("path",
			mcp.Description("Base directory to search in (default: the client's working directory)"),
		),
		mcp.WithReadOnlyHintAnnotation(true),
	), globTool(cfg))

	s.AddTool(mcp.NewTool("list",
		mcp.WithDescription("List the contents of a directory on the user's machine identified by host, "+
			"up to the given depth. Directories are suffixed with '/'."),
		hostArg(),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path of the directory to list"),
		),
		mcp.WithNumber("depth",
			mcp.Description("How deep to recurse (1 = direct children only; default 1, max 32)"),
		),
		mcp.WithReadOnlyHintAnnotation(true),
	), listTool(cfg))
}

// execTool — обработчик инструмента exec: задача ExecTask на машину
// клиента, результат отдаётся текстом (status, exit_code, duration,
// stdout, stderr).
func execTool(cfg Config) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		clientID, err := request.RequireString("host")
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

// readTool — обработчик инструмента read: задача ReadFileRequest
// (окно строк offset..offset+limit) на машину клиента. Нумерация строк
// выполняется здесь, в формате cat -n: ширина по номеру последней
// показанной строки (минимум 3), затем таб.
func readTool(cfg Config) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		clientID, err := request.RequireString("host")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		path, err := request.RequireString("path")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		offset := request.GetInt("offset", 1)
		if offset < 1 {
			return mcp.NewToolResultError("offset must be >= 1"), nil
		}
		limit := request.GetInt("limit", 0)
		if limit <= 0 {
			limit = defaultReadLines
		}

		task := &pb.Task{
			Payload: &pb.Task_ReadFile{ReadFile: &pb.ReadFileRequest{
				Path:     path,
				MaxBytes: int64(cfg.ReadMaxBytes),
				Offset:   int64(offset),
				Limit:    int64(limit),
			}},
			// Чтение файла не должно висеть вечно на зависшем клиенте.
			TimeoutMs: int64(cfg.TaskTimeoutMs),
		}
		res, err := dispatch(ctx, ctxUserID(ctx), clientID, cfg.Pool, task)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("read failed", err), nil
		}
		if res.Status != pb.TaskResult_STATUS_OK {
			return mcp.NewToolResultError(resultErrorText(res)), nil
		}

		// offset за концом файла — понятная ошибка вместо пустого ответа.
		if res.TotalLines > 0 && int64(offset) > res.TotalLines {
			return mcp.NewToolResultError(fmt.Sprintf(
				"file %s has only %d lines (offset %d is beyond end of file)",
				path, res.TotalLines, offset)), nil
		}

		lines := splitLines(res.Stdout)
		if len(lines) == 0 {
			return mcp.NewToolResultText("(empty file)"), nil
		}

		width := max(3, len(strconv.Itoa(offset+len(lines)-1)))
		var b strings.Builder
		for i, line := range lines {
			fmt.Fprintf(&b, "%*d\t%s\n", width, offset+i, line)
		}
		// Футер показывается, когда окно не покрывает весь файл целиком.
		last := offset + len(lines) - 1
		if len(lines) < limit || offset > 1 || res.Truncated {
			fmt.Fprintf(&b, "[%d-%d of %d lines]", offset, last, res.TotalLines)
			if res.Truncated {
				b.WriteString(" (truncated at byte limit)")
			}
			b.WriteByte('\n')
		}
		return mcp.NewToolResultText(b.String()), nil
	}
}

// editTool — обработчик инструмента edit: задача EditFileRequest
// на машину клиента. Семантические ошибки (old_str не найден,
// найден несколько раз) приходят как STATUS_ERROR и перекладываются
// в текст ошибки инструмента через resultErrorText.
func editTool(cfg Config) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		clientID, err := request.RequireString("host")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		path, err := request.RequireString("path")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		oldStr, err := request.RequireString("old_str")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		newStr, err := request.RequireString("new_str")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		replaceAll := request.GetBool("replace_all", false)

		task := &pb.Task{
			Payload: &pb.Task_EditFile{EditFile: &pb.EditFileRequest{
				Path:       path,
				OldStr:     oldStr,
				NewStr:     newStr,
				ReplaceAll: replaceAll,
			}},
			TimeoutMs: int64(cfg.TaskTimeoutMs),
		}
		res, err := dispatch(ctx, ctxUserID(ctx), clientID, cfg.Pool, task)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("edit failed", err), nil
		}
		if res.Status != pb.TaskResult_STATUS_OK {
			return mcp.NewToolResultError(resultErrorText(res)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("edited %s: %s (%d ms)",
			path, strings.TrimSpace(string(res.Stdout)), res.DurationMs)), nil
	}
}

// writeTool — обработчик инструмента write: задача WriteFileRequest
// на машину клиента. Родительские каталоги создаются всегда.
func writeTool(cfg Config) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		clientID, err := request.RequireString("host")
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

		task := &pb.Task{
			Payload: &pb.Task_WriteFile{WriteFile: &pb.WriteFileRequest{
				Path:       path,
				Content:    []byte(content),
				CreateDirs: true,
			}},
			// Чтение-запись файлов не исполняется бесконечно: таймаут
			// защищает ожидание от зависшего клиента.
			TimeoutMs: int64(cfg.TaskTimeoutMs),
		}
		res, err := dispatch(ctx, ctxUserID(ctx), clientID, cfg.Pool, task)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("write failed", err), nil
		}
		if res.Status != pb.TaskResult_STATUS_OK {
			return mcp.NewToolResultError(resultErrorText(res)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("written %s (%d ms)", path, res.DurationMs)), nil
	}
}

// globTool — обработчик инструмента glob: задача GlobRequest
// на машину клиента; результат (список путей) передаётся как есть.
func globTool(cfg Config) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		clientID, err := request.RequireString("host")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		pattern, err := request.RequireString("pattern")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		basePath := request.GetString("path", ".")

		task := &pb.Task{
			Payload: &pb.Task_Glob{Glob: &pb.GlobRequest{
				Path:    basePath,
				Pattern: pattern,
			}},
			TimeoutMs: int64(cfg.TaskTimeoutMs),
		}
		res, err := dispatch(ctx, ctxUserID(ctx), clientID, cfg.Pool, task)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("glob failed", err), nil
		}
		if res.Status != pb.TaskResult_STATUS_OK {
			return mcp.NewToolResultError(resultErrorText(res)), nil
		}
		return mcp.NewToolResultText(relayResultText(res)), nil
	}
}

// listTool — обработчик инструмента list: задача ListRequest
// на машину клиента; листинг передаётся как есть.
func listTool(cfg Config) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		clientID, err := request.RequireString("host")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		path, err := request.RequireString("path")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		depth := request.GetInt("depth", 1)
		if depth < 1 {
			return mcp.NewToolResultError("depth must be >= 1"), nil
		}
		depth = min(depth, maxListDepth)

		task := &pb.Task{
			Payload: &pb.Task_List{List: &pb.ListRequest{
				Path:  path,
				Depth: int32(depth),
			}},
			TimeoutMs: int64(cfg.TaskTimeoutMs),
		}
		res, err := dispatch(ctx, ctxUserID(ctx), clientID, cfg.Pool, task)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("list failed", err), nil
		}
		if res.Status != pb.TaskResult_STATUS_OK {
			return mcp.NewToolResultError(resultErrorText(res)), nil
		}
		return mcp.NewToolResultText(relayResultText(res)), nil
	}
}

// relayResultText собирает текст результата glob/list: stdout клиента
// и, при обрезке лимитом, футер с числом показанных записей.
func relayResultText(res *pb.TaskResult) string {
	text := strings.TrimRight(string(res.Stdout), "\n")
	if res.Truncated {
		shown := res.TotalLines
		if shown > 0 {
			shown = min(shown, int64(strings.Count(text, "\n")+1))
		}
		text += fmt.Sprintf("\n(showing first %d of %d)", shown, res.TotalLines)
	}
	return text
}

// splitLines режет содержимое на строки, отбрасывая пустой элемент
// после финального '\n'.
func splitLines(data []byte) []string {
	s := strings.Split(string(data), "\n")
	if n := len(s); n > 0 && s[n-1] == "" {
		s = s[:n-1]
	}
	return s
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
