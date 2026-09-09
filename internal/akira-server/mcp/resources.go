package akiramcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/mark3labs/mcp-go/mcp"

	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
)

// machinesResourceURI — URI статического ресурса списка машин.
const machinesResourceURI = "akira://machines"

// fileTemplateURI — URI-шаблон чтения файлов: {+path} — reserved
// expansion RFC 6570, пропускает слэши, поэтому путь может быть
// многоуровневым (akira://file/laptop1/etc/hostname → path=etc/hostname).
const fileTemplateURI = "akira://file/{client_id}/{+path}"

// addResources регистрирует статический ресурс akira://machines
// и шаблон akira://file/{client_id}/{+path}.
func addResources(s *mcpServer, cfg Config) {
	s.AddResource(mcp.NewResource(machinesResourceURI, "Connected machines",
		mcp.WithResourceDescription("Machines of the user connected to this server "+
			"(client_id, hostname, platform). Use client_id in tools and file URIs."),
	), machinesResource(cfg))

	s.AddResourceTemplate(mcp.NewResourceTemplate(fileTemplateURI, "File on a machine",
		mcp.WithTemplateDescription("Read a file from the user's machine: "+
			"akira://file/{client_id}/{path}. Use client_id from akira://machines."),
	), fileResource(cfg))
}

// argString достаёт строковое значение аргумента resource-шаблона:
// mcp-go кладёт значения как []string, но резервный разбор URI
// и будущие версии могут положить string — принимаем оба.
func argString(args map[string]any, name string) string {
	switch v := args[name].(type) {
	case string:
		return v
	case []string:
		if len(v) > 0 {
			return v[0]
		}
	case []any:
		if len(v) > 0 {
			if s, ok := v[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

// machinesResource — обработчик akira://machines: JSON-массив активных
// машин пользователя из пула.
func machinesResource(cfg Config) func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	return func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		type machine struct {
			ClientID string `json:"client_id"`
			Hostname string `json:"hostname"`
			Platform string `json:"platform"`
		}
		machines := make([]machine, 0, 4)
		for _, info := range cfg.Pool.ClientsByUser(ctxUserID(ctx)) {
			machines = append(machines, machine{
				ClientID: info.ClientID,
				Hostname: info.Hostname,
				Platform: info.Platform,
			})
		}
		data, err := json.Marshal(machines)
		if err != nil {
			return nil, err
		}
		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      request.Params.URI,
				MIMEType: "application/json",
				Text:     string(data),
			},
		}, nil
	}
}

// fileResource — обработчик шаблона akira://file/{client_id}/{+path}:
// задача ReadFileRequest на машину клиента. Текст валидного UTF-8
// отдаётся как TextResourceContents, бинарные данные — как
// BlobResourceContents (base64).
func fileResource(cfg Config) func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	return func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		// Переменные шаблона кладёт сервер mcp-go при матче URI
		// (см. handleReadResource): client_id и path. Значения —
		// []string (так mcp-go кладёт Values из uritemplate).
		clientID := argString(request.Params.Arguments, "client_id")
		path := argString(request.Params.Arguments, "path")
		if clientID == "" || path == "" {
			return nil, fmt.Errorf("akiramcp: cannot parse file URI %q", request.Params.URI)
		}

		task := &pb.Task{
			Payload: &pb.Task_ReadFile{ReadFile: &pb.ReadFileRequest{
				Path:     path,
				MaxBytes: int64(cfg.ReadMaxBytes),
			}},
			// Чтение файла не должно висеть вечно на зависшем клиенте.
			TimeoutMs: int64(cfg.TaskTimeoutMs),
		}
		res, err := dispatch(ctx, ctxUserID(ctx), clientID, cfg.Pool, task)
		if err != nil {
			return nil, err
		}
		if res.Status != pb.TaskResult_STATUS_OK {
			return nil, fmt.Errorf("%s", resultErrorText(res))
		}

		uri := request.Params.URI
		if utf8.Valid(res.Stdout) {
			return []mcp.ResourceContents{
				mcp.TextResourceContents{
					URI:      uri,
					MIMEType: "text/plain; charset=utf-8",
					Text:     string(res.Stdout),
				},
			}, nil
		}
		return []mcp.ResourceContents{
			mcp.BlobResourceContents{
				URI:      uri,
				MIMEType: "application/octet-stream",
				Blob:     base64.StdEncoding.EncodeToString(res.Stdout),
			},
		}, nil
	}
}
