package akiramcp

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
)

// machinesResourceURI — URI статического ресурса списка машин.
const machinesResourceURI = "akira://machines"

// addResources регистрирует статический ресурс akira://machines.
// URI-шаблонов нет намеренно: часть MCP-хостов их не показывает,
// чтение файлов выполняется инструментом read.
func addResources(s *mcpServer, cfg Config) {
	s.AddResource(mcp.NewResource(machinesResourceURI, "Connected machines",
		mcp.WithResourceDescription("Machines of the user connected to this server "+
			"(client_id, hostname, platform). Pass the client_id value as the host argument of the tools."),
	), machinesResource(cfg))
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
