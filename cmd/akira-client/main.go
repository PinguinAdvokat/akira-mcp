package main

import (
	"context"
	"flag"
	"log"

	"github.com/PinguinAdvokat/akira-mcp/internal/akira-client/connection"
)

var (
	// serverAddr — адрес akira-server, задаётся флагом -server.
	serverAddr = flag.String("server", "localhost:5000", "akira-server address (host:port)")
	// clientID — уникальный идентификатор клиента, задаётся флагом -client-id.
	clientID = flag.String("client-id", "", "unique client id (required)")
	// retryDelay — пауза между попытками переподключения.
	retryDelay = flag.Duration("retry-delay", 0, "pause between reconnect attempts (0 = 3s)")
)

func main() {
	flag.Parse()
	if *clientID == "" {
		log.Fatal("the -client-id flag is required")
	}

	// Логика подключения — в internal/akira-client/connection:
	// client_id не меняется, при разрыве клиент переподключается
	// с тем же id, выполняемые задачи не прерываются.
	if err := connection.Run(context.Background(), connection.Config{
		ServerAddr: *serverAddr,
		ClientID:   *clientID,
		RetryDelay: *retryDelay,
	}); err != nil {
		log.Fatal(err)
	}
}
