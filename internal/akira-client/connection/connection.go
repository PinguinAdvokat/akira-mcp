// Package connection содержит логику подключения akira-client к серверу:
// установление соединения, регистрацию, heartbeat и переподключение
// после разрывов.
package connection

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/PinguinAdvokat/akira-mcp/internal/akira-client/executor"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
)

// defaultRetryDelay — пауза между попытками переподключения по умолчанию.
const defaultRetryDelay = 3 * time.Second

// defaultHeartbeatMs используется, если сервер не сообщил интервал пинга.
const defaultHeartbeatMs = 30_000

// Config — параметры подключения клиента.
type Config struct {
	// ServerAddr — адрес akira-server (host:port).
	ServerAddr string
	// ClientID — уникальный идентификатор клиента; задаётся пользователем
	// и не меняется, поэтому при переподключении сервер видит тот же
	// id подключения.
	ClientID string
	// RetryDelay — пауза между попытками переподключения; 0 = 3с.
	RetryDelay time.Duration
}

// Run подключается к серверу и поддерживает соединение, переподключаясь
// после разрывов, пока ctx не отменят.
func Run(ctx context.Context, cfg Config) error {
	if cfg.ClientID == "" {
		return errors.New("client_id is not set")
	}
	retry := cfg.RetryDelay
	if retry <= 0 {
		retry = defaultRetryDelay
	}

	conn, err := grpc.NewClient(cfg.ServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to create gRPC client: %w", err)
	}
	defer conn.Close()
	client := pb.NewConnectionServiceClient(conn)

	log.Printf("connecting to %s, client_id=%s", cfg.ServerAddr, cfg.ClientID)
	for {
		if err := runSession(ctx, client, cfg.ClientID); err != nil && ctx.Err() == nil {
			log.Printf("connection lost: %v; reconnecting in %s", err, retry)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(retry):
		}
	}
}

// runSession устанавливает подключение, регистрируется с client_id
// и обслуживает поток до разрыва или отмены ctx.
func runSession(ctx context.Context, client pb.ConnectionServiceClient, clientID string) error {
	// Регистрация выполняется самим запросом Connect; сервер присылает
	// RegisterResponse первым сообщением одностороннего потока.
	stream, err := client.Connect(ctx, &pb.RegisterRequest{
		ClientId: clientID,
		Hostname: hostname(),
		Platform: runtime.GOOS,
	})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	msg, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("register ack: %w", err)
	}
	ack := msg.GetRegisterAck()
	if ack == nil {
		return fmt.Errorf("expected RegisterResponse as the first message, got %T", msg.Payload)
	}
	log.Printf("registered: session_id=%s", ack.SessionId)

	go heartbeat(ctx, client, ack.HeartbeatIntervalMs)

	// Приём задач: исполнение запускается в отдельной горутине,
	// чтобы разрыв соединения не прерывал выполняемые задачи.
	for {
		msg, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}
		if task := msg.GetTask(); task != nil {
			go runTask(ctx, client, task)
		}
	}
}

// runTask исполняет задачу и отправляет результат через SubmitResult.
// Задача продолжает исполняться при разрыве соединения; если результат
// доставить уже некуда — это логируется.
func runTask(ctx context.Context, client pb.ConnectionServiceClient, task *pb.Task) {
	res := executor.Execute(task)
	if _, err := client.SubmitResult(ctx, res); err != nil {
		log.Printf("task %s finished, but its result was not delivered: %v", task.Id, err)
	}
}

// heartbeat периодически вызывает Ping, чтобы сервер видел,
// что клиент жив.
func heartbeat(ctx context.Context, client pb.ConnectionServiceClient, intervalMs int64) {
	if intervalMs <= 0 {
		intervalMs = defaultHeartbeatMs
	}
	ticker := time.NewTicker(time.Duration(intervalMs) * time.Millisecond)
	defer ticker.Stop()
	var seq int64
	for {
		select {
		case <-ticker.C:
			seq++
			if _, err := client.Heartbeat(ctx, &pb.Ping{Seq: seq}); err != nil {
				log.Printf("ping failed: %v", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

// hostname возвращает имя хоста или "unknown".
func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}
