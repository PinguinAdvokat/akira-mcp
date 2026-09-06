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

// session — одно подключение к серверу: stream, очередь исходящих
// сообщений и канал завершения.
type session struct {
	stream pb.ConnectionService_ConnectClient
	out    chan *pb.ClientMessage
	done   chan struct{}
}

// runSession устанавливает подключение, регистрируется с client_id
// и обслуживает поток до разрыва или отмены ctx.
func runSession(ctx context.Context, client pb.ConnectionServiceClient, clientID string) error {
	stream, err := client.Connect(ctx)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	// Регистрация — первое сообщение в потоке.
	if err := stream.Send(&pb.ClientMessage{
		Payload: &pb.ClientMessage_Register{
			Register: &pb.RegisterRequest{
				ClientId: clientID,
				Hostname: hostname(),
				Platform: runtime.GOOS,
			},
		},
	}); err != nil {
		return fmt.Errorf("register send: %w", err)
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

	s := &session{
		stream: stream,
		out:    make(chan *pb.ClientMessage, 16),
		done:   make(chan struct{}),
	}
	// done закрывается один раз — здесь, при выходе из сессии;
	// writer и heartbeat выходят по нему.
	defer close(s.done)

	go s.writeLoop()
	go s.heartbeat(ack.HeartbeatIntervalMs)

	// Приём задач: исполнение запускается в отдельной горутине,
	// чтобы разрыв соединения не прерывал выполняемые задачи.
	for {
		msg, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}
		if task := msg.GetTask(); task != nil {
			go s.runTask(task)
		}
		// Pong игнорируем.
	}
}

// runTask исполняет задачу и отправляет результат. Задача продолжает
// исполняться при разрыве соединения; если результат доставить уже
// некуда — это логируется.
func (s *session) runTask(task *pb.Task) {
	res := executor.Execute(task)
	if err := s.post(&pb.ClientMessage{
		Payload: &pb.ClientMessage_Result{Result: res},
	}); err != nil {
		log.Printf("task %s finished, but its result was not delivered: %v", task.Id, err)
	}
}

// writeLoop — единственный писатель в stream (параллельные Send
// в один gRPC stream запрещены).
func (s *session) writeLoop() {
	for {
		select {
		case msg := <-s.out:
			if err := s.stream.Send(msg); err != nil {
				log.Printf("stream send failed: %v", err)
				return
			}
		case <-s.done:
			return
		}
	}
}

// heartbeat периодически отправляет Ping, чтобы сервер видел, что клиент жив.
func (s *session) heartbeat(intervalMs int64) {
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
			_ = s.post(&pb.ClientMessage{
				Payload: &pb.ClientMessage_Ping{Ping: &pb.Ping{Seq: seq}},
			})
		case <-s.done:
			return
		}
	}
}

// post ставит исходящее сообщение в очередь к writeLoop.
func (s *session) post(msg *pb.ClientMessage) error {
	select {
	case s.out <- msg:
		return nil
	case <-s.done:
		return errors.New("connection closed")
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
