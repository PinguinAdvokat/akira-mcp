// Package connection содержит логику подключения akira-client к серверу:
// установление соединения, регистрацию, heartbeat, возврат результатов
// задач и переподключение после разрывов.
package connection

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
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

	// outbox живёт на уровне Run, а не сессии: результаты задач,
	// завершившихся во время разрыва соединения, хранятся в очереди
	// и доставляются после переподключения.
	ob := newOutbox()
	go submitLoop(ctx, client, ob, retry)

	log.Printf("connecting to %s, client_id=%s", cfg.ServerAddr, cfg.ClientID)
	for {
		if err := runSession(ctx, client, cfg.ClientID, ob); err != nil && ctx.Err() == nil {
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
func runSession(ctx context.Context, client pb.ConnectionServiceClient, clientID string, ob *outbox) error {
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

	// Heartbeat живёт, пока жива сессия: при выходе из runSession
	// горутина останавливается.
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go heartbeat(sctx, client, ack.HeartbeatIntervalMs)

	// Приём задач: исполнение запускается в отдельной горутине,
	// чтобы разрыв соединения не прерывал выполняемые задачи.
	for {
		msg, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}
		if task := msg.GetTask(); task != nil {
			go runTask(task, ob)
		}
	}
}

// runTask исполняет задачу и кладёт результат в outbox. Задача
// продолжает исполняться при разрыве соединения; результат хранится
// в outbox до успешной доставки — переживая переподключение.
func runTask(task *pb.Task, ob *outbox) {
	ob.push(executor.Execute(task))
}

// heartbeat периодически вызывает Heartbeat, чтобы сервер видел,
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
				log.Printf("heartbeat failed: %v", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

// outbox — накопитель результатов задач. Очередь не ограничена:
// пока соединения нет, сервер не присылает новые задачи, так что
// в очереди оказываются только результаты уже выполняющихся задач.
type outbox struct {
	mu     sync.Mutex
	queue  []*pb.TaskResult
	notify chan struct{}
}

func newOutbox() *outbox {
	return &outbox{notify: make(chan struct{}, 1)}
}

// push добавляет результат и будит доставщика.
func (o *outbox) push(res *pb.TaskResult) {
	o.mu.Lock()
	o.queue = append(o.queue, res)
	o.mu.Unlock()
	o.wake()
}

// wake сигнализирует доставщику (не блокируется).
func (o *outbox) wake() {
	select {
	case o.notify <- struct{}{}:
	default:
	}
}

// peek возвращает первый результат очереди, не извлекая его.
func (o *outbox) peek() (*pb.TaskResult, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.queue) == 0 {
		return nil, false
	}
	return o.queue[0], true
}

// pop извлекает первый результат очереди.
func (o *outbox) pop() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.queue = o.queue[1:]
}

// len возвращает размер очереди.
func (o *outbox) len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.queue)
}

// submitLoop доставляет результаты из outbox на сервер через
// SubmitResult. При ошибке (нет соединения) результат остаётся
// в очереди, и попытка повторяется через retry — так результат
// доживает до переподключения и доставляется по нему.
func submitLoop(ctx context.Context, client pb.ConnectionServiceClient, ob *outbox, retry time.Duration) {
	for {
		select {
		case <-ctx.Done():
			if n := ob.len(); n > 0 {
				log.Printf("client stopped, dropping %d undelivered results", n)
			}
			return
		case <-ob.notify:
		}
		for {
			res, ok := ob.peek()
			if !ok {
				break
			}
			if _, err := client.SubmitResult(ctx, res); err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("result for task %s not delivered: %v; will retry in %s", res.TaskId, err, retry)
				select {
				case <-ctx.Done():
					return
				case <-time.After(retry):
				}
				continue
			}
			ob.pop()
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
