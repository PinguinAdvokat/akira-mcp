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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/PinguinAdvokat/akira-mcp/internal/akira-client/executor"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
)

// defaultRetryDelay — пауза между попытками переподключения по умолчанию.
const defaultRetryDelay = time.Second

// defaultHeartbeatMs используется, если сервер не сообщил интервал пинга.
const defaultHeartbeatMs = 30_000

// minHeartbeatTimeout — нижняя граница таймаута одного вызова Heartbeat.
const minHeartbeatTimeout = 5 * time.Second

// Config — параметры подключения клиента.
type Config struct {
	// ServerAddr — адрес akira-server (host:port).
	ServerAddr string
	// ClientID — уникальный идентификатор клиента; задаётся пользователем
	// и не меняется, поэтому при переподключении сервер видит тот же
	// id подключения.
	ClientID string
	// RetryDelay — пауза между попытками переподключения и между
	// повторными попытками доставки результата (SubmitResult); 0 = 3с.
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

	conn, err := grpc.NewClient(cfg.ServerAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		// keepalive на канале: при «тихом» разрыве (пакеты исчезают,
		// RST нет) Recv по потоку не падает сам по себе — пинг/понг
		// закрывают канал примерно за Time+Timeout (~40с), и клиент
		// переподключается вместо ожидания таймаута TCP (~15 минут).
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
	)
	if err != nil {
		return fmt.Errorf("failed to create gRPC client: %w", err)
	}
	defer conn.Close()
	client := pb.NewConnectionServiceClient(conn)

	// outbox живёт на уровне Run, а не сессии: результаты задач,
	// завершившихся во время разрыва соединения, хранятся в очереди
	// и доставляются после переподключения.
	ob := newOutbox()
	go submitLoop(ctx, client, ob, cfg.ClientID, retry)

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
	// sctx живёт, пока жива сессия: по нему создаётся поток Connect
	// и работает heartbeat; отмена sctx (например, при сбое heartbeat)
	// рвёт и поток, и heartbeat-горутину.
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Регистрация выполняется самим запросом Connect; сервер присылает
	// RegisterResponse первым сообщением одностороннего потока.
	stream, err := client.Connect(sctx, &pb.RegisterRequest{
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

	go heartbeat(sctx, cancel, client, ack.HeartbeatIntervalMs)

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
// что клиент жив. Вызов ограничен таймаутом: при «тихом» разрыве
// вызов без дедлайна завис бы до таймаута TCP (~15 минут). Первая
// ошибка отменяет сессию (cancel) — клиент переподключается, а не
// сидит на мёртвом соединении, пока сервер числит его подключённым.
func heartbeat(ctx context.Context, cancel context.CancelFunc, client pb.ConnectionServiceClient, intervalMs int64) {
	if intervalMs <= 0 {
		intervalMs = defaultHeartbeatMs
	}
	interval := time.Duration(intervalMs) * time.Millisecond
	timeout := interval
	if timeout < minHeartbeatTimeout {
		timeout = minHeartbeatTimeout
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var seq int64
	for {
		select {
		case <-ticker.C:
			seq++
			hctx, hcancel := context.WithTimeout(ctx, timeout)
			pong, err := client.Heartbeat(hctx, &pb.Ping{Seq: seq})
			hcancel()
			if err != nil {
				if ctx.Err() != nil {
					return // сессия уже завершается
				}
				log.Printf("heartbeat failed: %v; dropping the session to reconnect", err)
				cancel()
				return
			}
			if pong.GetSeq() != seq {
				log.Printf("heartbeat seq mismatch: sent %d, got %d", seq, pong.GetSeq())
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
	closed bool
}

func newOutbox() *outbox {
	return &outbox{notify: make(chan struct{}, 1)}
}

// push добавляет результат и будит доставщика. Если доставка уже
// остановлена (клиент завершает работу), результат отбрасывается
// с логом — иначе он потерялся бы в брошенной очереди молча.
func (o *outbox) push(res *pb.TaskResult) {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		log.Printf("dropping result for task %s: client is stopping", res.TaskId)
		return
	}
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

// stop закрывает очередь (последующие push отбрасываются с логом)
// и логирует результаты, оставшиеся без доставки.
func (o *outbox) stop() {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return
	}
	o.closed = true
	n := len(o.queue)
	o.mu.Unlock()
	if n > 0 {
		log.Printf("dropping %d undelivered results (client is stopping)", n)
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

// pop извлекает первый результат очереди. Извлечённый элемент
// обнуляется, а при сильном уменьшении очереди базовый массив
// копируется заново — иначе queue[1:] пиннит данные в памяти.
func (o *outbox) pop() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.queue) == 0 {
		return
	}
	o.queue[0] = nil
	o.queue = o.queue[1:]
	if len(o.queue)*2 < cap(o.queue) {
		fresh := make([]*pb.TaskResult, len(o.queue))
		copy(fresh, o.queue)
		o.queue = fresh
	}
}

// permanentSubmitError сообщает, бессмысленно ли повторять SubmitResult
// с этим результатом: постоянные ошибки (например, ResourceExhausted —
// сообщение больше лимита приёма сервера) не исчезнут при повторе.
func permanentSubmitError(err error) bool {
	s, ok := status.FromError(err)
	if !ok {
		return false
	}
	switch s.Code() {
	case codes.ResourceExhausted, codes.InvalidArgument, codes.Unimplemented,
		codes.NotFound, codes.PermissionDenied, codes.Unauthenticated,
		codes.OutOfRange, codes.FailedPrecondition:
		return true
	}
	return false
}

// submitLoop доставляет результаты из outbox на сервер через
// SubmitResult, подписывая их client_id. При временной ошибке (нет
// соединения) результат остаётся в очереди, и попытка повторяется
// через retry — так результат доживает до переподключения. При
// постоянной ошибке результат отбрасывается с логом: повторение
// не поможет, а копание в очереди навсегда заблокировало бы
// доставку остальных результатов.
func submitLoop(ctx context.Context, client pb.ConnectionServiceClient, ob *outbox, clientID string, retry time.Duration) {
	defer ob.stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ob.notify:
		}
		for {
			res, ok := ob.peek()
			if !ok {
				break
			}
			res.ClientId = clientID
			_, err := client.SubmitResult(ctx, res)
			if err == nil {
				ob.pop()
				continue
			}
			if ctx.Err() != nil {
				return
			}
			if permanentSubmitError(err) {
				log.Printf("dropping result for task %s: %v (will not succeed on retry)", res.TaskId, err)
				ob.pop()
				continue
			}
			log.Printf("result for task %s not delivered: %v; will retry in %s", res.TaskId, err, retry)
			select {
			case <-ctx.Done():
				return
			case <-time.After(retry):
			}
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
