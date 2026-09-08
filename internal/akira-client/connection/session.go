package connection

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"sync/atomic"
	"time"

	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"

	"github.com/PinguinAdvokat/akira-mcp/internal/akira-client/executor"
)

// runSession устанавливает подключение, регистрируется с client_id
// и connect_key и обслуживает поток до разрыва или отмены ctx.
func runSession(ctx context.Context, client pb.ConnectionServiceClient, cfg Config, ob *outbox, connID *atomic.Pointer[string]) error {
	// sctx живёт, пока жива сессия: по нему создаётся поток Connect
	// и работает heartbeat; отмена sctx (например, при сбое heartbeat)
	// рвёт и поток, и heartbeat-горутину.
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Регистрация выполняется самим запросом Connect; сервер находит
	// пользователя по connect_key и присылает RegisterResponse первым
	// сообщением одностороннего потока — с назначенным connection_id
	// ({user_id}:{client_id}), которым подписываются результаты задач.
	stream, err := client.Connect(sctx, &pb.RegisterRequest{
		ClientId:   cfg.ClientID,
		Hostname:   hostname(),
		Platform:   runtime.GOOS,
		ConnectKey: cfg.ConnectKey,
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
	if ack.ConnectionId != "" {
		id := ack.ConnectionId
		connID.Store(&id)
	}
	log.Printf("registered: session_id=%s connection_id=%s", ack.SessionId, ack.ConnectionId)

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
