// Package connection содержит логику подключения akira-client к серверу:
// установление соединения, регистрацию, heartbeat, возврат результатов
// задач и переподключение после разрывов.
//
// Файлы пакета: run.go — цикл переподключения и конфигурация;
// session.go — жизненный цикл одной сессии; outbox.go — накопитель
// результатов и их доставка через SubmitResult.
package connection

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
)

// defaultRetryDelay — пауза между попытками переподключения по умолчанию.
const defaultRetryDelay = 3 * time.Second

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
	// ConnectKey — короткий ключ пользователя из auth-сервиса:
	// по нему сервер определяет владельца подключения.
	ConnectKey string
	// RetryDelay — пауза между попытками переподключения и между
	// повторными попытками доставки результата (SubmitResult); 0 = 3с.
	RetryDelay time.Duration
}

// Run подключается к серверу и поддерживает соединение, переподключаясь
// после разрывов, пока ctx не отменят. Причиной отказа может быть
// заведомо нерешаемый ключ (неизвестный connect_key, неподтверждённый
// email) — в этом случае Run возвращает ошибку без ретраев.
func Run(ctx context.Context, cfg Config) error {
	if cfg.ClientID == "" {
		return errors.New("client_id is not set")
	}
	if cfg.ConnectKey == "" {
		return errors.New("connect_key is not set")
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
	// и доставляются после переподключения. connection_id приходит
	// с первым ack и стабилен для пары user+client (вычисляется
	// из connect_key и client_id), поэтому подпись результатов
	// переживает переподключения.
	ob := newOutbox()
	var connID atomic.Pointer[string]
	go submitLoop(ctx, client, ob, &connID, retry)

	log.Printf("connecting to %s, client_id=%s", cfg.ServerAddr, cfg.ClientID)
	for {
		err := runSession(ctx, client, cfg, ob, &connID)
		if err != nil && ctx.Err() == nil {
			if isFatalConnectError(err) {
				// Неизвестный connect_key или неподтверждённый email:
				// повтор не изменит исхода.
				log.Printf("connect rejected: %v; giving up (check connect_key)", err)
				ob.stop()
				return err
			}
			log.Printf("connection lost: %v; reconnecting in %s", err, retry)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(retry):
		}
	}
}

// isFatalConnectError сообщает, бессмысленно ли переподключаться
// после такой ошибки Connect: неверный ключ никогда не станет верным
// сам собой.
func isFatalConnectError(err error) bool {
	s, ok := status.FromError(err)
	if !ok {
		return false
	}
	return s.Code() == codes.Unauthenticated || s.Code() == codes.PermissionDenied
}

// hostname возвращает имя хоста или "unknown".
func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}
