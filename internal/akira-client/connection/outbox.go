package connection

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
)

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
// SubmitResult, подписывая их connection_id из RegisterResponse.
// connection_id стабилен для пары user+client, поэтому подпись верна
// и для результатов, поставленных в очередь до переподключения.
// При временной ошибке (нет соединения) результат остаётся в очереди,
// и попытка повторяется через retry — так результат доживает до
// переподключения. При постоянной ошибке результат отбрасывается
// с логом: повторение не поможет, а копание в очереди навсегда
// заблокировало бы доставку остальных результатов.
func submitLoop(ctx context.Context, client pb.ConnectionServiceClient, ob *outbox, connID *atomic.Pointer[string], retry time.Duration) {
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
			// Штампуем актуальный connection_id при каждой попытке:
			// задача могла быть поставлена в очередь до регистрации
			// или при предыдущем ключе пользователя.
			if id := connID.Load(); id != nil {
				res.ClientId = *id
			}
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
