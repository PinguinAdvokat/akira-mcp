package connectionpool

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection"
	"github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/client"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// pendingTask — ждущая результата задача: подключение, которому
// отправлена задача, и канал для доставки TaskResult.
type pendingTask struct {
	conn *client.ClientConnection
	ch   chan *pb.TaskResult
}

// ConnectionPool хранит активные подключения клиентов по client_id
// и реестр задач, ожидающих результат, по task_id. Через SendTask
// любые объекты сервера могут отправлять задачи на исполнение клиенту
// по id подключения; результаты приходят через SubmitResult
// и маршрутизируются по task_id.
type ConnectionPool struct {
	mu      sync.RWMutex
	conns   map[string]*client.ClientConnection
	pending map[string]*pendingTask
}

func New() *ConnectionPool {
	return &ConnectionPool{
		conns:   make(map[string]*client.ClientConnection),
		pending: make(map[string]*pendingTask),
	}
}

// Register добавляет новое подключение в пул.
// Возвращает ошибку, если клиент с таким client_id уже подключен.
func (p *ConnectionPool) Register(clientID string) (*client.ClientConnection, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.conns[clientID]; ok {
		return nil, connection.ErrAlreadyRegistered
	}
	c := client.New(clientID)
	p.conns[clientID] = c
	return c, nil
}

// Unregister убирает подключение из пула, будит ждущие SendTask
// результатом STATUS_ERROR и удаляет их из реестра pending.
// Если в пуле уже лежит другое, более новое подключение — пропускает.
func (p *ConnectionPool) Unregister(conn *client.ClientConnection) {
	p.mu.Lock()
	if p.conns[conn.ClientID] != conn {
		p.mu.Unlock()
		return
	}
	delete(p.conns, conn.ClientID)
	for id, pt := range p.pending {
		if pt.conn == conn {
			delete(p.pending, id)
			pt.ch <- &pb.TaskResult{
				TaskId: id,
				Status: pb.TaskResult_STATUS_ERROR,
				Error:  "connection closed",
			}
		}
	}
	p.mu.Unlock()
	conn.Close()
}

// HandleResult доставляет TaskResult (поступивший через SubmitResult)
// ждущему SendTask по task_id. Результат задачи, которой никто
// не ждёт (например, истёк таймаут), молча отбрасывается.
func (p *ConnectionPool) HandleResult(res *pb.TaskResult) {
	p.mu.Lock()
	pt, ok := p.pending[res.TaskId]
	if ok {
		delete(p.pending, res.TaskId)
	}
	p.mu.Unlock()
	if ok {
		pt.ch <- res
	}
}

// ClientIDs возвращает отсортированный список id подключённых клиентов.
func (p *ConnectionPool) ClientIDs() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ids := make([]string, 0, len(p.conns))
	for id := range p.conns {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Has сообщает, подключён ли клиент с данным client_id.
func (p *ConnectionPool) Has(clientID string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.conns[clientID]
	return ok
}

// SendTask отправляет задачу клиенту с id clientID и блокируется
// до результата (SubmitResult), закрытия соединения, таймаута задачи
// или отмены ctx.
func (p *ConnectionPool) SendTask(ctx context.Context, clientID string, task *pb.Task) (*pb.TaskResult, error) {
	p.mu.RLock()
	c := p.conns[clientID]
	p.mu.RUnlock()
	if c == nil {
		return nil, connection.ErrConnectionNotFound
	}
	if task.Id == "" {
		task.Id = connection.NewID()
	}
	if task.CreatedAt == nil {
		task.CreatedAt = timestamppb.Now()
	}

	ch := make(chan *pb.TaskResult, 1)
	p.mu.Lock()
	p.pending[task.Id] = &pendingTask{conn: c, ch: ch}
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.pending, task.Id)
		p.mu.Unlock()
	}()

	if err := c.Post(&pb.ServerMessage{
		Payload: &pb.ServerMessage_Task{Task: task},
	}); err != nil {
		return nil, err
	}

	if task.TimeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(task.TimeoutMs)*time.Millisecond)
		defer cancel()
	}

	select {
	case res := <-ch:
		return res, nil
	case <-c.Done():
		return nil, connection.ErrConnectionClosed
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return &pb.TaskResult{
				TaskId: task.Id,
				Status: pb.TaskResult_STATUS_TIMEOUT,
				Error:  "task timed out",
			}, nil
		}
		return nil, ctx.Err()
	}
}
