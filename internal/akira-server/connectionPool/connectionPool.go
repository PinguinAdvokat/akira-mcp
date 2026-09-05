package connectionpool

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	// ErrAlreadyRegistered — клиент с таким client_id уже подключен.
	ErrAlreadyRegistered = errors.New("connectionpool: client already registered")
	// ErrConnectionNotFound — активного подключения с таким client_id нет.
	ErrConnectionNotFound = errors.New("connectionpool: connection not found")
	// ErrConnectionClosed — подключение закрыто.
	ErrConnectionClosed = errors.New("connectionpool: connection closed")
)

// ConnectionPool хранит активные stream-подключения клиентов по client_id.
// Через SendTask любые объекты сервера могут отправлять задачи
// на исполнение клиенту по id подключения.
type ConnectionPool struct {
	mu    sync.RWMutex
	conns map[string]*ClientConnection
}

func New() *ConnectionPool {
	return &ConnectionPool{conns: make(map[string]*ClientConnection)}
}

// Register добавляет новое подключение в пул.
// Возвращает ошибку, если клиент с таким client_id уже подключен.
func (p *ConnectionPool) Register(clientID string) (*ClientConnection, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.conns[clientID]; ok {
		return nil, ErrAlreadyRegistered
	}
	c := &ClientConnection{
		ClientID:  clientID,
		SessionID: newID(),
		out:       make(chan *pb.ServerMessage, 16),
		done:      make(chan struct{}),
		pending:   make(map[string]chan *pb.TaskResult),
	}
	p.conns[clientID] = c
	return c, nil
}

// Unregister убирает подключение из пула и будит ждущие Execute.
func (p *ConnectionPool) Unregister(conn *ClientConnection) {
	p.mu.Lock()
	if p.conns[conn.ClientID] != conn {
		p.mu.Unlock()
		return
	}
	delete(p.conns, conn.ClientID)
	p.mu.Unlock()
	conn.close()
}

// SendTask отправляет задачу клиенту с id clientID и ждёт
// TaskResult по тому же stream-соединению.
func (p *ConnectionPool) SendTask(ctx context.Context, clientID string, task *pb.Task) (*pb.TaskResult, error) {
	p.mu.RLock()
	c := p.conns[clientID]
	p.mu.RUnlock()
	if c == nil {
		return nil, ErrConnectionNotFound
	}
	return c.Execute(ctx, task)
}

// ClientConnection — одно активное stream-подключение клиента.
type ClientConnection struct {
	ClientID  string
	SessionID string

	out     chan *pb.ServerMessage
	done    chan struct{}
	mu      sync.Mutex
	pending map[string]chan *pb.TaskResult
}

// Out — канал исходящих сообщений; сервер вычитывает их
// и пишет в gRPC stream (единственный писатель).
func (c *ClientConnection) Out() <-chan *pb.ServerMessage { return c.out }

// Post ставит сообщение в очередь на отправку клиенту.
func (c *ClientConnection) Post(msg *pb.ServerMessage) error {
	select {
	case c.out <- msg:
		return nil
	case <-c.done:
		return ErrConnectionClosed
	}
}

// Execute отправляет задачу клиенту и блокируется до результата,
// закрытия соединения, таймаута задачи или отмены ctx.
func (c *ClientConnection) Execute(ctx context.Context, task *pb.Task) (*pb.TaskResult, error) {
	if task.Id == "" {
		task.Id = newID()
	}
	if task.CreatedAt == nil {
		task.CreatedAt = timestamppb.Now()
	}

	ch := make(chan *pb.TaskResult, 1)
	c.mu.Lock()
	c.pending[task.Id] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, task.Id)
		c.mu.Unlock()
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
	case <-c.done:
		return nil, ErrConnectionClosed
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

// HandleResult доставляет TaskResult ждущему Execute.
func (c *ClientConnection) HandleResult(res *pb.TaskResult) {
	c.mu.Lock()
	ch, ok := c.pending[res.TaskId]
	if ok {
		delete(c.pending, res.TaskId)
	}
	c.mu.Unlock()
	if ok {
		ch <- res
	}
}

func (c *ClientConnection) close() {
	close(c.done)
	close(c.out)
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, ch := range c.pending {
		delete(c.pending, id)
		ch <- &pb.TaskResult{
			TaskId: id,
			Status: pb.TaskResult_STATUS_ERROR,
			Error:  "connection closed",
		}
	}
}

// newID возвращает случайный hex-идентификатор (session_id / task id).
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand не должен падать
	}
	return hex.EncodeToString(b[:])
}
