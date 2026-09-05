package client

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ClientConnection — одно активное stream-подключение клиента.
type ClientConnection struct {
	ClientID  string
	SessionID string

	out     chan *pb.ServerMessage
	done    chan struct{}
	mu      sync.Mutex
	pending map[string]chan *pb.TaskResult
}

func New(clientID string) *ClientConnection {
	return &ClientConnection{
		ClientID:  clientID,
		SessionID: connection.NewID(),
		out:       make(chan *pb.ServerMessage, 16),
		done:      make(chan struct{}),
		pending:   make(map[string]chan *pb.TaskResult),
	}
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
		return connection.ErrConnectionClosed
	}
}

// Execute отправляет задачу клиенту и блокируется до результата,
// закрытия соединения, таймаута задачи или отмены ctx.
func (c *ClientConnection) Execute(ctx context.Context, task *pb.Task) (*pb.TaskResult, error) {
	if task.Id == "" {
		task.Id = connection.NewID()
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

func (c *ClientConnection) Close() {
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
