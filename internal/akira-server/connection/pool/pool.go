package connectionpool

import (
	"context"
	"sync"

	"github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection"
	"github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/client"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
)

// ConnectionPool хранит активные stream-подключения клиентов по client_id.
// Через SendTask любые объекты сервера могут отправлять задачи
// на исполнение клиенту по id подключения.
type ConnectionPool struct {
	mu    sync.RWMutex
	conns map[string]*client.ClientConnection
}

func New() *ConnectionPool {
	return &ConnectionPool{conns: make(map[string]*client.ClientConnection)}
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

// Unregister убирает подключение из пула и будит ждущие Execute.
func (p *ConnectionPool) Unregister(conn *client.ClientConnection) {
	p.mu.Lock()
	if p.conns[conn.ClientID] != conn {
		p.mu.Unlock()
		return
	}
	delete(p.conns, conn.ClientID)
	p.mu.Unlock()
	conn.Close()
}

// SendTask отправляет задачу клиенту с id clientID и ждёт
// TaskResult по тому же stream-соединению.
func (p *ConnectionPool) SendTask(ctx context.Context, clientID string, task *pb.Task) (*pb.TaskResult, error) {
	p.mu.RLock()
	c := p.conns[clientID]
	p.mu.RUnlock()
	if c == nil {
		return nil, connection.ErrConnectionNotFound
	}
	return c.Execute(ctx, task)
}
