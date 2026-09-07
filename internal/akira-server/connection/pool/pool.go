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

// ConnectionPool хранит активные подключения клиентов по client_id
// и реестр задач, ожидающих результат, по task_id. Через SendTask
// любые объекты сервера могут отправлять задачи на исполнение клиенту;
// результаты приходят через SubmitResult и маршрутизируются по task_id.
// Ожидание результата переживает разрыв соединения: клиент
// переподключается с тем же client_id и доставляет результат.
type ConnectionPool struct {
	mu      sync.RWMutex
	conns   map[string]*client.ClientConnection
	pending map[string]chan *pb.TaskResult
}

func New() *ConnectionPool {
	return &ConnectionPool{
		conns:   make(map[string]*client.ClientConnection),
		pending: make(map[string]chan *pb.TaskResult),
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

// Unregister убирает подключение из пула. Ожидающие результаты задачи
// не прерываются: клиент переподключится с тем же client_id и доставит
// результаты через SubmitResult. Если в пуле уже другое, более новое
// подключение — пропускает (гонка переподключения).
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

// Disconnect разрывает текущее подключение клиента: подключение
// убирается из пула, поток Connect завершается, клиент переподключится.
// Ожидающие результаты задачи не прерываются. Возвращает false,
// если клиент не подключен.
func (p *ConnectionPool) Disconnect(clientID string) bool {
	p.mu.RLock()
	c := p.conns[clientID]
	p.mu.RUnlock()
	if c == nil {
		return false
	}
	p.Unregister(c)
	return true
}

// HandleResult доставляет TaskResult (поступивший через SubmitResult)
// ждущему SendTask по task_id — в том числе после переподключения
// клиента. Результат задачи, которой никто не ждёт (например, истёк
// таймаут), молча отбрасывается.
func (p *ConnectionPool) HandleResult(res *pb.TaskResult) {
	p.mu.Lock()
	ch, ok := p.pending[res.TaskId]
	if ok {
		delete(p.pending, res.TaskId)
	}
	p.mu.Unlock()
	if ok {
		ch <- res
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
// до результата, таймаута задачи или отмены ctx. Разрыв соединения
// не прерывает ожидание: клиент переподключится и доставит результат.
// Если сообщение о задаче не успело уйти до разрыва, ожидание
// завершится по таймауту или отмене ctx.
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
	p.pending[task.Id] = ch
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
