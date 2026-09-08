package connectionpool

import (
	"context"
	"errors"
	"time"

	"github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// pendingEntry — задача, ожидающая результат: SendTask ждёт resCh,
// HandleResult доставляет результат в resCh, а ошибки ожидания
// (задача не ушла клиенту) — в errCh. owner — connection_id, которому
// отправлена задача: по нему отбрасываются результаты чужих подключений.
type pendingEntry struct {
	resCh chan *pb.TaskResult
	errCh chan error
	owner string
}

// SendTask отправляет задачу подключению connectionID и блокируется
// до результата, таймаута задачи или отмены ctx.
//
// Потеря подключения клиента завершает ожидание ошибкой
// ErrConnectionClosed — независимо от того, ушло сообщение клиенту
// или нет: переподключение не пересылает задачи заново, и результата
// можно не ждать. Задача без таймаута (TimeoutMs == 0) при живом
// подключении и ctx без дедлайна ждёт результата неограниченно долго —
// вызывающий код должен задавать таймаут задачи или дедлайн ctx.
//
// Таймаут задачи (task.timeout_ms) возвращается как TaskResult
// со статусом STATUS_TIMEOUT и nil error; истечение дедлайна или отмена
// ctx вызывающего кода возвращаются как ошибка ctx. Повторный вызов
// с task_id, уже ожидающим результат, возвращает ErrTaskAlreadyPending.
func (p *ConnectionPool) SendTask(ctx context.Context, connectionID string, task *pb.Task) (*pb.TaskResult, error) {
	p.mu.RLock()
	c := p.conns[connectionID]
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

	e := &pendingEntry{
		resCh: make(chan *pb.TaskResult, 1),
		errCh: make(chan error, 1),
		owner: connectionID,
	}
	p.mu.Lock()
	if _, exists := p.pending[task.Id]; exists {
		p.mu.Unlock()
		return nil, connection.ErrTaskAlreadyPending
	}
	p.pending[task.Id] = e
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		// удаляем только свою запись: после таймаута под этим же id
		// может ждать следующая попытка
		if cur, ok := p.pending[task.Id]; ok && cur == e {
			delete(p.pending, task.Id)
		}
		p.mu.Unlock()
	}()

	// Таймаут задачи действует и на постановку в очередь: если очередь
	// подключения переполнена (писатель не вычитывает), Post прерывается
	// по дедлайну, а не висит вечно.
	parent := ctx
	if task.TimeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(task.TimeoutMs)*time.Millisecond)
		defer cancel()
	}

	if err := c.Post(ctx, &pb.ServerMessage{
		Payload: &pb.ServerMessage_Task{Task: task},
	}); err != nil {
		return nil, err
	}

	select {
	case res := <-e.resCh:
		return res, nil
	case err := <-e.errCh:
		return nil, err
	case <-ctx.Done():
		// STATUS_TIMEOUT — только таймаут самой задачи: родительский ctx
		// жив, значит дедлайн породил таймер задачи, а не вызывающий код.
		if errors.Is(ctx.Err(), context.DeadlineExceeded) && parent.Err() == nil {
			return &pb.TaskResult{
				TaskId: task.Id,
				Status: pb.TaskResult_STATUS_TIMEOUT,
				Error:  "task timed out",
			}, nil
		}
		return nil, ctx.Err()
	}
}

// HandleResult доставляет TaskResult (поступивший через SubmitResult)
// ждущему SendTask по task_id — в том числе после переподключения
// клиента. Владелец задачи задан connection_id, и результат обязан
// быть подписан ровно им: результат от другого подключения (включая
// результат с пустым client_id) отбрасывается с ErrNotTaskOwner —
// ожидание продолжается, владелец может доставить результат позже.
// Результат задачи, которой никто не ждёт (например, истёк таймаут),
// отбрасывается молча.
func (p *ConnectionPool) HandleResult(res *pb.TaskResult) error {
	p.mu.Lock()
	e, ok := p.pending[res.TaskId]
	if ok && res.ClientId != e.owner {
		p.mu.Unlock()
		return connection.ErrNotTaskOwner
	}
	if ok {
		delete(p.pending, res.TaskId)
	}
	p.mu.Unlock()
	if ok {
		e.resCh <- res
	}
	return nil
}

// FailTask завершает ошибкой ErrConnectionClosed ожидание задачи:
// сообщение о ней не будет отправлено клиенту (например, подключение
// закрылось, пока сообщение было в очереди на отправку).
func (p *ConnectionPool) FailTask(taskID string) {
	p.mu.Lock()
	e, ok := p.pending[taskID]
	if ok {
		delete(p.pending, taskID)
	}
	p.mu.Unlock()
	if ok {
		e.errCh <- connection.ErrConnectionClosed
	}
}

// failUnsent завершает ошибкой ErrConnectionClosed ожидание задач,
// сообщения о которых остались в очереди подключения при закрытии:
// клиент их не получил и результата не пришлёт.
func (p *ConnectionPool) failUnsent(msgs []*pb.ServerMessage) {
	for _, msg := range msgs {
		if task := msg.GetTask(); task != nil {
			p.FailTask(task.GetId())
		}
	}
}

// failPendingClient завершает ошибкой ErrConnectionClosed ожидание всех
// задач подключения connectionID — и отправленных, и оставшихся в очереди.
// Вызывается при потере подключения: клиент может не вернуться (или не
// получить часть задач из-за «полумёртвого» канала), и без этого
// задачи без таймаута ждали бы результата неограниченно долго.
func (p *ConnectionPool) failPendingClient(connectionID string) {
	p.mu.Lock()
	var entries []*pendingEntry
	for id, e := range p.pending {
		if e.owner == connectionID {
			delete(p.pending, id)
			entries = append(entries, e)
		}
	}
	p.mu.Unlock()
	for _, e := range entries {
		e.errCh <- connection.ErrConnectionClosed
	}
}
