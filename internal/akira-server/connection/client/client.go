package client

import (
	"context"
	"sync"

	"github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
)

// ClientConnection — одно активное подключение клиента: идентификаторы
// и очередь исходящих сообщений для одностороннего потока Connect.
// Корреляция результатов с задачами живёт в пуле (см. connectionpool):
// результаты приходят отдельным методом SubmitResult и маршрутизируются
// по task_id, а не по этому подключению. При закрытии подключения (Close)
// пул завершает ошибкой все задачи клиента (см. failPendingClient).
type ClientConnection struct {
	ClientID  string
	SessionID string

	out  chan *pb.ServerMessage
	done chan struct{}

	closeOnce sync.Once
}

func New(clientID string) *ClientConnection {
	return &ClientConnection{
		ClientID:  clientID,
		SessionID: connection.NewID(),
		out:       make(chan *pb.ServerMessage, 16),
		done:      make(chan struct{}),
	}
}

// Out — канал исходящих сообщений; сервер вычитывает их
// и пишет в gRPC stream (единственный писатель). Канал никогда
// не закрывается: закрытие подключения сигнализируется через Done(),
// поэтому конкурентный Post не может запаниковать на закрытом канале.
func (c *ClientConnection) Out() <-chan *pb.ServerMessage { return c.out }

// Done закрывается при Close; писатель потока завершает работу по нему.
func (c *ClientConnection) Done() <-chan struct{} { return c.done }

// Post ставит сообщение в очередь на отправку клиенту. Учитывает ctx:
// если очередь переполнена и писатель не вычитывает, Post прерывается
// по отмене ctx, а не висит вечно.
func (c *ClientConnection) Post(ctx context.Context, msg *pb.ServerMessage) error {
	select {
	case c.out <- msg:
		return nil
	case <-c.done:
		return connection.ErrConnectionClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close закрывает подключение (идемпотентно) и возвращает сообщения,
// оставшиеся в очереди: клиент их не получит, и пул завершает по ним
// ожидание ошибкой. Канал out не закрывается — сообщения, которые писатель
// уже забрал из очереди, могли дойти до клиента, но при потере
// подключения пул всё равно завершает ожидание всех задач клиента:
// результата можно не ждать.
func (c *ClientConnection) Close() []*pb.ServerMessage {
	c.closeOnce.Do(func() { close(c.done) })
	var unsent []*pb.ServerMessage
	for {
		select {
		case msg := <-c.out:
			unsent = append(unsent, msg)
		default:
			return unsent
		}
	}
}
