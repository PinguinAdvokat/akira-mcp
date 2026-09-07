package client

import (
	"github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
)

// ClientConnection — одно активное подключение клиента: идентификаторы
// и очередь исходящих сообщений для одностороннего потока Connect.
// Корреляция результатов с задачами живёт в пуле (см. connectionpool):
// результаты приходят отдельным методом SubmitResult и маршрутизируются
// по task_id, а не по этому подключению. Закрытие подключения (Close)
// не прерывает ожидающие задачи — их результаты будут доставлены после
// переподключения клиента.
type ClientConnection struct {
	ClientID  string
	SessionID string

	out  chan *pb.ServerMessage
	done chan struct{}
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
// и пишет в gRPC stream (единственный писатель). При закрытии
// подключения канал закрывается.
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

func (c *ClientConnection) Close() {
	close(c.done)
	close(c.out)
}
