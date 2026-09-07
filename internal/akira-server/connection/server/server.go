package connectionserver

import (
	"context"
	"log/slog"

	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/pool"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// HeartbeatIntervalMs — период вызова Heartbeat, сообщаемый клиенту
// при регистрации.
const HeartbeatIntervalMs = 30_000

// ConnectionServer реализует akira.connection.v1.ConnectionService.
type ConnectionServer struct {
	pb.UnimplementedConnectionServiceServer
	pool   *connectionpool.ConnectionPool
	logger *slog.Logger
}

func New(pool *connectionpool.ConnectionPool) *ConnectionServer {
	return &ConnectionServer{
		pool:   pool,
		logger: slog.Default().With(slog.String("component", "connectionServer")),
	}
}

// Connect регистрирует клиента (самим запросом) и открывает
// односторонний поток сервер→клиент. Первое сообщение потока —
// RegisterResponse, далее сервер присылает Task.
func (s *ConnectionServer) Connect(reg *pb.RegisterRequest, stream pb.ConnectionService_ConnectServer) error {
	if reg == nil || reg.ClientId == "" {
		s.logger.Warn("invalid register request", "client_id", reg.GetClientId())
		return status.Error(codes.InvalidArgument, "register request must have client_id")
	}

	logger := s.logger.With(slog.String("client_id", reg.ClientId))

	conn, err := s.pool.Register(reg.ClientId)
	if err != nil {
		logger.Warn("register failed", "err", err)
		return status.Error(codes.AlreadyExists, err.Error())
	}
	defer s.pool.Unregister(conn)

	// Подтверждение регистрации — первое сообщение потока.
	if err := stream.Send(&pb.ServerMessage{
		Payload: &pb.ServerMessage_RegisterAck{
			RegisterAck: &pb.RegisterResponse{
				SessionId:           conn.SessionID,
				HeartbeatIntervalMs: HeartbeatIntervalMs,
			},
		},
	}); err != nil {
		logger.Warn("failed to send register ack", "err", err)
		return err
	}

	logger.Info("client registered", "session_id", conn.SessionID)
	defer logger.Info("client disconnected", "session_id", conn.SessionID)

	// Единственный писатель stream: исходящие сообщения из conn.Out()
	// сериализуются в поток (параллельные Send в один stream запрещены).
	// Закрытие Out (Unregister/Disconnect) завершает цикл.
	for {
		select {
		case msg, ok := <-conn.Out():
			if !ok {
				return nil
			}
			if err := stream.Send(msg); err != nil {
				// Разрыв stream — завершаем handler, пул снимет подключение.
				logger.Warn("stream send failed", "err", err)
				return nil
			}
		case <-stream.Context().Done():
			return nil
		}
	}
}

// SubmitResult принимает результат исполнения задачи от клиента.
// Сервер сопоставляет результат с ожидающей задачей по task_id.
func (s *ConnectionServer) SubmitResult(ctx context.Context, res *pb.TaskResult) (*pb.SubmitResultResponse, error) {
	if res == nil || res.TaskId == "" {
		return nil, status.Error(codes.InvalidArgument, "result must have task_id")
	}
	// Результат задачи, которой никто не ждёт, отбрасывается молча —
	// нормальная ситуация после таймаута на стороне сервера.
	s.pool.HandleResult(res)
	return &pb.SubmitResultResponse{}, nil
}

// Heartbeat — проверка живости клиента: отвечает Pong с тем же seq.
func (s *ConnectionServer) Heartbeat(ctx context.Context, ping *pb.Ping) (*pb.Pong, error) {
	return &pb.Pong{Seq: ping.GetSeq()}, nil
}
