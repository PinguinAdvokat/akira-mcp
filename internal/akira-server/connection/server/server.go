package connectionserver

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/pool"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
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

// NewGRPCServer создаёт gRPC-сервер akira с параметрами keepalive
// и зарегистрированным ConnectionService. Сервер пингует долгоживущие
// потоки Connect: «полумёртвое» (half-open) TCP-соединение закрывается
// примерно за Time+Timeout (~80с). Без этого призрачная регистрация
// держала бы client_id до таймаута стека TCP (~15 минут) и блокировала
// переподключение клиента ошибкой AlreadyExists.
func NewGRPCServer(pool *connectionpool.ConnectionPool) *grpc.Server {
	grpcServer := grpc.NewServer(grpc.KeepaliveParams(keepalive.ServerParameters{
		Time:    60 * time.Second,
		Timeout: 20 * time.Second,
	}))
	pb.RegisterConnectionServiceServer(grpcServer, New(pool))
	return grpcServer
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
	// Закрытие подключения (Unregister/Disconnect) закрывает Done() —
	// цикл завершается, не отправляя сообщения из очереди: их ожидание
	// пул завершает ошибкой ErrConnectionClosed.
	for {
		select {
		case msg := <-conn.Out():
			select {
			case <-conn.Done():
				// Подключение закрылось, пока сообщение было в очереди, —
				// не отправляем: отключённый клиент не должен получать
				// задачи. Ожидание задачи завершаем ошибкой.
				if task := msg.GetTask(); task != nil {
					s.pool.FailTask(task.GetId())
				}
				return nil
			default:
			}
			if err := stream.Send(msg); err != nil {
				// Разрыв stream — завершаем handler, пул снимет подключение
				// и завершит ожидание недоставленных задач.
				logger.Warn("stream send failed", "err", err)
				return nil
			}
		case <-conn.Done():
			return nil
		case <-stream.Context().Done():
			return nil
		}
	}
}

// SubmitResult принимает результат исполнения задачи от клиента.
// Сервер сопоставляет результат с ожидающей задачей по task_id;
// результат от клиента, не являющегося владельцем задачи, отклоняется.
func (s *ConnectionServer) SubmitResult(ctx context.Context, res *pb.TaskResult) (*pb.SubmitResultResponse, error) {
	if res == nil || res.TaskId == "" {
		return nil, status.Error(codes.InvalidArgument, "result must have task_id")
	}
	// Результат задачи, которой никто не ждёт, отбрасывается молча —
	// нормальная ситуация после таймаута на стороне сервера.
	if err := s.pool.HandleResult(res); err != nil {
		s.logger.Warn("result rejected", "task_id", res.TaskId, "client_id", res.ClientId, "err", err)
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	return &pb.SubmitResultResponse{}, nil
}

// Heartbeat — проверка живости клиента: отвечает Pong с тем же seq.
func (s *ConnectionServer) Heartbeat(ctx context.Context, ping *pb.Ping) (*pb.Pong, error) {
	return &pb.Pong{Seq: ping.GetSeq()}, nil
}
