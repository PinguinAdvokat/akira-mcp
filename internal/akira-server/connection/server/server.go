package connectionserver

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection"
	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/pool"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
)

// HeartbeatIntervalMs — период вызова Heartbeat, сообщаемый клиенту
// при регистрации.
const HeartbeatIntervalMs = 30_000

// ErrUnknownConnectKey — connect_key не найден: пользователя нет или
// ключ ещё не выдан. Адаптеры UserLookup транслируют сюда «пользователь
// не найден» из хранилища (сам пакет не зависит от authstore). Прочие
// ошибки поиска (например, недоступная БД) возвращаются адаптером
// как есть: Connect отвечает на них codes.Internal, и клиент
// переподключается с повторными попытками, а не выходит, как при
// Unauthenticated.
var ErrUnknownConnectKey = errors.New("connectionserver: unknown connect key")

// UserLookup — поиск пользователя по connect_key (реализация —
// authstore поверх общей БД). Узкий интерфейс, чтобы сервер не зависел
// от хранилища целиком.
type UserLookup interface {
	// LookupConnectKey возвращает id и признак подтверждённости email
	// пользователя, владеющего connect_key. Неизвестный ключ —
	// ErrUnknownConnectKey; прочие ошибки хранилища возвращаются как есть.
	LookupConnectKey(ctx context.Context, connectKey string) (userID string, verified bool, err error)
}

// ConnectionServer реализует akira.connection.v1.ConnectionService.
type ConnectionServer struct {
	pb.UnimplementedConnectionServiceServer
	pool   *connectionpool.ConnectionPool
	users  UserLookup
	logger *slog.Logger
}

func New(pool *connectionpool.ConnectionPool, users UserLookup) *ConnectionServer {
	return &ConnectionServer{
		pool:   pool,
		users:  users,
		logger: slog.Default().With(slog.String("component", "connectionServer")),
	}
}

// NewGRPCServer создаёт gRPC-сервер akira с параметрами keepalive
// и зарегистрированным ConnectionService. Сервер пингует долгоживущие
// потоки Connect: «полумёртвое» (half-open) TCP-соединение закрывается
// примерно за Time+Timeout (~80с). Без этого призрачная регистрация
// держала бы client_id до таймаута стека TCP (~15 минут) и блокировала
// переподключение клиента ошибкой AlreadyExists.
func NewGRPCServer(pool *connectionpool.ConnectionPool, users UserLookup) *grpc.Server {
	grpcServer := grpc.NewServer(grpc.KeepaliveParams(keepalive.ServerParameters{
		Time:    60 * time.Second,
		Timeout: 20 * time.Second,
	}))
	pb.RegisterConnectionServiceServer(grpcServer, New(pool, users))
	return grpcServer
}

// Connect регистрирует клиента (самим запросом) и открывает
// односторонний поток сервер→клиент. Пользователь находится по
// connect_key из запроса; подключение регистрируется в пуле под
// connection_id формата {user_id}:{client_id}, который возвращается
// клиенту в RegisterResponse и подписывает его TaskResult. Первое
// сообщение потока — RegisterResponse, далее сервер присылает Task.
func (s *ConnectionServer) Connect(reg *pb.RegisterRequest, stream pb.ConnectionService_ConnectServer) error {
	if reg == nil || reg.ClientId == "" || reg.ConnectKey == "" {
		s.logger.Warn("invalid register request", "client_id", reg.GetClientId())
		return status.Error(codes.InvalidArgument, "register request must have client_id and connect_key")
	}

	// Пользователь по connect_key: без ключа подключения нет, без
	// подтверждённого email — тоже (ключ выдаётся только верифицированным).
	userID, verified, err := s.users.LookupConnectKey(stream.Context(), reg.ConnectKey)
	if err != nil {
		if errors.Is(err, ErrUnknownConnectKey) {
			// Неизвестный ключ не станет валидным — фатальная для клиента
			// ошибка (Unauthenticated).
			s.logger.Warn("connect key lookup failed", "err", err)
			return status.Error(codes.Unauthenticated, "unknown connect key")
		}
		// Прочие ошибки (недоступная БД и т.п.) — транзиентные: Internal,
		// клиент пережидает и пробует снова. Раньше любая ошибка поиска
		// превращалась в Unauthenticated и клиент завершался.
		s.logger.Error("connect key lookup error", "err", err)
		return status.Error(codes.Internal, "connect key lookup failed")
	}
	if !verified {
		s.logger.Warn("connect key owner is not verified", "user_id", userID)
		return status.Error(codes.PermissionDenied, "email is not verified")
	}

	connectionID := userID + ":" + reg.ClientId
	logger := s.logger.With(slog.String("connection_id", connectionID))

	conn, err := s.pool.Register(connectionID, userID, connectionpool.ClientInfo{
		Hostname: reg.GetHostname(),
		Platform: reg.GetPlatform(),
	})
	if err != nil {
		logger.Warn("register failed", "err", err)
		switch {
		case errors.Is(err, connection.ErrTooManyConnections):
			return status.Error(codes.ResourceExhausted, err.Error())
		default:
			return status.Error(codes.AlreadyExists, err.Error())
		}
	}
	defer s.pool.Unregister(conn)

	// Подтверждение регистрации — первое сообщение потока.
	if err := stream.Send(&pb.ServerMessage{
		Payload: &pb.ServerMessage_RegisterAck{
			RegisterAck: &pb.RegisterResponse{
				SessionId:           conn.SessionID,
				HeartbeatIntervalMs: HeartbeatIntervalMs,
				ConnectionId:        connectionID,
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
	// цикл завершается, не отправляя сообщения из очереди; пул при этом
	// завершает ошибкой ErrConnectionClosed все задачи клиента.
	for {
		select {
		case msg := <-conn.Out():
			select {
			case <-conn.Done():
				// Подключение закрылось, пока сообщение было в очереди, —
				// не отправляем: отключённый клиент не должен получать
				// задачи. Ожидание задач завершит пул (failPendingClient).
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
	// Владелец задачи задан connection_id; пустой client_id не может
	// быть «владельческим» — иначе результат без подписи принимался бы
	// за результат владельца.
	if res.ClientId == "" {
		return nil, status.Error(codes.InvalidArgument, "result must have client_id (connection_id from the register ack)")
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
