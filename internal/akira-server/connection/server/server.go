package connectionserver

import (
	"errors"
	"io"
	"log/slog"

	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/pool"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// HeartbeatIntervalMs — период Ping, сообщаемый клиенту при регистрации.
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

func (s *ConnectionServer) Connect(stream pb.ConnectionService_ConnectServer) error {
	// Первое сообщение обязано быть RegisterRequest.
	firstMsg, err := stream.Recv()
	if err != nil {
		s.logger.Warn("failed to receive register request", "err", err)
		return err
	}
	reg := firstMsg.GetRegister()
	if reg == nil || reg.ClientId == "" {
		s.logger.Warn("invalid first message", "client_id", reg.GetClientId())
		return status.Error(codes.InvalidArgument, "first message must be RegisterRequest with client_id")
	}

	logger := s.logger.With(slog.String("client_id", reg.ClientId))

	conn, err := s.pool.Register(reg.ClientId)
	if err != nil {
		logger.Warn("register failed", "err", err)
		return status.Error(codes.AlreadyExists, err.Error())
	}
	defer s.pool.Unregister(conn)

	// Подтверждение регистрации.
	if err := conn.Post(&pb.ServerMessage{
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
	go func() {
		for msg := range conn.Out() {
			if err := stream.Send(msg); err != nil {
				// Разрыв stream — Recv ниже тоже завершится с ошибкой.
				logger.Warn("stream send failed", "err", err)
				return
			}
		}
	}()

	// Читаем входящие: результаты команд и heartbeat.
	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			logger.Warn("stream recv failed", "err", err)
			return err
		}
		switch payload := msg.Payload.(type) {
		case *pb.ClientMessage_Result:
			conn.HandleResult(payload.Result)
		case *pb.ClientMessage_Ping:
			_ = conn.Post(&pb.ServerMessage{
				Payload: &pb.ServerMessage_Pong{Pong: &pb.Pong{Seq: payload.Ping.Seq}},
			})
		case *pb.ClientMessage_Register:
			logger.Warn("duplicate register")
			return status.Error(codes.InvalidArgument, "duplicate register")
		}
	}
}
