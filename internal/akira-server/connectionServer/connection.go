package connectionserver

import (
	"io"

	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connectionPool"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// HeartbeatIntervalMs — период Ping, сообщаемый клиенту при регистрации.
const HeartbeatIntervalMs = 30_000

// ConnectionServer реализует akira.connection.v1.ConnectionService.
type ConnectionServer struct {
	pb.UnimplementedConnectionServiceServer
	pool *connectionpool.ConnectionPool
}

func New(pool *connectionpool.ConnectionPool) *ConnectionServer {
	return &ConnectionServer{pool: pool}
}

func (s *ConnectionServer) Connect(stream pb.ConnectionService_ConnectServer) error {
	// Первое сообщение обязано быть RegisterRequest.
	firstMsg, err := stream.Recv()
	if err != nil {
		return err
	}
	reg := firstMsg.GetRegister()
	if reg == nil || reg.ClientId == "" {
		return status.Error(codes.InvalidArgument, "first message must be RegisterRequest with client_id")
	}

	conn, err := s.pool.Register(reg.ClientId)
	if err != nil {
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
		return err
	}

	// Единственный писатель stream: исходящие сообщения из conn.Out()
	// сериализуются в поток (параллельные Send в один stream запрещены).
	go func() {
		for msg := range conn.Out() {
			if err := stream.Send(msg); err != nil {
				// Разрыв stream — Recv ниже тоже завершится с ошибкой.
				return
			}
		}
	}()

	// Читаем входящие: результаты команд и heartbeat.
	for {
		msg, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
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
			return status.Error(codes.InvalidArgument, "duplicate register")
		}
	}
}
