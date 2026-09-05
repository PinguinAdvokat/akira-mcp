package connection

import (
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
)

type ConnectionServer struct {
	pb.UnimplementedConnectionServiceServer
}

func (c *ConnectionServer) Connect(stream pb.ConnectionService_ConnectServer) error {
	ctx := stream.Context()

}
