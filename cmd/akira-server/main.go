package main

import (
	"context"
	"fmt"
	"log"
	"net"

	db "github.com/PinguinAdvokat/akira-mcp/pkg/api"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type server struct {
	db.UnimplementedDBServiceServer
}

func NewServer() *server {
	return &server{}
}

func (s *server) AddUser(_ context.Context, req *db.User) (*emptypb.Empty, error) {
	fmt.Println("add user ", req.Name)
	return &emptypb.Empty{}, nil
}

func (s *server) GetUser(_ context.Context, req *db.UserID) (*db.User, error) {
	return &db.User{Id: req.Id, Age: 5, Name: "fds"}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":5000")
	if err != nil {
		log.Fatal(err)
	}

	s := grpc.NewServer()
	db.RegisterDBServiceServer(s, NewServer())

	log.Print("started at: :5000")
	if err := s.Serve(lis); err != nil {
		log.Fatal(err)
	}
}
