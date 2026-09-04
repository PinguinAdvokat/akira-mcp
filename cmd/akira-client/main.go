package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	db "github.com/PinguinAdvokat/akira-mcp/pkg/api"
	"github.com/joho/godotenv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func init() {
	// loads values from .env into the system
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found")
	}
}

func main() {
	// Get the GITHUB_USERNAME environment variable
	server, exists := os.LookupEnv("AKIRA_SERVER")
	if !exists {
		log.Fatal("server env is not defind")
	}

	conn, err := grpc.NewClient(server, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	dbclient := db.NewDBServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err = dbclient.AddUser(ctx, &db.User{Id: "id", Name: "penis", Age: 13})
	if err != nil {
		log.Fatal(err)
	}

	user, err := dbclient.GetUser(ctx, &db.UserID{Id: "id"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(user)
}
