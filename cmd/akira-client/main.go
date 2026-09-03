package main

import (
	"log"
	"os"

	"github.com/joho/godotenv"
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

	key, exists := os.LookupEnv("AKIRA_KEY")
	if !exists {
		log.Fatal("key env is not defind")
	}

	id, exists := os.LookupEnv("HOST_ID")
	if !exists {
		log.Fatal("host id env is not defind")
	}

}
