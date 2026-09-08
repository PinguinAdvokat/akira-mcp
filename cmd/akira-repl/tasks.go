package main

import (
	"context"
	"fmt"
	"strings"

	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/pool"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
)

// runTask строит Task по команде REPL и печатает результат.
func runTask(pool *connectionpool.ConnectionPool, cmd, clientID string, args []string, timeout int64) {
	var task *pb.Task
	switch cmd {
	case "exec":
		if len(args) == 0 {
			fmt.Println("usage: exec <cmd...>")
			return
		}
		task = &pb.Task{
			Payload: &pb.Task_Exec{Exec: &pb.ExecTask{
				Cmd: strings.Join(args, " "),
			}},
		}
	case "read":
		if len(args) < 1 {
			fmt.Println("usage: read <path>")
			return
		}
		task = &pb.Task{
			Payload: &pb.Task_ReadFile{ReadFile: &pb.ReadFileRequest{
				Path: args[0],
			}},
		}
	case "write":
		if len(args) < 2 {
			fmt.Println("usage: write <path> <text...>")
			return
		}
		task = &pb.Task{
			Payload: &pb.Task_WriteFile{WriteFile: &pb.WriteFileRequest{
				Path:    args[0],
				Content: []byte(strings.Join(args[1:], " ")),
			}},
		}
	}
	task.TimeoutMs = timeout

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Printf("-> %s %s\n", clientID, taskDesc(task))
	res, err := pool.SendTask(ctx, clientID, task)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	printResult(res)
}

// taskDesc — краткое человекочитаемое описание задачи.
func taskDesc(t *pb.Task) string {
	switch p := t.Payload.(type) {
	case *pb.Task_Exec:
		return "exec: " + p.Exec.Cmd
	case *pb.Task_ReadFile:
		return "read: " + p.ReadFile.Path
	case *pb.Task_WriteFile:
		return "write: " + p.WriteFile.Path
	}
	return "?"
}

// printResult печатает TaskResult.
func printResult(res *pb.TaskResult) {
	fmt.Printf("status=%s exit_code=%d duration=%dms\n", res.Status, res.ExitCode, res.DurationMs)
	if len(res.Stdout) > 0 {
		fmt.Printf("--- stdout ---\n%s\n", res.Stdout)
	}
	if len(res.Stderr) > 0 {
		fmt.Printf("--- stderr ---\n%s\n", res.Stderr)
	}
	if res.Error != "" {
		fmt.Printf("--- error ---\n%s\n", res.Error)
	}
}
