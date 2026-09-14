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
			fmt.Println("usage: read <path> [offset] [limit]")
			return
		}
		req := &pb.ReadFileRequest{Path: args[0]}
		if len(args) > 1 {
			fmt.Sscanf(args[1], "%d", &req.Offset)
		}
		if len(args) > 2 {
			fmt.Sscanf(args[2], "%d", &req.Limit)
		}
		task = &pb.Task{
			Payload: &pb.Task_ReadFile{ReadFile: req},
		}
	case "write":
		if len(args) < 2 {
			fmt.Println("usage: write <path> <text...>")
			return
		}
		task = &pb.Task{
			Payload: &pb.Task_WriteFile{WriteFile: &pb.WriteFileRequest{
				Path:       args[0],
				Content:    []byte(strings.Join(args[1:], " ")),
				CreateDirs: true,
			}},
		}
	case "edit":
		if len(args) < 3 {
			fmt.Println("usage: edit <path> <old_str> <new_str> [all]")
			return
		}
		task = &pb.Task{
			Payload: &pb.Task_EditFile{EditFile: &pb.EditFileRequest{
				Path:       args[0],
				OldStr:     args[1],
				NewStr:     args[2],
				ReplaceAll: len(args) > 3 && args[3] == "all",
			}},
		}
	case "glob":
		if len(args) < 2 {
			fmt.Println("usage: glob <path> <pattern>")
			return
		}
		task = &pb.Task{
			Payload: &pb.Task_Glob{Glob: &pb.GlobRequest{
				Path:    args[0],
				Pattern: args[1],
			}},
		}
	case "list":
		if len(args) < 1 {
			fmt.Println("usage: list <path> [depth]")
			return
		}
		depth := int32(1)
		if len(args) > 1 {
			fmt.Sscanf(args[1], "%d", &depth)
		}
		task = &pb.Task{
			Payload: &pb.Task_List{List: &pb.ListRequest{
				Path:  args[0],
				Depth: depth,
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
		return fmt.Sprintf("read: %s (offset=%d limit=%d)", p.ReadFile.Path, p.ReadFile.Offset, p.ReadFile.Limit)
	case *pb.Task_WriteFile:
		return "write: " + p.WriteFile.Path
	case *pb.Task_EditFile:
		return "edit: " + p.EditFile.Path
	case *pb.Task_Glob:
		return "glob: " + p.Glob.Pattern
	case *pb.Task_List:
		return fmt.Sprintf("list: %s (depth=%d)", p.List.Path, p.List.Depth)
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
