package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	"google.golang.org/grpc"

	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/pool"
	connectionserver "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/server"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
	"github.com/joho/godotenv"
)

// repl — ручная проверка сервера: поднимает gRPC-сервер
// (как akira-server) и читает команды из stdin.
//
// Команды:
//
//	list                       — подключённые клиенты
//	exec <client> <cmd...>     — выполнить команду на клиенте
//	read <client> <path>       — прочитать файл
//	write <client> <path> <text...> — записать текст в файл
//	timeout <ms>               — таймаут задач для последующих команд
//	help                       — список команд
//	quit                       — выход
func main() {
	_ = godotenv.Load()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	addr := os.Getenv("LISTEN")
	if addr == "" {
		addr = ":5000"
	}

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("listen failed", "addr", addr, "err", err)
		os.Exit(1)
	}

	pool := connectionpool.New()

	grpcServer := grpc.NewServer()
	pb.RegisterConnectionServiceServer(grpcServer, connectionserver.New(pool))

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			logger.Error("serve failed", "err", err)
			os.Exit(1)
		}
	}()
	logger.Info("akira-repl listening", "addr", addr)

	repl(logger, pool)
}

// repl — цикл чтения команд из stdin.
func repl(logger *slog.Logger, pool *connectionpool.ConnectionPool) {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)

	timeout := int64(0)
	clientID := ""

	for {
		prompt(pool, clientID, timeout)
		if !sc.Scan() {
			fmt.Println()
			return
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		cmd := fields[0]
		args := fields[1:]

		switch cmd {
		case "quit", "exit":
			return
		case "help":
			usage()
		case "list":
			listClients(pool)
		case "use":
			if len(args) != 1 {
				fmt.Println("usage: use <client-id>")
				continue
			}
			clientID = args[0]
		case "timeout":
			if len(args) != 1 {
				fmt.Println("usage: timeout <ms>")
				continue
			}
			ms, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil || ms < 0 {
				fmt.Println("timeout must be a non-negative number (ms)")
				continue
			}
			timeout = ms
		case "exec", "read", "write":
			// Первым аргументом может идти client-id, иначе — активный.
			id := clientID
			var rest []string
			if len(args) > 0 && pool.Has(args[0]) {
				id = args[0]
				rest = args[1:]
			} else {
				rest = args
			}
			if id == "" {
				fmt.Println("no client selected: run use <client-id> or pass one as the first argument")
				continue
			}
			runTask(pool, cmd, id, rest, timeout)
		default:
			fmt.Printf("unknown command: %s\n", cmd)
			usage()
		}
	}
}

// prompt печатает строку приглашения: список подключённых клиентов
// и активный клиент с таймаутом, если заданы.
func prompt(pool *connectionpool.ConnectionPool, clientID string, timeout int64) {
	ids := pool.ClientIDs()
	connected := "-"
	if len(ids) > 0 {
		connected = strings.Join(ids, ",")
	}
	if clientID == "" {
		fmt.Printf("[%s] > ", connected)
		return
	}
	if timeout > 0 {
		fmt.Printf("[%s] (%s, t=%dms) > ", connected, clientID, timeout)
	} else {
		fmt.Printf("[%s] (%s) > ", connected, clientID)
	}
}

// usage печатает список команд.
func usage() {
	fmt.Println("commands:")
	fmt.Println("  list                          — connected clients")
	fmt.Println("  use <client-id>               — select the active client")
	fmt.Println("  exec [client] <cmd...>        — run a command")
	fmt.Println("  read [client] <path>          — read a file")
	fmt.Println("  write [client] <path> <text>  — write text to a file")
	fmt.Println("  timeout <ms>                  — task timeout (0 = no limit)")
	fmt.Println("  help | quit")
}

// listClients печатает подключённых клиентов.
func listClients(pool *connectionpool.ConnectionPool) {
	ids := pool.ClientIDs()
	if len(ids) == 0 {
		fmt.Println("no connected clients")
		return
	}
	for _, id := range ids {
		fmt.Println(id)
	}
}

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
