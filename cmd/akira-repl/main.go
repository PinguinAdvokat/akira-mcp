package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/pool"
	connectionserver "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/server"
	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
	authstorepostgres "github.com/PinguinAdvokat/akira-mcp/internal/auth/store/postgres"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
	"github.com/joho/godotenv"
)

// repl — ручная проверка сервера: поднимает gRPC-сервер
// (как akira-server) и читает команды из stdin.
//
// Команды:
//
//	list                       — активные подключения (connection_id)
//	use <connection-id>        — выбрать активное подключение
//	exec <conn> <cmd...>       — выполнить команду на клиенте
//	read <conn> <path>         — прочитать файл
//	write <conn> <path> <text...> — записать текст в файл
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

	// Пользователи — в общей БД с auth-сервисом: как и akira-server,
	// repl находит владельца подключения по connect_key.
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		logger.Error("DATABASE_URL is required")
		os.Exit(1)
	}
	logger.Info("connecting to postgres", "migrations", "applying at startup")
	store, err := authstorepostgres.New(context.Background(), databaseURL)
	if err != nil {
		logger.Error("postgres store init failed", "err", err)
		os.Exit(1)
	}
	defer store.Close()

	// Некорректное значение — ошибка конфигурации: молчаливый отход
	// к умолчанию скрывал бы опечатку (лимит незаметно менялся на 5).
	maxConns := 5
	if raw := os.Getenv("MAX_CONNECTIONS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			logger.Error("invalid MAX_CONNECTIONS", "value", raw, "err", err)
			os.Exit(1)
		}
		maxConns = n
	}

	pool := connectionpool.New(maxConns)

	// gRPC-сервер с keepalive (см. connectionserver.NewGRPCServer):
	// полумёртвые соединения закрываются, не блокируя переподключение.
	grpcServer := connectionserver.NewGRPCServer(pool, storeLookup{store: store})

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			logger.Error("serve failed", "err", err)
			os.Exit(1)
		}
	}()
	logger.Info("akira-repl listening", "addr", addr)

	repl(logger, pool)
}

// storeLookup адаптирует authstore.Store к узкому интерфейсу
// connectionserver.UserLookup.
type storeLookup struct {
	store authstore.Store
}

// LookupConnectKey находит пользователя по ключу подключения.
// «Пользователь не найден» транслируется в сентинель сервера
// (ErrUnknownConnectKey): Connect отвечает Unauthenticated, и клиент
// с заведомо неверным ключом завершается. Прочие ошибки хранилища
// возвращаются как есть — Connect отвечает Internal, клиент пережидает
// и пробует снова (например, при недоступной БД).
func (l storeLookup) LookupConnectKey(ctx context.Context, connectKey string) (string, bool, error) {
	user, err := l.store.GetUserByConnectKey(ctx, connectKey)
	if err != nil {
		if errors.Is(err, authstore.ErrUserNotFound) {
			return "", false, connectionserver.ErrUnknownConnectKey
		}
		return "", false, err
	}
	return user.ID, user.EmailVerified, nil
}

// defaultTimeoutMs — таймаут задач по умолчанию: без него задача
// в адрес навсегда пропавшего клиента висела бы бесконечно.
const defaultTimeoutMs = int64(60_000)

// repl — цикл чтения команд из stdin.
func repl(logger *slog.Logger, pool *connectionpool.ConnectionPool) {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)

	timeout := defaultTimeoutMs
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
				fmt.Println("usage: use <connection-id>")
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
				fmt.Println("no connection selected: run use <connection-id> or pass one as the first argument")
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
	fmt.Println("  list                          — active connections (connection_id)")
	fmt.Println("  use <connection-id>           — select the active connection")
	fmt.Println("  exec [conn] <cmd...>          — run a command")
	fmt.Println("  read [conn] <path>            — read a file")
	fmt.Println("  write [conn] <path> <text>    — write text to a file")
	fmt.Println("  timeout <ms>                  — task timeout (default 60000, 0 = no limit)")
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
