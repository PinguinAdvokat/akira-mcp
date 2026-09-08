package main

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/pool"
)

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
