# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
make proto          # regenerate *.pb.go from api/**/*.proto (needs nix-shell for protoc plugins)
make proto-clean    # delete generated code
go build ./...      # build everything
go test ./...       # run tests
go test ./internal/akira-client/connection/...        # single package (the e2e tests: in-process server + real client)
go test ./internal/... -run TestName -v               # single test
go run ./cmd/akira-server                              # run server
go run ./cmd/akira-repl                                # server + stdin REPL for manual testing
go run ./cmd/akira-client -client-id <id> [-server host:port]   # run client executor
```

protoc and Go plugins come from `nix-shell` (see `shell.nix`). Proto → Go mapping is defined by the Makefile (`module=` option), not by go_package alone: `api/connection/v1/connection.proto` generates into `pkg/api/connectionpb/v1`. Never edit `*.pb.go` by hand — change the proto and run `make proto`.

Env vars (`.env` loaded via godotenv in server and repl): `LISTEN` (listen address, default `":5000"`), `LOG_LEVEL` (debug|info|warn|error), `LOG_FORMAT` (text|json). The `AKIRA_*`/`HOST_ID` vars currently in `.env` are not read by any code.

## Architecture

Server side of a reverse-command channel: clients hold long-lived bidirectional gRPC streams; the server pushes tasks for execution on the client and receives results over the same stream.

- **`api/connection/v1/connection.proto`** — the single source of truth for the wire protocol. Three RPCs: `Connect(RegisterRequest) returns (stream ServerMessage)` — one-way server→client stream; the client registers via the RPC request itself, the server answers with `RegisterResponse` (session_id + heartbeat interval) as the first stream message and then pushes `Task` (exec / read_file / write_file); `SubmitResult(TaskResult)` — unary, the client returns task results here, the server correlates them by `task_id`; `Heartbeat(Ping) returns (Pong)` — liveness check.
- **`internal/akira-server/connection/server`** — gRPC handlers. `Connect` validates registration, spawns the connection in the pool, sends the `RegisterResponse` ack as the first stream message, then runs the single stream-writer loop (drains `conn.Out()`, also selects on `conn.Done()` and `stream.Context()`). `SubmitResult` routes results to the pool by `task_id`; `Heartbeat` echoes `Pong`.
- **`internal/akira-server/connection/pool`** — the hub other server objects use. `Register`/`Unregister` manage connections keyed by `client_id` (`Unregister` skips if the map already holds a different, newer connection — reconnect race); `Disconnect(clientID)` drops a live connection server-side; `SendTask(ctx, clientID, task)` is the public API: sends a task to a connected client and blocks until the `TaskResult` (delivered via `HandleResult`), timeout (`task.timeout_ms`), or ctx cancel. `HandleResult` correlates by `task_id` against the pool-wide `pending` map; `ClientIDs()`/`Has()` for discovery. Pending waits **survive** disconnects: the client reconnects with the same `client_id` and delivers stored results, and `SendTask` keeps waiting across the reconnect.
- **`internal/akira-server/connection/client`** — `ClientConnection`: per-client state (session id, outgoing queue) with `Post`/`Out()`/`Done()`/`Close`. Purely outbound: result correlation lives in the pool.
- **`internal/akira-server/connection`** (package `connection`) — shared sentinel errors (`ErrAlreadyRegistered`, `ErrConnectionNotFound`, `ErrConnectionClosed`) and `NewID()` (random hex for session/task ids).
- **`internal/akira-client/connection`** — client-side connection logic: register (via the `Connect` request), heartbeat (interval from `RegisterResponse`, 30s default, unary `Heartbeat` calls), task receive loop, result outbox, reconnect loop reusing the same `client_id` after disconnects. `cmd/akira-client` is a thin entrypoint: flags → `connection.Run`.
- **`internal/akira-client/executor`** — task execution (exec via shell, read/write file). Runs on its own context bound only to `task.timeout_ms` — never to the stream.
- **`cmd/akira-repl`** — manual testing tool: starts the same gRPC server, then reads stdin commands (`list`, `use <client-id>`, `exec|read|write [client] ...`, `timeout <ms>`, `quit`).

Key invariants when modifying either side:

- Only one goroutine may call `stream.Send` per stream (gRPC streams don't allow concurrent sends). On the server all outgoing messages go through a channel to a single writer loop — `ClientConnection.Post` → `Out()` → the loop in `Connect`. The client stream is server→client only, so the client never sends on it.
- `pending` map in `ConnectionPool` correlates `task_id` → result channel between `SendTask` (sender side) and `HandleResult` (fed by `SubmitResult`). Pending waits survive disconnects on both sides: the client's outbox (`submitLoop` in `internal/akira-client/connection`) stores results and retries `SubmitResult` until delivered; the server keeps the pending entry across the reconnect. Results for unknown `task_id` (e.g. server-side timeout already fired) are discarded silently.
- On disconnect `Unregister` runs; a client reconnecting with the same `client_id` while the old stream is still registered gets `ErrAlreadyRegistered`.
- Task execution on the client is decoupled from the stream: each task runs in its own goroutine (`runTask` → `executor.Execute`), so a disconnect never interrupts a running task; finished results go to the outbox and are delivered via `SubmitResult` even after a reconnect (the client reconnects with the same `client_id`). `connection_test.go` in `internal/akira-client/connection` covers this (echo task, task survives disconnect + result delivered after reconnect, reconnect with same id).

## Conventions

- Comments and doc comments are written in Russian.
- Directories are lowercase, but package names may be longer than the directory (`pool` dir → package `connectionpool`, `server` dir → `connectionserver`), so imports use aliases named after the package.
- Server logging is `log/slog` (`slog.Default()` with a `component` field); the client uses stdlib `log`.
