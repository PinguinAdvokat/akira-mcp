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

Env vars (`.env` loaded via godotenv in server and repl): `LISTEN` (listen address, default `":5000"`, read by both). `LOG_LEVEL` (debug|info|warn|error) and `LOG_FORMAT` (text|json) are read **only by akira-server**; the repl hardcodes a text handler on stderr. The `AKIRA_*`/`HOST_ID` vars currently in `.env` are not read by any code.

## Architecture

Server side of a reverse-command channel: each client holds a long-lived one-way gRPC stream (`Connect`, server→client) over which the server pushes tasks for execution on the client; the client returns results via the separate unary `SubmitResult` RPC.

- **`api/connection/v1/connection.proto`** — the single source of truth for the wire protocol. Three RPCs: `Connect(RegisterRequest) returns (stream ServerMessage)` — one-way server→client stream; the client registers via the RPC request itself, the server answers with `RegisterResponse` (session_id + heartbeat interval) as the first stream message and then pushes `Task` (exec / read_file / write_file); `SubmitResult(TaskResult)` — unary, the client returns task results here (stamped with its `client_id`), the server correlates them by `task_id` and rejects results from a non-owner client; `Heartbeat(Ping) returns (Pong)` — liveness check.
- **`internal/akira-server/connection/server`** — gRPC handlers. `NewGRPCServer(pool)` builds the gRPC server with keepalive params (half-open TCP connections die in ~80s, so a ghost registration can't block the client's reconnect with `AlreadyExists`); all entrypoints (server, repl, tests) construct the server through it. `Connect` validates registration, spawns the connection in the pool, sends the `RegisterResponse` ack as the first stream message, then runs the single stream-writer loop (selects on `conn.Out()`, `conn.Done()`, `stream.Context()`; a message taken off the queue while `Done()` is closed is failed via `pool.FailTask` instead of being sent). `SubmitResult` routes results to the pool by `task_id` and returns `PermissionDenied` for non-owner results; `Heartbeat` echoes `Pong`.
- **`internal/akira-server/connection/pool`** — the hub other server objects use. `Register`/`Unregister` manage connections keyed by `client_id` (`Unregister` skips if the map already holds a different, newer connection — reconnect race). `Disconnect(clientID)` atomically drops the currently registered connection under a single lock (no reconnect-race window) and returns whether one was dropped. `SendTask(ctx, clientID, task)` is the public API: posts the task and blocks until the `TaskResult` (delivered via `HandleResult`), the task timeout (`task.timeout_ms` → `STATUS_TIMEOUT` result with nil error), caller ctx expiry/cancel (returned as a ctx **error**, never a synthetic result), or `ErrConnectionClosed` when the task message never left the server. `pending` entries carry an owner `client_id` plus result/error channels; re-registering a `task_id` that is still pending → `ErrTaskAlreadyPending`. `HandleResult` delivers by `task_id`, rejects non-owner results with `ErrNotTaskOwner`, and discards unknown `task_id`s silently. `ClientIDs()`/`Has()` for discovery. Pending waits **survive** disconnects once the task has actually been sent: the client reconnects with the same `client_id` and delivers stored results, and `SendTask` keeps waiting across the reconnect.
- **`internal/akira-server/connection/client`** — `ClientConnection`: per-client state (session id, outgoing queue) with `Post(ctx, msg)`/`Out()`/`Done()`/`Close`. Purely outbound: result correlation lives in the pool. `Close` closes only `done` (idempotent) — the `out` channel is **never** closed, so a racing `Post` cannot panic — and returns the messages still queued so the pool can fail their waiters.
- **`internal/akira-server/connection`** (package `connection`) — shared sentinel errors (`ErrAlreadyRegistered`, `ErrConnectionNotFound`, `ErrConnectionClosed`, `ErrTaskAlreadyPending`, `ErrNotTaskOwner`) and `NewID()` (random hex for session/task ids).
- **`internal/akira-client/connection`** — client-side connection logic: register (via the `Connect` request), heartbeat (interval from `RegisterResponse`, 30s default; each call has a per-call deadline and the first failure tears down the session to force a reconnect), task receive loop, result outbox, reconnect loop reusing the same `client_id` after disconnects. The gRPC channel uses client keepalive (30s ping / 10s timeout) so silent partitions are detected in ~40s instead of the ~15-minute TCP retransmit timeout. `submitLoop` stamps results with `client_id` and **drops** results on permanent `SubmitResult` errors (e.g. `ResourceExhausted` for oversized results) instead of retrying forever — otherwise one poisoned result would wedge the whole FIFO outbox. `cmd/akira-client` is a thin entrypoint: flags → `connection.Run`.
- **`internal/akira-client/executor`** — task execution (exec via shell, read/write file). Runs on its own context bound only to `task.timeout_ms` — never to the stream.
- **`cmd/akira-repl`** — manual testing tool: starts the same gRPC server, then reads stdin commands (`list`, `use <client-id>`, `exec|read|write [client] ...`, `timeout <ms>`, `quit`).

Key invariants when modifying either side:

- Only one goroutine may call `stream.Send` per stream (gRPC streams don't allow concurrent sends). On the server all outgoing messages go through a channel to a single writer loop — `ClientConnection.Post` → `Out()` → the loop in `Connect`. The client stream is server→client only, so the client never sends on it. The `out` channel is never closed — closing it would make a concurrent `Post` panic on "send on closed channel"; termination is signalled via `done` only.
- `pending` map in `ConnectionPool` correlates `task_id` → pending entry between `SendTask` (sender side) and `HandleResult` (fed by `SubmitResult`). Waits for tasks that **reached the client** survive disconnects on both sides: the client's outbox (`submitLoop` in `internal/akira-client/connection`) stores results and retries `SubmitResult` until delivered; the server keeps the pending entry across the reconnect. Waits for tasks that **never left the server** are failed with `ErrConnectionClosed` when the connection closes (`Close` returns the unsent messages → `failUnsent`/`FailTask`). Results for unknown `task_id` (e.g. server-side timeout already fired) are discarded silently; results from a non-owner `client_id` are rejected and the wait continues.
- On disconnect `Unregister` runs; a client reconnecting with the same `client_id` while the old stream is still registered gets `ErrAlreadyRegistered`. Half-open (silently dead) old registrations are cleared by the server-side keepalive (~80s), not by heartbeats — the server never tracks heartbeat times.
- Task execution on the client is decoupled from the stream: each task runs in its own goroutine (`runTask` → `executor.Execute`), so a disconnect never interrupts a running task; finished results go to the outbox and are delivered via `SubmitResult` even after a reconnect (the client reconnects with the same `client_id`). `connection_test.go` in `internal/akira-client/connection` covers this (echo task, task survives disconnect + result delivered after reconnect, reconnect with same id); `pool_test.go` in `internal/akira-server/connection/pool` covers the failure paths (unsent task, duplicate id, timeout semantics, non-owner rejection).

## Conventions

- Comments and doc comments are written in Russian.
- Directories are lowercase, but package names may be longer than the directory (`pool` dir → package `connectionpool`, `server` dir → `connectionserver`), so imports use aliases named after the package.
- Server logging is `log/slog` (`slog.Default()` with a `component` field); the client uses stdlib `log`.
