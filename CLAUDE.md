# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
make proto          # regenerate *.pb.go from api/**/*.proto (needs nix-shell for protoc plugins)
make proto-clean    # delete generated code
go build ./...      # build everything
go test ./...       # run tests
go test ./internal/akira-server/connectionPool/...       # single package
go test ./internal/... -run TestName -v                  # single test
go run ./cmd/akira-server   # run server (AKIRA_LISTEN, default ":5000"; .env loaded via godotenv)
```

protoc and Go plugins come from `nix-shell` (see `shell.nix`). Proto → Go mapping is defined by the Makefile (`module=` option), not by go_package alone: `api/connection/v1/connection.proto` generates into `pkg/api/connectionpb/v1`. Never edit `*.pb.go` by hand — change the proto and run `make proto`.

## Architecture

Server side of a reverse-command channel: clients hold long-lived bidirectional gRPC streams; the server pushes tasks for execution on the client and receives results over the same stream.

- **`api/connection/v1/connection.proto`** — the single source of truth for the wire protocol. Envelopes `ClientMessage`/`ServerMessage` with oneof payloads. Flow: `RegisterRequest` (must be first) → `RegisterResponse` (session_id + heartbeat), then any number of `Task` (exec / read_file / write_file) → `TaskResult` (correlated by `task_id`), plus `Ping`/`Pong` heartbeat.
- **`internal/akira-server/connectionServer`** — gRPC handler. `Connect` validates registration, spawns the single stream-writer goroutine, and runs the recv loop routing `TaskResult` → `HandleResult`, `Ping` → `Pong`.
- **`internal/akira-server/connectionPool`** — the hub other server objects use. `Register`/`Unregister` manage stream connections keyed by `client_id`; `SendTask(ctx, clientID, task)` is the public API: it sends a task to a connected client and blocks until the `TaskResult`, timeout (`task.timeout_ms`), or disconnect.
- **`cmd/akira-client`** — client executor (stub, being rewritten): connects, registers, executes tasks, sends results.

Key invariants when modifying the server:

- Only one goroutine may call `stream.Send` per stream (gRPC streams don't allow concurrent sends). All outgoing messages go through `ClientConnection.Post` → `out` channel → the writer goroutine in `Connect`.
- `pending` map in `ClientConnection` correlates `task_id` → result channel between `Execute` (sender side) and `HandleResult` (recv loop). `Unregister` must fail all pending waiters with `STATUS_ERROR`.
- On disconnect `Unregister` runs; a client reconnecting with the same `client_id` while the old stream is still registered gets `ErrAlreadyRegistered`.

## Conventions

- Comments and doc comments are written in Russian.
- Directory names are CamelCase (`connectionPool`, `connectionServer`) but package names are lowercase (`connectionpool`, `connectionserver`); import paths must match the directory case exactly, so imports use aliases.
