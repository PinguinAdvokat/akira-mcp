# syntax=docker/dockerfile:1
# Один Dockerfile на оба сервиса: общий этап сборки, два целевых
# (docker build --target akira-server|auth). Сгенерированный код
# (*.pb.go) закоммичен, поэтому protoc здесь не нужен — достаточно
# go build. Миграции и протофайлы зашиты в бинарник через go:embed.

# ── общий этап сборки ────────────────────────────────────────────────
FROM golang:1.26-alpine AS build
WORKDIR /src

# Сначала только go.mod/go.sum — слой с зависимостями кэшируется
# отдельно от исходников; cache-mount'ы ускоряют пересборки.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

# Сборка без cgo: статические бинарники, работают в alpine/scratch.
# Собираем оба сразу: зависимости общие, второй почти бесплатен;
# -o с несколькими main-пакетами кладёт бинарники в /out по имени
# каталога. Целевые этапы просто копируют свой бинарник — ARG
# финального этапа в предыдущие этапы не пробрасывается, поэтому
# --build-arg не нужен.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    mkdir -p /out && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
      -o /out ./cmd/akira-server ./cmd/auth

# ── akira-server: gRPC :5000 + MCP HTTP :7000 ────────────────────────
# Целевой этап по умолчанию (docker build . без --target).
FROM alpine:3.22 AS akira-server
COPY --from=build /out/akira-server /usr/local/bin/akira-server
# Непривилегированный пользователь: порты > 1024, рут не нужен.
RUN adduser -D -H -u 10001 appuser
USER appuser
EXPOSE 5000 7000
ENTRYPOINT ["akira-server"]

# ── auth: HTTP :6000 ─────────────────────────────────────────────────
FROM alpine:3.22 AS auth
COPY --from=build /out/auth /usr/local/bin/auth
RUN adduser -D -H -u 10001 appuser
USER appuser
EXPOSE 6000
ENTRYPOINT ["auth"]
