MODULE := github.com/PinguinAdvokat/akira-mcp

PROTO_DIR := api
GEN_DIR := pkg/api

PROTO_FILES := $(shell find $(PROTO_DIR) -name '*.proto')

# protoc и плагины берутся из окружения (в nix-окружении уже в PATH);
# при необходимости можно переопределить: make proto PROTOC=/path/to/protoc
# Пути резолвятся в абсолютные: protoc не ищет плагины в PATH,
# когда они переданы через --plugin.
PROTOC ?= $(shell command -v protoc)
PROTOC_GEN_GO ?= $(shell command -v protoc-gen-go)
PROTOC_GEN_GO_GRPC ?= $(shell command -v protoc-gen-go-grpc)

.PHONY: proto
proto: $(PROTO_FILES) ## Сгенерировать Go-код из всех .proto в $(PROTO_DIR)
	$(PROTOC) \
		-I$(PROTO_DIR) \
		--plugin=protoc-gen-go=$(PROTOC_GEN_GO) \
		--plugin=protoc-gen-go-grpc=$(PROTOC_GEN_GO_GRPC) \
		--go_out=. --go_opt=module=$(MODULE) \
		--go-grpc_out=. --go-grpc_opt=module=$(MODULE) \
		$(PROTO_FILES)
	go build ./$(GEN_DIR)/...

.PHONY: proto-clean
proto-clean: ## Удалить весь сгенерированный Go-код
	find $(GEN_DIR) -name '*.pb.go' -delete
	find $(GEN_DIR) -type d -empty -delete

.PHONY: help
help: ## Показать список целей
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
