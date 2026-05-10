.PHONY: all build plugin test test-race cover clean lint

GO ?= go
PLUGIN_NAME ?= mqtt-auth.so
PLUGIN_DIR  := plugin
BIN_DIR     := bin

CFLAGS  ?= -fPIC
LDFLAGS ?= -shared

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	LDFLAGS += -undefined dynamic_lookup
endif

all: test build

build: plugin

plugin:
	@mkdir -p $(BIN_DIR)
	CGO_CFLAGS="$(CFLAGS)" CGO_LDFLAGS="$(LDFLAGS)" \
		$(GO) build -buildmode=c-shared -o $(BIN_DIR)/$(PLUGIN_NAME) ./$(PLUGIN_DIR)

verify-cli:
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN_DIR)/mqtt-auth-verify ./cmd/verify

test:
	$(GO) test ./internal/...

test-race:
	$(GO) test -race ./internal/...

cover:
	$(GO) test -coverprofile=coverage.out ./internal/...
	$(GO) tool cover -html=coverage.out -o coverage.html

lint:
	$(GO) vet ./...

clean:
	rm -rf $(BIN_DIR) coverage.out coverage.html
