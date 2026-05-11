.PHONY: all build plugin verify test test-race test-plugin cover clean lint package release-dryrun

GO ?= go
PLUGIN_NAME ?= mqtt-auth.so
PLUGIN_DIR  := plugin
BIN_DIR     := bin
DIST_DIR    := dist
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)

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

verify:
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN_DIR)/mqtt-auth-verify ./cmd/verify

test:
	$(GO) test ./internal/...

test-race:
	$(GO) test -race ./internal/...

# Requires libmosquitto/mosquitto-dev installed.
test-plugin:
	$(GO) test -tags=mqttauth_plugintest ./plugin/...

cover:
	$(GO) test -coverprofile=coverage.out ./internal/...
	$(GO) tool cover -html=coverage.out -o coverage.html

e2e: plugin
	$(GO) test -tags=e2e -v ./test/e2e/...

lint:
	$(GO) vet ./internal/... ./plugin/...

clean:
	rm -rf $(BIN_DIR) $(DIST_DIR) coverage.out coverage.html

# Build a Debian package. Requires nfpm (`go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest`).
# envsubst is used to inline VERSION into the yaml because nfpm's own env
# expansion treats e.g. "0.1.0" as a versioned name only sometimes.
package: plugin verify
	@mkdir -p $(DIST_DIR)
	@command -v nfpm >/dev/null || { echo "nfpm not installed; run: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"; exit 1; }
	@command -v envsubst >/dev/null || { echo "envsubst not installed (apt install gettext-base)"; exit 1; }
	@VERSION=$(VERSION) envsubst '$$VERSION' < packaging/nfpm.yaml > $(DIST_DIR)/nfpm.rendered.yaml
	nfpm pkg --config $(DIST_DIR)/nfpm.rendered.yaml --packager deb --target $(DIST_DIR)/
	@rm $(DIST_DIR)/nfpm.rendered.yaml
	@echo
	@echo "Built:"
	@ls $(DIST_DIR)/mqtt-auth_*.deb

# Build a tarball — distro-agnostic fallback when .deb isn't an option.
tarball: plugin verify
	@mkdir -p $(DIST_DIR)
	tar -czf $(DIST_DIR)/mqtt-auth_$(VERSION)_linux_amd64.tar.gz \
		-C $(BIN_DIR) mqtt-auth.so mqtt-auth-verify \
		-C ../examples production.mosquitto.conf \
		-C ../packaging mqtt-auth.conf postinstall.sh
	@echo "Built $(DIST_DIR)/mqtt-auth_$(VERSION)_linux_amd64.tar.gz"

# Dry-run a release: show what tarball + .deb would contain without uploading.
release-dryrun: package tarball
	@echo "--- package contents ---"
	@dpkg-deb -c $(DIST_DIR)/mqtt-auth_$(VERSION)_amd64.deb | head -30
	@echo "--- tarball contents ---"
	@tar -tzf $(DIST_DIR)/mqtt-auth_$(VERSION)_linux_amd64.tar.gz
