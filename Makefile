
GO = go

PREFIX ?= /usr/local

BIN = lima-driver-proxmox
CMD = cmd/lima-driver-proxmox
PKG = pkg/driver/proxmox
all: $(BIN)

$(BIN): $(CMD) $(PKG) go.mod
	$(GO) build ./$(CMD)

.PHONY: install
install: $(BIN)
	$(INSTALL) -D -m 755 $@ $(DESTDIR)$(PREFIX)/libexec/lima/$(BIN)

.PHONY: lint
lint:
	golangci-lint run $(CMD) $(PKG)

.PHONY: clean
clean:
	$(RM) $(BIN)
