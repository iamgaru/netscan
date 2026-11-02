.DEFAULT_GOAL := build

GO ?= go
PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
INSTALL_NAME ?= netscan

.PHONY: build install test vet check race fmt clean help

build:
	$(GO) build -o netscan ./cmd/netscan

install: build
	install -d "$(BINDIR)"
	install -m 0755 ./netscan "$(BINDIR)/$(INSTALL_NAME)"
	@printf 'Installed %s\n' "$(BINDIR)/$(INSTALL_NAME)"
	@case ":$$PATH:" in \
	  *":$(BINDIR):"*) ;; \
	  *) printf 'Add this directory to your PATH: %s\n' "$(BINDIR)" ;; \
	esac

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

check: test vet build

race:
	$(GO) test -race ./...

fmt:
	$(GO) fmt ./...

clean:
	$(RM) ./netscan

help:
	@printf '%s\n' \
	  'make / make build  Build ./netscan' \
	  'make install       Build and install to ~/.local/bin (no sudo)' \
	  '                   Override PREFIX, BINDIR, or INSTALL_NAME as needed' \
	  'make check         Run tests, vet, and build (no network scans)' \
	  'make test          Run offline fixture-based tests' \
	  'make vet           Run Go static analysis' \
	  'make race          Run tests with the race detector' \
	  'make fmt           Format Go source files' \
	  'make clean         Remove only the built ./netscan executable'
