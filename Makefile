.DEFAULT_GOAL := build

GO ?= go

.PHONY: build test vet check race fmt clean help

build:
	$(GO) build -o netscan ./cmd/netscan

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
	  'make check         Run tests, vet, and build (no network scans)' \
	  'make test          Run offline fixture-based tests' \
	  'make vet           Run Go static analysis' \
	  'make race          Run tests with the race detector' \
	  'make fmt           Format Go source files' \
	  'make clean         Remove only the built ./netscan executable'
