VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test race lint snapshots demo

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o nethelp ./cmd/nethelp

test:
	go test ./...

race:
	go test -race ./...

lint:
	go vet ./...
	test -z "$$(gofmt -l .)"

# Regenerate golden report files after an intentional format change.
snapshots:
	go test ./internal/report -update

# Drive the TUI model against the real network and print frames.
demo:
	NETHELP_TUI_DEMO=1 go test ./internal/tui -run LiveDemo -v -count=1
