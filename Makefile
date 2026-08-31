.PHONY: all build test lint vulncheck clean

BINARY_NAME=bin/logzero

all: lint test build

build:
	@mkdir -p bin
	go build -ldflags="-s -w" -o $(BINARY_NAME) ./cmd/logzero

test:
	go test -v -race -cover ./...

fuzz:
	go test -fuzz=FuzzIngestFromReader -fuzztime=30s ./pkg/aws

lint:
	golangci-lint run ./...

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

clean:
	rm -rf bin/ coverage.out
