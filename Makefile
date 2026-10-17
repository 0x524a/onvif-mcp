.PHONY: build test check lint fmt demo

build:
	go build ./...

test:
	go test -race ./...

lint:
	golangci-lint run

fmt:
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "gofmt needed"; exit 1)

check: fmt build lint test
