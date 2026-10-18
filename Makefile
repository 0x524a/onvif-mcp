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

# demo runs the virtual camera (cmd/demo-camera) in the background and the MCP
# server on this terminal's stdio, with control enabled. Type or pipe JSON-RPC
# lines as shown in the README; end stdin (ctrl-d) to stop. The camera is its
# own process because nothing may write to the server's stdout but JSON-RPC.
# Git does not keep file modes, so the demo config is copied to a 0600 temp file.
demo:
	@set -e; d=$$(mktemp -d); \
	trap 'kill $$cam 2>/dev/null || true; rm -rf "$$d"' EXIT INT TERM; \
	go build -o "$$d/demo-camera" ./cmd/demo-camera </dev/null; \
	go build -o "$$d/onvif-mcp" ./cmd/onvif-mcp </dev/null; \
	cp testdata/demo.json "$$d/demo.json"; chmod 600 "$$d/demo.json"; \
	"$$d/demo-camera" </dev/null & cam=$$!; \
	i=0; until curl -s -o /dev/null </dev/null http://127.0.0.1:18080/onvif/device_service; do \
		i=$$((i+1)); [ $$i -lt 50 ] || { echo "virtual camera did not start" >&2; exit 1; }; sleep 0.1; done; \
	echo "onvif-mcp ready on stdio (control enabled for the demo camera); see README, Try it without a camera" >&2; \
	"$$d/onvif-mcp" -config "$$d/demo.json" -enable-control
