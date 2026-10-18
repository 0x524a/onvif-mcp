.PHONY: build test check lint fmt demo hardware release-check release-dry-run

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

# hardware runs the opt-in real-camera tier (build tag "hardware"). It is not
# part of check and CI never runs it. ONVIF_MCP_HW_CONFIG must name a mode-0600
# config you keep outside the repository (see testdata/hardware.example.json).
# The gated move runs only when ONVIF_MCP_HW_MOVE is also set; see README.
hardware:
	@test -n "$$ONVIF_MCP_HW_CONFIG" || { echo "set ONVIF_MCP_HW_CONFIG to a mode-0600 config file"; exit 2; }
	go test -tags hardware -race -count=1 -run TestHardware -v ./internal/mcpserver/

# release-check runs the full gate, extracts the CHANGELOG notes for VERSION and
# cross-builds the archives and SHA256SUMS into dist/ (do not commit dist/).
#   make release-check VERSION=v0.1.0
release-check:
	@test -n "$(VERSION)" || { echo "usage: make release-check VERSION=vX.Y.Z"; exit 2; }
	test -z "$$(gofmt -l .)"
	go vet ./...
	golangci-lint run
	go test -race -count=1 ./...
	scripts/release-notes.sh "$(VERSION)" > /dev/null
	scripts/build-release.sh "$(VERSION)" dist
	cd dist && sha256sum -c SHA256SUMS
	@echo "release-check OK for $(VERSION); notes preview: scripts/release-notes.sh $(VERSION)"

# release-dry-run is release-check plus a look at what the workflow would
# publish: the notes, the file list, and the version the linux binary reports.
release-dry-run: release-check
	@echo "--- release notes ($(VERSION)) ---"; scripts/release-notes.sh "$(VERSION)"
	@echo "--- assets ---"; ls -l dist
	@case "$(VERSION)" in *-*) echo "would mark as pre-release";; *) echo "would publish as a full release";; esac
	@m=$$(uname -m); case $$m in x86_64) a=amd64;; aarch64|arm64) a=arm64;; *) a=;; esac; \
	o=$$(uname -s | tr A-Z a-z); \
	if [ -n "$$a" ] && [ -f "dist/onvif-mcp_$(VERSION)_$${o}_$$a.tar.gz" ]; then \
		d=$$(mktemp -d); tar -xzf "dist/onvif-mcp_$(VERSION)_$${o}_$$a.tar.gz" -C "$$d"; \
		echo "host binary reports: $$("$$d/onvif-mcp_$(VERSION)_$${o}_$$a/onvif-mcp" -version)"; rm -rf "$$d"; fi
