package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
	"github.com/0x524a/onvif-mcp/internal/tools"
)

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (l *lockedBuf) records(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(l.text()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("not JSON: %q", line)
		}
		out = append(out, m)
	}
	return out
}

type auditIn struct {
	safety.WriteBase
}

type auditOut struct {
	Note string `json:"note" jsonschema:"what happened"`
}

// auditServer is a server with one gated write tool, "test.move", and a
// policy whose audit trail is returned.
func auditServer(t *testing.T) (*mcp.ClientSession, *lockedBuf) {
	t.Helper()
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a": {ID: "cam-a", Endpoint: "http://192.0.2.1/onvif/device_service", Control: true},
	}})
	buf := &lockedBuf{}
	policy := safety.NewPolicy(safety.PolicyOptions{
		ControlEnabled: true, Cameras: reg, Log: slog.New(slog.NewJSONHandler(buf, nil)),
	})
	srv := New(reg, quietLog(), policy)
	h := func(context.Context, *mcp.CallToolRequest, auditIn) (*mcp.CallToolResult, mcperr.Out[auditOut], error) {
		return nil, mcperr.OK(auditOut{Note: "x"}), nil
	}
	tools.GuardedTool(srv, tools.Deps{Reg: reg, Log: quietLog(), Policy: policy}, safety.RiskWrite,
		&mcp.Tool{Name: "test.move", Description: "x"}, h, h)
	return connect(t, srv), buf
}

func TestSchemaRejectedWriteCallsAreStillAudited(t *testing.T) {
	cs, buf := auditServer(t)
	secret := "hunter2-argument-secret"
	for name, args := range map[string]any{
		"string dry_run": map[string]any{"camera": "cam-a", "dry_run": secret},
		"zero dry_run":   map[string]any{"camera": "cam-a", "dry_run": 0},
		"unknown field":  map[string]any{"camera": "cam-a", "bogus": secret},
		"missing camera": map[string]any{"dry_run": false},
		"null arguments": nil,
	} {
		before := len(buf.records(t))
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "test.move", Arguments: args})
		if err == nil && !res.IsError {
			t.Fatalf("%s: want a rejection", name)
		}
		recs := buf.records(t)
		if name == "null arguments" {
			// null is a valid empty call that the handler refuses itself;
			// either way it must leave exactly one record.
			if len(recs)-before != 1 {
				t.Errorf("%s: %d new records", name, len(recs)-before)
			}
			continue
		}
		if len(recs)-before != 1 {
			t.Fatalf("%s: %d new audit records, want 1", name, len(recs)-before)
		}
		r := recs[len(recs)-1]
		if r["level"] != "WARN" || r["tool"] != "test.move" || r["blocked"] != true ||
			r["executed"] != false || r["reason"] != "invalid_arguments" {
			t.Errorf("%s: record = %v", name, r)
		}
	}
	if strings.Contains(buf.text(), secret) {
		t.Errorf("a rejected call's arguments reached the audit trail: %s", buf.text())
	}
}

func TestAcceptedAndReadCallsAreNotAuditedAsRejected(t *testing.T) {
	cs, buf := auditServer(t)
	if res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "test.move",
		Arguments: map[string]any{"camera": "cam-a"}}); err != nil || res.IsError {
		t.Fatalf("dry run: %v %v", res, err)
	}
	if n := len(buf.records(t)); n != 1 {
		t.Fatalf("a handled call must leave exactly one record, got %d: %s", n, buf.text())
	}
	// A read tool rejected for bad arguments is not a write attempt.
	_, _ = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "camera.list",
		Arguments: map[string]any{"probe": "yes"}})
	if n := len(buf.records(t)); n != 1 {
		t.Fatalf("read tool rejections must not be audited: %s", buf.text())
	}
}
