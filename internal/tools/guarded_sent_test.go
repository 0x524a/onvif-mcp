package tools

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
)

// sentRig registers a write tool whose executing function returns te, so the
// guard's treatment of a failure after a real write can be checked per code.
func sentRig(t *testing.T, te *mcperr.ToolError, note string) (*mcp.ClientSession, *auditBuf) {
	t.Helper()
	audit := &auditBuf{}
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a": {ID: "cam-a", Endpoint: "http://192.0.2.1/onvif/device_service", Control: true},
	}})
	policy := safety.NewPolicy(safety.PolicyOptions{ControlEnabled: true, Cameras: reg, Interval: time.Hour,
		Log: slog.New(slog.NewJSONHandler(audit, nil))})
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	GuardedTool(srv, Deps{Reg: reg, Log: quietLog(), Policy: policy}, safety.RiskWrite,
		&mcp.Tool{Name: "test.sent", Description: "x"},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ nudgeIn) (*mcp.CallToolResult, mcperr.Out[nudgeOut], error) {
			safety.NoteTarget(ctx, note)
			e := *te
			return fail[nudgeOut](&e)
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ nudgeIn) (*mcp.CallToolResult, mcperr.Out[nudgeOut], error) {
			safety.NoteTarget(ctx, note)
			return nil, mcperr.OK(nudgeOut{Note: "dry"}), nil
		})
	return connectTo(t, srv), audit
}

func errField(res *mcp.CallToolResult, key string) any {
	m, _ := res.StructuredContent.(map[string]any)
	e, _ := m["error"].(map[string]any)
	return e[key]
}

// A timeout or transport error after a real write is an unknown outcome: the
// camera may have moved. It must say so and must not invite a blind retry.
func TestTimeoutOrTransportErrorAfterASentWriteIsUnknownStateAndNotRetryable(t *testing.T) {
	for _, code := range []mcperr.Code{mcperr.CodeTimeout, mcperr.CodeUnreachable, mcperr.CodeDeviceFault} {
		cs, _ := sentRig(t, &mcperr.ToolError{Code: code, Retryable: code.Retryable(), Message: "m", Hint: "h"}, "p1")
		res := call(t, cs, "test.sent", map[string]any{"camera": "cam-a", "dry_run": false})
		_, hint := errCode(t, res)
		if !strings.Contains(hint, "may or may not") || !strings.Contains(hint, "unknown") {
			t.Errorf("%s: hint = %q, want the unknown-state warning", code, hint)
		}
		if errField(res, "retryable") != false {
			t.Errorf("%s: retryable = %v, must be false after a sent write", code, errField(res, "retryable"))
		}
		// The warning is stated once, not repeated by two layers.
		if strings.Count(hint, "may or may not") != 1 {
			t.Errorf("%s: warning repeated: %q", code, hint)
		}
	}
}

// A failure the tool marks as happening before anything was sent keeps its
// honest, retryable form.
func TestFailureBeforeTheWriteWasSentKeepsItsRetryableHint(t *testing.T) {
	cs, _ := sentRig(t, &mcperr.ToolError{Code: mcperr.CodeTimeout, Retryable: true, Message: "m", Hint: "retry me", NotSent: true}, "p1")
	res := call(t, cs, "test.sent", map[string]any{"camera": "cam-a", "dry_run": false})
	_, hint := errCode(t, res)
	if hint != "retry me" || errField(res, "retryable") != true {
		t.Errorf("hint=%q retryable=%v", hint, errField(res, "retryable"))
	}
}

func TestAuditCarriesTheNotedTargetForDryAndRealRuns(t *testing.T) {
	cs, audit := sentRig(t, &mcperr.ToolError{Code: mcperr.CodeNotFound, Message: "m"}, "preset-7")
	call(t, cs, "test.sent", map[string]any{"camera": "cam-a"})
	call(t, cs, "test.sent", map[string]any{"camera": "cam-a", "dry_run": false})
	recs := audit.records(t)
	if len(recs) != 2 {
		t.Fatalf("records = %v", recs)
	}
	for i, r := range recs {
		if r["target"] != "preset-7" {
			t.Errorf("record %d target = %v", i, r["target"])
		}
	}
}

func TestAuditTargetIsScrubbedAndBounded(t *testing.T) {
	cs, audit := sentRig(t, &mcperr.ToolError{Code: mcperr.CodeNotFound, Message: "m"},
		"http://user:hunter2pw@host/"+strings.Repeat("x", 500))
	call(t, cs, "test.sent", map[string]any{"camera": "cam-a"})
	a := audit.records(t)[0]
	tg, _ := a["target"].(string)
	if strings.Contains(tg, "hunter2pw") || len(tg) > 64 {
		t.Errorf("target = %q", tg)
	}
}

func TestNoteTargetWithoutASlotIsHarmless(*testing.T) {
	safety.NoteTarget(context.Background(), "x") // must not panic
}
