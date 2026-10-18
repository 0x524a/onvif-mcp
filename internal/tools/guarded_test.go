package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
	"github.com/0x524a/onvif-mcp/internal/testcam"
)

// nudgeIn is the input of the TEST-ONLY write tool. No production write tool
// exists until the PTZ phase; this exercises the helper in the meantime.
type nudgeIn struct {
	safety.WriteBase
	Amount int `json:"amount,omitempty" jsonschema:"how far to nudge"`
}

type nudgeOut struct {
	Moved bool   `json:"moved" jsonschema:"whether the camera was changed"`
	Note  string `json:"note" jsonschema:"what happened"`
}

// plainIn does not embed WriteBase, so it cannot satisfy safety.WriteInput.
type plainIn struct {
	Camera string `json:"camera"`
}

type auditBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (a *auditBuf) Write(p []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.b.Write(p)
}

func (a *auditBuf) records(t *testing.T) []map[string]any {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(a.b.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("audit line is not JSON: %q", line)
		}
		out = append(out, m)
	}
	return out
}

type guardedRig struct {
	cs     *mcp.ClientSession
	srv    *mcp.Server
	policy *safety.Policy
	audit  *auditBuf
	execs  atomic.Int32
	dries  atomic.Int32
	panics bool
}

// newRig builds a server with one write tool, "test.nudge", over a testcam
// reachable as cam-a (opted in) and cam-fixed (not opted in).
func newRig(t *testing.T, control bool, panics bool) *guardedRig {
	t.Helper()
	cam := testcam.Start(t)
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a":     {ID: "cam-a", Endpoint: cam.Endpoint(), Username: cam.Username(), Password: cam.Password(), Control: true},
		"cam-fixed": {ID: "cam-fixed", Endpoint: cam.Endpoint(), Username: cam.Username(), Password: cam.Password()},
	}})
	r := &guardedRig{audit: &auditBuf{}, panics: panics}
	r.policy = safety.NewPolicy(safety.PolicyOptions{
		ControlEnabled: control, Cameras: reg, Interval: time.Hour, Burst: 1,
		Log: slog.New(slog.NewJSONHandler(r.audit, nil)),
	})
	r.srv = mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	d := Deps{Reg: reg, Log: quietLog(), Policy: r.policy}
	GuardedTool(r.srv, d, safety.RiskWrite, &mcp.Tool{
		Name:        "test.nudge",
		Description: "test-only write tool",
		// A caller must not be able to downgrade the hints.
		Annotations: ReadOnly("Nudge"),
	}, func(_ context.Context, _ *mcp.CallToolRequest, in nudgeIn) (*mcp.CallToolResult, mcperr.Out[nudgeOut], error) {
		r.execs.Add(1)
		if r.panics {
			panic("boom password=hunter2-secret")
		}
		return nil, mcperr.OK(nudgeOut{Moved: true, Note: "moved " + in.Camera}), nil
	}, func(_ context.Context, _ *mcp.CallToolRequest, in nudgeIn) (*mcp.CallToolResult, mcperr.Out[nudgeOut], error) {
		r.dries.Add(1)
		return nil, mcperr.OK(nudgeOut{Moved: false, Note: "would move " + in.Camera}), nil
	})
	r.cs = connectTo(t, r.srv)
	return r
}

func (r *guardedRig) listed(t *testing.T) map[string]*mcp.Tool {
	t.Helper()
	res, err := r.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]*mcp.Tool{}
	for _, x := range res.Tools {
		m[x.Name] = x
	}
	return m
}

func (r *guardedRig) lastAudit(t *testing.T) map[string]any {
	t.Helper()
	recs := r.audit.records(t)
	if len(recs) == 0 {
		t.Fatal("no audit record")
	}
	return recs[len(recs)-1]
}

func TestWriteToolIsAbsentWhenControlIsOffButStillNamedByThePolicy(t *testing.T) {
	r := newRig(t, false, false)
	if _, ok := r.listed(t)["test.nudge"]; ok {
		t.Fatal("a write tool must not be registered while control is disabled")
	}
	if got := r.policy.GatedTools(); len(got) != 1 || got[0] != "test.nudge" {
		t.Errorf("the policy must still know the gated tool: %v", got)
	}
	if _, err := r.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "test.nudge",
		Arguments: map[string]any{"camera": "cam-a", "dry_run": false}}); err == nil {
		t.Error("calling an unregistered tool must fail")
	}
	if r.execs.Load() != 0 || r.dries.Load() != 0 {
		t.Error("nothing may run")
	}
}

func TestWriteToolIsListedWithForcedWriteAnnotationsWhenControlIsOn(t *testing.T) {
	r := newRig(t, true, false)
	tool, ok := r.listed(t)["test.nudge"]
	if !ok {
		t.Fatal("write tool missing with control enabled")
	}
	a := tool.Annotations
	if a == nil || a.ReadOnlyHint || a.DestructiveHint == nil || !*a.DestructiveHint ||
		a.OpenWorldHint == nil || *a.OpenWorldHint || !a.IdempotentHint {
		t.Errorf("caller-supplied read-only hints must be overridden: %+v", a)
	}
	if a.Title != "Nudge" {
		t.Errorf("title lost: %q", a.Title)
	}
}

func TestDryRunIsDefaultAndNeverCallsTheExecutingFunction(t *testing.T) {
	r := newRig(t, true, false)
	res := call(t, r.cs, "test.nudge", map[string]any{"camera": "cam-a"}) // dry_run omitted
	d := dataMap(t, res)
	if d["moved"] != false || !strings.Contains(d["note"].(string), "would move") {
		t.Errorf("data = %v", d)
	}
	if r.execs.Load() != 0 || r.dries.Load() != 1 {
		t.Fatalf("execs=%d dries=%d", r.execs.Load(), r.dries.Load())
	}
	a := r.lastAudit(t)
	if a["dry_run"] != true || a["executed"] != false || a["blocked"] != false || a["outcome"] != "dry_run" {
		t.Errorf("audit = %v", a)
	}
	// An explicit dry_run true behaves the same.
	call(t, r.cs, "test.nudge", map[string]any{"camera": "cam-a", "dry_run": true})
	if r.execs.Load() != 0 {
		t.Error("explicit dry_run true executed")
	}
}

func TestDryRunOnACameraWithoutAGrantIsBlockedToo(t *testing.T) {
	r := newRig(t, true, false)
	res := call(t, r.cs, "test.nudge", map[string]any{"camera": "cam-fixed"})
	if code, _ := errCode(t, res); code != "blocked_by_policy" {
		t.Fatalf("code = %q: %s", code, wire(t, res))
	}
	if r.execs.Load() != 0 || r.dries.Load() != 0 {
		t.Error("no function may run for a camera that did not opt in")
	}
}

func TestRealCallWithoutCameraGrantIsBlockedAndDoesNotExecute(t *testing.T) {
	r := newRig(t, true, false)
	res := call(t, r.cs, "test.nudge", map[string]any{"camera": "cam-fixed", "dry_run": false})
	if !res.IsError {
		t.Fatal("must be flagged isError")
	}
	if code, hint := errCode(t, res); code != "blocked_by_policy" || !strings.Contains(hint, "control") {
		t.Fatalf("code=%q hint=%q", code, hint)
	}
	if r.execs.Load() != 0 || r.dries.Load() != 0 {
		t.Error("neither function may run")
	}
	a := r.lastAudit(t)
	if a["blocked"] != true || a["reason"] != safety.ReasonCameraNotGranted || a["executed"] != false {
		t.Errorf("audit = %v", a)
	}
}

func TestRealCallExecutesOnceThenIsRateLimitedWithRetryAfter(t *testing.T) {
	r := newRig(t, true, false)
	d := dataMap(t, call(t, r.cs, "test.nudge", map[string]any{"camera": "cam-a", "dry_run": false}))
	if d["moved"] != true {
		t.Fatalf("data = %v", d)
	}
	if r.execs.Load() != 1 || r.dries.Load() != 0 {
		t.Fatalf("execs=%d dries=%d: a real call must not touch the dry-run function", r.execs.Load(), r.dries.Load())
	}
	a := r.lastAudit(t)
	if a["executed"] != true || a["dry_run"] != false || a["outcome"] != "ok" {
		t.Errorf("audit = %v", a)
	}

	res := call(t, r.cs, "test.nudge", map[string]any{"camera": "cam-a", "dry_run": false})
	if code, _ := errCode(t, res); code != "blocked_by_policy" {
		t.Fatalf("second call: %s", wire(t, res))
	}
	e := res.StructuredContent.(map[string]any)["error"].(map[string]any)
	if e["retryable"] != true || e["retry_after_seconds"] == nil {
		t.Errorf("rate limit must carry retry_after: %v", e)
	}
	if r.execs.Load() != 1 {
		t.Error("the rate-limited call executed")
	}
	// Dry runs consume no budget.
	call(t, r.cs, "test.nudge", map[string]any{"camera": "cam-a"})
	if r.dries.Load() != 1 {
		t.Error("dry run should still work while rate limited")
	}
}

func TestUnknownCameraIsNotFoundWithoutTouchingTheLimiter(t *testing.T) {
	r := newRig(t, true, false)
	for i := 0; i < 3; i++ {
		res := call(t, r.cs, "test.nudge", map[string]any{"camera": "no-such-cam", "dry_run": false})
		if code, _ := errCode(t, res); code != "not_found" {
			t.Fatalf("code = %q: %s", code, wire(t, res))
		}
	}
	if r.execs.Load() != 0 || r.dries.Load() != 0 {
		t.Error("nothing may run for an unknown camera")
	}
	// The burst for the real camera is untouched.
	if d := dataMap(t, call(t, r.cs, "test.nudge", map[string]any{"camera": "cam-a", "dry_run": false})); d["moved"] != true {
		t.Errorf("cam-a should still have its token: %v", d)
	}
}

func TestPanicInTheExecutingHandlerIsAuditedAndBecomesAnInternalError(t *testing.T) {
	r := newRig(t, true, true)
	res := call(t, r.cs, "test.nudge", map[string]any{"camera": "cam-a", "dry_run": false})
	if !res.IsError {
		t.Fatalf("a panic must surface as a tool error: %s", wire(t, res))
	}
	if code, _ := errCode(t, res); code != "internal" {
		t.Errorf("code = %q", code)
	}
	if strings.Contains(wire(t, res), "hunter2") {
		t.Error("the panic value must not reach the agent")
	}
	a := r.lastAudit(t)
	if a["executed"] != true || a["outcome"] != "panic" || a["blocked"] != false {
		t.Errorf("a panic must still be audited as an executed attempt: %v", a)
	}
	if strings.Contains(a["outcome"].(string), "hunter2") {
		t.Error("panic text in audit")
	}
	// The server survives.
	if _, err := r.cs.ListTools(context.Background(), nil); err != nil {
		t.Errorf("session died: %v", err)
	}
}

func TestOutputOfAGuardedToolStillPassesTheSanitisingChokePoint(t *testing.T) {
	cam := testcam.Start(t)
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a": {ID: "cam-a", Endpoint: cam.Endpoint(), Control: true},
	}})
	p := safety.NewPolicy(safety.PolicyOptions{ControlEnabled: true, Cameras: reg,
		Log: slog.New(slog.NewJSONHandler(&auditBuf{}, nil))})
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	GuardedTool(srv, Deps{Reg: reg, Log: quietLog(), Policy: p}, safety.RiskWrite, &mcp.Tool{Name: "test.dirty", Description: "x"},
		func(context.Context, *mcp.CallToolRequest, nudgeIn) (*mcp.CallToolResult, mcperr.Out[nudgeOut], error) {
			return nil, mcperr.OK(nudgeOut{}), nil
		},
		func(context.Context, *mcp.CallToolRequest, nudgeIn) (*mcp.CallToolResult, mcperr.Out[nudgeOut], error) {
			return nil, mcperr.OK(nudgeOut{Note: "a\x1b[31mb\u202ec"}), nil
		})
	res := call(t, connectTo(t, srv), "test.dirty", map[string]any{"camera": "cam-a"})
	w := wire(t, res)
	if strings.Contains(w, "\\u001b") || strings.Contains(w, "\\u202e") {
		t.Errorf("dry-run output was not sanitised: %s", w)
	}
}

func TestReadRiskToolRegistersWithoutControlWithForcedReadOnlyAnnotations(t *testing.T) {
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	p := safety.NewPolicy(safety.PolicyOptions{ControlEnabled: false})
	GuardedTool[CameraIn, nudgeOut](srv, Deps{Policy: p}, safety.RiskRead, &mcp.Tool{
		Name: "test.read", Description: "x", Annotations: safety.WriteAnnotations("Read"),
	}, func(context.Context, *mcp.CallToolRequest, CameraIn) (*mcp.CallToolResult, mcperr.Out[nudgeOut], error) {
		return nil, mcperr.OK(nudgeOut{Note: "hi"}), nil
	}, nil)
	cs := connectTo(t, srv)
	res, _ := cs.ListTools(context.Background(), nil)
	if len(res.Tools) != 1 {
		t.Fatalf("tools = %d", len(res.Tools))
	}
	a := res.Tools[0].Annotations
	if a == nil || !a.ReadOnlyHint || a.DestructiveHint == nil || *a.DestructiveHint {
		t.Errorf("read annotations must be forced: %+v", a)
	}
	if len(p.GatedTools()) != 0 {
		t.Error("a read tool is not gated")
	}
	if d := dataMap(t, call(t, cs, "test.read", map[string]any{"camera": "x"})); d["note"] != "hi" {
		t.Errorf("data = %v", d)
	}
}

func mustPanic(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s: expected a registration-time panic", name)
		}
	}()
	f()
}

func TestMisuseOfTheHelperPanicsAtRegistration(t *testing.T) {
	noop := func(context.Context, *mcp.CallToolRequest, nudgeIn) (*mcp.CallToolResult, mcperr.Out[nudgeOut], error) {
		return nil, mcperr.OK(nudgeOut{}), nil
	}
	plain := func(context.Context, *mcp.CallToolRequest, plainIn) (*mcp.CallToolResult, mcperr.Out[nudgeOut], error) {
		return nil, mcperr.OK(nudgeOut{}), nil
	}
	newSrv := func() *mcp.Server { return mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil) }
	tool := func() *mcp.Tool { return &mcp.Tool{Name: "test.x", Description: "x"} }

	on := safety.NewPolicy(safety.PolicyOptions{ControlEnabled: true})
	off := safety.NewPolicy(safety.PolicyOptions{ControlEnabled: false})

	// The WriteInput check holds even when the tool would be skipped, so a
	// mistake cannot hide until an operator enables control.
	for _, p := range []*safety.Policy{on, off, nil} {
		mustPanic(t, "write without WriteInput", func() {
			GuardedTool(newSrv(), Deps{Policy: p}, safety.RiskWrite, tool(), plain, plain)
		})
		mustPanic(t, "write without a dry-run function", func() {
			GuardedTool(newSrv(), Deps{Policy: p}, safety.RiskWrite, tool(), noop, nil)
		})
		mustPanic(t, "write without a handler", func() {
			GuardedTool[nudgeIn, nudgeOut](newSrv(), Deps{Policy: p}, safety.RiskWrite, tool(), nil, noop)
		})
		mustPanic(t, "unknown risk class", func() {
			GuardedTool(newSrv(), Deps{Policy: p}, safety.RiskClass(99), tool(), noop, nil)
		})
		mustPanic(t, "read with a dry-run function", func() {
			// The input is not a WriteInput, so only the dry-run function is wrong.
			GuardedTool(newSrv(), Deps{Policy: p}, safety.RiskRead, tool(), plain, plain)
		})
	}
}

func TestWriteToolWithNilPolicyIsNeverRegistered(t *testing.T) {
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	h := func(context.Context, *mcp.CallToolRequest, nudgeIn) (*mcp.CallToolResult, mcperr.Out[nudgeOut], error) {
		return nil, mcperr.OK(nudgeOut{}), nil
	}
	GuardedTool(srv, Deps{}, safety.RiskWrite, &mcp.Tool{Name: "test.x", Description: "x"}, h, h)
	res, _ := connectTo(t, srv).ListTools(context.Background(), nil)
	if len(res.Tools) != 0 {
		t.Error("no policy means no write tool")
	}
}

func TestSchemaForAWriteToolDocumentsDryRun(t *testing.T) {
	r := newRig(t, true, false)
	b, _ := json.Marshal(r.listed(t)["test.nudge"].InputSchema)
	if !strings.Contains(string(b), "dry_run") || !strings.Contains(string(b), "defaults to true") {
		t.Errorf("schema = %s", b)
	}
}

type nanOut struct {
	V float64 `json:"v" jsonschema:"a number"`
}

// The audit trail must say what the client was told, and for a write that was
// sent the client must be told the camera's state is unknown.
func TestNonFiniteResultIsAuditedAsDeviceFaultAndSaysTheCommandWasSent(t *testing.T) {
	audit := &auditBuf{}
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a": {ID: "cam-a", Endpoint: "http://192.0.2.1/onvif/device_service", Control: true},
	}})
	policy := safety.NewPolicy(safety.PolicyOptions{ControlEnabled: true, Cameras: reg, Interval: time.Hour,
		Log: slog.New(slog.NewJSONHandler(audit, nil))})
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	GuardedTool(srv, Deps{Reg: reg, Log: quietLog(), Policy: policy}, safety.RiskWrite,
		&mcp.Tool{Name: "test.nan", Description: "x"},
		func(context.Context, *mcp.CallToolRequest, nudgeIn) (*mcp.CallToolResult, mcperr.Out[nanOut], error) {
			return nil, mcperr.OK(nanOut{V: math.NaN()}), nil
		},
		func(context.Context, *mcp.CallToolRequest, nudgeIn) (*mcp.CallToolResult, mcperr.Out[nanOut], error) {
			return nil, mcperr.OK(nanOut{}), nil
		})
	res := call(t, connectTo(t, srv), "test.nan", map[string]any{"camera": "cam-a", "dry_run": false})
	code, hint := errCode(t, res)
	if code != "device_fault" || !strings.Contains(hint, "sent") || !strings.Contains(hint, "unknown") {
		t.Fatalf("code=%q hint=%q", code, hint)
	}
	recs := audit.records(t)
	a := recs[len(recs)-1]
	if a["outcome"] != "device_fault" || a["executed"] != true {
		t.Errorf("audit = %v", a)
	}
}

func TestDeviceFaultAfterASentWriteSaysTheStateIsUnknown(t *testing.T) {
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a": {ID: "cam-a", Endpoint: "http://192.0.2.1/onvif/device_service", Control: true},
	}})
	policy := safety.NewPolicy(safety.PolicyOptions{ControlEnabled: true, Cameras: reg, Log: quietLog()})
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	fault := func(context.Context, *mcp.CallToolRequest, nudgeIn) (*mcp.CallToolResult, mcperr.Out[nudgeOut], error) {
		return fail[nudgeOut](&mcperr.ToolError{Code: mcperr.CodeDeviceFault, Message: "soap fault", Hint: "try later"})
	}
	GuardedTool(srv, Deps{Reg: reg, Log: quietLog(), Policy: policy}, safety.RiskWrite,
		&mcp.Tool{Name: "test.fault", Description: "x"}, fault, fault)
	cs := connectTo(t, srv)

	res := call(t, cs, "test.fault", map[string]any{"camera": "cam-a", "dry_run": false})
	if _, hint := errCode(t, res); !strings.Contains(hint, "try later") || !strings.Contains(hint, "sent") || !strings.Contains(hint, "unknown") {
		t.Errorf("real call hint = %q", hint)
	}
	if !strings.Contains(wire(t, res), "unknown") {
		t.Errorf("text content lost the warning: %s", wire(t, res))
	}
	// A dry run sent nothing, so it must not claim otherwise.
	res = call(t, cs, "test.fault", map[string]any{"camera": "cam-a"})
	if _, hint := errCode(t, res); strings.Contains(hint, "sent") {
		t.Errorf("dry run hint = %q", hint)
	}
}

// The wait is in the text an agent reads, not only in structured content.
func TestRateLimitedTextCarriesTheWaitInSeconds(t *testing.T) {
	r := newPresetRig(t, true)
	args := r.args(map[string]any{"dry_run": false})
	call(t, r.cs, gotoTool, args)
	res := call(t, r.cs, gotoTool, args)
	if code, _ := errCode(t, res); code != "blocked_by_policy" {
		t.Fatalf("code = %q", code)
	}
	txt := ""
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			txt += tc.Text
		}
	}
	if !strings.Contains(txt, "retry_after_seconds=3600") {
		t.Errorf("text = %q, want the wait in seconds", txt)
	}
}
