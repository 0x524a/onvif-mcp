package tools

import (
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
)

// haltIn is the input of the TEST-ONLY halt tool.
type haltIn struct {
	Camera string `json:"camera"`
}

func (h haltIn) CameraID() string { return h.Camera }

type haltOut struct {
	Ran bool `json:"ran"`
}

type haltRig struct {
	cs       *mcp.ClientSession
	srv      *mcp.Server
	policy   *safety.Policy
	audit    *auditBuf
	d        Deps
	runs     atomic.Int32
	sawCtxOK atomic.Bool
}

func newHaltRig(base context.Context, t *testing.T, control, withLog bool) *haltRig {
	t.Helper()
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a":     {ID: "cam-a", Endpoint: "http://192.0.2.1/onvif/device_service", Control: true},
		"cam-fixed": {ID: "cam-fixed", Endpoint: "http://192.0.2.3/onvif/device_service"},
	}})
	r := &haltRig{audit: &auditBuf{}}
	opts := safety.PolicyOptions{ControlEnabled: control, Cameras: reg, Interval: time.Hour, Burst: 1}
	if withLog {
		opts.Log = slog.New(slog.NewJSONHandler(r.audit, nil))
	}
	r.policy = safety.NewPolicy(opts)
	r.srv = mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	r.d = Deps{Reg: reg, Log: quietLog(), Policy: r.policy, Base: base}
	GuardedTool(r.srv, r.d, safety.RiskHalt, &mcp.Tool{
		Name: "test.halt", Description: "test-only halt tool",
		Annotations: safety.WriteAnnotations("Halt"), // must be replaced
	}, r.run, nil)
	r.cs = connectTo(t, r.srv)
	return r
}

func (r *haltRig) run(ctx context.Context, _ *mcp.CallToolRequest, in haltIn) (*mcp.CallToolResult, mcperr.Out[haltOut], error) {
	r.runs.Add(1)
	r.sawCtxOK.Store(ctx.Err() == nil)
	return text("halted " + in.Camera), mcperr.OK(haltOut{Ran: true}), nil
}

func TestHaltToolRegistrationRejectsAnInputWithADryRunField(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("RiskHalt with an input embedding safety.WriteBase must panic at registration")
		}
	}()
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	GuardedTool(srv, Deps{Policy: &safety.Policy{}}, safety.RiskHalt, &mcp.Tool{Name: "bad.halt", Description: "x"},
		func(context.Context, *mcp.CallToolRequest, nudgeIn) (*mcp.CallToolResult, mcperr.Out[nudgeOut], error) {
			return nil, mcperr.OK(nudgeOut{}), nil
		}, nil)
}

func TestHaltToolRegistrationRejectsAnInputWithoutACameraID(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("RiskHalt whose input has no CameraID must panic")
		}
	}()
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	GuardedTool(srv, Deps{Policy: &safety.Policy{}}, safety.RiskHalt, &mcp.Tool{Name: "bad.halt", Description: "x"},
		func(context.Context, *mcp.CallToolRequest, plainIn) (*mcp.CallToolResult, mcperr.Out[nudgeOut], error) {
			return nil, mcperr.OK(nudgeOut{}), nil
		}, nil)
}

func TestHaltToolRegistrationRejectsADryRunFunction(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("RiskHalt with a dry-run function must panic")
		}
	}()
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	h := func(context.Context, *mcp.CallToolRequest, haltIn) (*mcp.CallToolResult, mcperr.Out[haltOut], error) {
		return nil, mcperr.OK(haltOut{}), nil
	}
	GuardedTool(srv, Deps{Policy: &safety.Policy{}}, safety.RiskHalt, &mcp.Tool{Name: "bad.halt", Description: "x"}, h, h)
}

func TestNonIdempotentIsRefusedOutsideRiskWrite(t *testing.T) {
	for _, risk := range []safety.RiskClass{safety.RiskRead, safety.RiskHalt} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("NonIdempotent on risk %s must panic", risk)
				}
			}()
			srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
			h := func(context.Context, *mcp.CallToolRequest, haltIn) (*mcp.CallToolResult, mcperr.Out[haltOut], error) {
				return nil, mcperr.OK(haltOut{}), nil
			}
			GuardedTool(srv, Deps{Policy: &safety.Policy{}}, risk, &mcp.Tool{Name: "x", Description: "x"}, h, nil, NonIdempotent())
		}()
	}
}

func TestNonIdempotentWriteToolListsIdempotentFalseAndStaysDestructive(t *testing.T) {
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a": {ID: "cam-a", Endpoint: "http://192.0.2.1/x", Control: true},
	}})
	p := safety.NewPolicy(safety.PolicyOptions{ControlEnabled: true, Cameras: reg, Log: quietLog()})
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	d := Deps{Reg: reg, Log: quietLog(), Policy: p}
	h := func(context.Context, *mcp.CallToolRequest, nudgeIn) (*mcp.CallToolResult, mcperr.Out[nudgeOut], error) {
		return nil, mcperr.OK(nudgeOut{}), nil
	}
	GuardedTool(srv, d, safety.RiskWrite, &mcp.Tool{Name: "t.rel", Description: "x"}, h, h, NonIdempotent())
	GuardedTool(srv, d, safety.RiskWrite, &mcp.Tool{Name: "t.plain", Description: "x"}, h, h)
	cs := connectTo(t, srv)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*mcp.ToolAnnotations{}
	for _, x := range res.Tools {
		got[x.Name] = x.Annotations
	}
	if a := got["t.rel"]; a == nil || a.IdempotentHint || a.DestructiveHint == nil || !*a.DestructiveHint || a.ReadOnlyHint {
		t.Errorf("non-idempotent write annotations = %+v", a)
	}
	if a := got["t.plain"]; a == nil || !a.IdempotentHint {
		t.Errorf("default write annotations must stay idempotent: %+v", a)
	}
}

func TestGotoPresetAnnotationsAreUnchanged(t *testing.T) {
	r := newPresetRig(t, true)
	res, err := r.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range res.Tools {
		if x.Name == gotoTool {
			a := x.Annotations
			if a == nil || !a.IdempotentHint || a.DestructiveHint == nil || !*a.DestructiveHint || a.ReadOnlyHint {
				t.Errorf("goto_preset annotations changed: %+v", a)
			}
			return
		}
	}
	t.Fatal("goto_preset not listed")
}

func TestHaltToolIsAbsentWithControlOffButNamedByThePolicy(t *testing.T) {
	r := newHaltRig(context.Background(), t, false, true)
	res, err := r.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range res.Tools {
		if x.Name == "test.halt" {
			t.Fatal("a halt tool must not be listed while control is off")
		}
	}
	if got := r.policy.GatedTools(); len(got) != 1 || got[0] != "test.halt" {
		t.Errorf("gated = %v", got)
	}
	if got := r.policy.HaltTools(); len(got) != 1 || got[0] != "test.halt" {
		t.Errorf("halt tools = %v", got)
	}
}

func TestHaltToolListsHaltAnnotationsNotWriteOnes(t *testing.T) {
	r := newHaltRig(context.Background(), t, true, true)
	res, err := r.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range res.Tools {
		if x.Name != "test.halt" {
			continue
		}
		a := x.Annotations
		if a == nil || a.ReadOnlyHint || a.DestructiveHint == nil || *a.DestructiveHint || !a.IdempotentHint ||
			a.OpenWorldHint == nil || *a.OpenWorldHint || a.Title != "Halt" {
			t.Errorf("annotations = %+v", a)
		}
		if strings.Contains(wireOf(t, x.InputSchema), "dry_run") {
			t.Error("a halt tool must have no dry_run field")
		}
		return
	}
	t.Fatal("halt tool not listed with control on")
}

func TestHaltCallsAreNeverRateLimitedOrBlockedByAMissingLog(t *testing.T) {
	for _, withLog := range []bool{true, false} {
		r := newHaltRig(context.Background(), t, true, withLog)
		r.policy.Limiter = nil
		for i := 0; i < 50; i++ {
			res := call(t, r.cs, "test.halt", map[string]any{"camera": "cam-a"})
			if res.IsError {
				t.Fatalf("log=%v call %d refused: %s", withLog, i, wire(t, res))
			}
		}
		if r.runs.Load() != 50 {
			t.Errorf("runs = %d", r.runs.Load())
		}
	}
}

func TestHaltCallRefusalsMatchTheGrantRules(t *testing.T) {
	r := newHaltRig(context.Background(), t, true, true)
	if code, _ := errCode(t, call(t, r.cs, "test.halt", map[string]any{"camera": "cam-fixed"})); code != "blocked_by_policy" {
		t.Errorf("not granted: code = %q", code)
	}
	if code, _ := errCode(t, call(t, r.cs, "test.halt", map[string]any{"camera": "nope"})); code != "not_found" {
		t.Errorf("unknown: code = %q", code)
	}
	if r.runs.Load() != 0 {
		t.Error("the tool must not run for a refused call")
	}
}

func TestHaltRunsOnAContextThatIgnoresRequestCancelAndBaseCancel(t *testing.T) {
	base, cancelBase := context.WithCancel(context.Background())
	cancelBase() // shutdown already begun
	r := newHaltRig(base, t, true, true)

	// Handler called directly with an already cancelled request context.
	h := haltHandler(r.d, "test.halt", r.run)
	reqCtx, cancel := context.WithCancel(context.Background())
	cancel()
	res, out, err := h(asOperator(reqCtx), nil, haltIn{Camera: "cam-a"})
	if err != nil || res == nil || out.Error != nil || out.Data == nil || !out.Data.Ran {
		t.Fatalf("halt refused under cancelled contexts: res=%v out=%+v err=%v", res, out, err)
	}
	if !r.sawCtxOK.Load() {
		t.Error("the run context must not be cancelled")
	}

	// And over MCP with Base cancelled.
	res2 := call(t, r.cs, "test.halt", map[string]any{"camera": "cam-a"})
	if res2.IsError || !r.sawCtxOK.Load() {
		t.Errorf("halt over MCP with a cancelled Base: %s", wire(t, res2))
	}
}

func TestHaltAuditsOutcomeAndSurvivesAPanic(t *testing.T) {
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a": {ID: "cam-a", Endpoint: "http://192.0.2.1/x", Control: true},
	}})
	buf := &auditBuf{}
	p := safety.NewPolicy(safety.PolicyOptions{ControlEnabled: true, Cameras: reg, Log: slog.New(slog.NewJSONHandler(buf, nil))})
	d := Deps{Reg: reg, Log: quietLog(), Policy: p}
	h := haltHandler(d, "test.halt", func(context.Context, *mcp.CallToolRequest, haltIn) (*mcp.CallToolResult, mcperr.Out[haltOut], error) {
		panic("boom password=hunter2-secret")
	})
	res, out, _ := h(asOperator(context.Background()), nil, haltIn{Camera: "cam-a"})
	if out.Error == nil || out.Error.Code != mcperr.CodeInternal || res == nil || !res.IsError {
		t.Fatalf("a panic must become an internal tool error: %+v", out)
	}
	if strings.Contains(wire(t, res), "hunter2") {
		t.Error("panic value leaked")
	}
	recs := buf.records(t)
	last := recs[len(recs)-1]
	if last["outcome"] != "panic" || last["executed"] != true || last["dry_run"] != false {
		t.Errorf("audit = %v", last)
	}
}
