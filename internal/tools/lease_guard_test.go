package tools

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
)

// leaseRig serves two write tools over one device (two camera ids for one
// endpoint), with a rate budget large enough that only the lease can refuse.
type leaseRig struct {
	cs      *mcp.ClientSession
	policy  *safety.Policy
	inRun   atomic.Int32
	sawNil  atomic.Bool
	release chan struct{}
	panics  atomic.Bool
	notSent atomic.Bool
}

func newLeaseRig(t *testing.T) *leaseRig {
	t.Helper()
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"a": {ID: "a", Endpoint: "http://192.0.2.50/onvif/device_service", Control: true},
		"b": {ID: "b", Endpoint: "http://192.0.2.50:80/onvif/device_service/", Control: true},
	}})
	r := &leaseRig{release: make(chan struct{})}
	close(r.release)
	r.policy = safety.NewPolicy(safety.PolicyOptions{ControlEnabled: true, Cameras: reg, Interval: time.Millisecond, Burst: 100, Log: quietLog()})
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	d := Deps{Reg: reg, Log: quietLog(), Policy: r.policy}
	run := func(ctx context.Context, _ *mcp.CallToolRequest, _ nudgeIn) (*mcp.CallToolResult, mcperr.Out[nudgeOut], error) {
		if safety.LeaseFrom(ctx) == nil {
			r.sawNil.Store(true)
		}
		r.inRun.Add(1)
		defer r.inRun.Add(-1)
		<-r.release
		if r.panics.Load() {
			panic("boom")
		}
		if r.notSent.Load() {
			return fail[nudgeOut](&mcperr.ToolError{Code: mcperr.CodeInvalidArgument, NotSent: true, Message: "x"})
		}
		return nil, mcperr.OK(nudgeOut{Moved: true}), nil
	}
	dry := func(ctx context.Context, _ *mcp.CallToolRequest, _ nudgeIn) (*mcp.CallToolResult, mcperr.Out[nudgeOut], error) {
		if safety.LeaseFrom(ctx) != nil {
			t.Error("a dry run must hold no lease")
		}
		return nil, mcperr.OK(nudgeOut{}), nil
	}
	for _, name := range []string{"test.one", "test.two"} {
		GuardedTool(srv, d, safety.RiskWrite, &mcp.Tool{Name: name, Description: "x"}, run, dry)
	}
	r.cs = connectTo(t, srv)
	return r
}

func (r *leaseRig) real(t *testing.T, tool, cam string) *mcp.CallToolResult {
	t.Helper()
	return call(t, r.cs, tool, map[string]any{"camera": cam, "dry_run": false})
}

func TestGuardedWriteHoldsTheLeaseOnlyWhileItRuns(t *testing.T) {
	r := newLeaseRig(t)
	for i := 0; i < 3; i++ {
		if res := r.real(t, "test.one", "a"); res.IsError {
			t.Fatalf("sequential call %d: %s", i, wire(t, res))
		}
	}
	call(t, r.cs, "test.one", map[string]any{"camera": "a"}) // dry run
	if r.sawNil.Load() {
		t.Error("a real write ran without its lease on the context")
	}
	for _, mode := range []string{"panic", "not sent"} {
		r.panics.Store(mode == "panic")
		r.notSent.Store(mode == "not sent")
		if res := r.real(t, "test.one", "a"); !res.IsError {
			t.Fatalf("%s: want an error", mode)
		}
		r.panics.Store(false)
		r.notSent.Store(false)
		if res := r.real(t, "test.two", "b"); res.IsError {
			t.Fatalf("after a %s the device lease was not released: %s", mode, wire(t, res))
		}
	}
}

func TestGuardedWritesOnOneDeviceNeverOverlap(t *testing.T) {
	r := newLeaseRig(t)
	r.release = make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); r.real(t, "test.one", "a") }()
	deadline := time.Now().Add(5 * time.Second)
	for r.inRun.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("first call never ran")
		}
		time.Sleep(time.Millisecond)
	}
	// A different tool and a different id for the same device: busy, never run.
	res := r.real(t, "test.two", "b")
	code, _ := errCode(t, res)
	if code != "blocked_by_policy" || errField(res, "retry_after_seconds") == nil || r.inRun.Load() != 1 {
		t.Fatalf("code=%q inRun=%d: %s", code, r.inRun.Load(), wire(t, res))
	}
	close(r.release)
	wg.Wait()
	if res := r.real(t, "test.two", "b"); res.IsError {
		t.Fatalf("after the first call returned: %s", wire(t, res))
	}
}
