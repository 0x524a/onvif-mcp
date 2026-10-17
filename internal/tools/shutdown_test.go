package tools

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
)

// context.AfterFunc runs its callback on another goroutine, so a Base that is
// already done must be handled synchronously.
func TestScopeIsCancelledAtOnceWhenBaseIsAlreadyDone(t *testing.T) {
	base, cancelBase := context.WithCancel(context.Background())
	cancelBase()
	for i := 0; i < 200; i++ {
		ctx, cancel := Deps{Base: base}.Scope(context.Background())
		if ctx.Err() == nil {
			cancel()
			t.Fatalf("iteration %d: scope not cancelled although Base is done", i)
		}
		cancel()
	}
}

func TestWriteIsNotStartedWhenShutdownHasBegun(t *testing.T) {
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a": {ID: "cam-a", Endpoint: "http://192.0.2.1/onvif/device_service", Control: true},
	}})
	audit := &auditBuf{}
	policy := safety.NewPolicy(safety.PolicyOptions{
		ControlEnabled: true, Cameras: reg, Interval: time.Hour, Burst: 1,
		Log: slog.New(slog.NewJSONHandler(audit, nil)),
	})
	base, cancelBase := context.WithCancel(context.Background())
	cancelBase()

	var execs, sawLive atomic.Int32
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	GuardedTool(srv, Deps{Reg: reg, Log: quietLog(), Base: base, Policy: policy}, safety.RiskWrite,
		&mcp.Tool{Name: "test.nudge", Description: "x"},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ nudgeIn) (*mcp.CallToolResult, mcperr.Out[nudgeOut], error) {
			execs.Add(1)
			if ctx.Err() == nil {
				sawLive.Add(1)
			}
			return nil, mcperr.OK(nudgeOut{Moved: true}), nil
		}, nudgeNoop)
	cs := connectTo(t, srv)

	for i := 0; i < 20; i++ {
		res := call(t, cs, "test.nudge", map[string]any{"camera": "cam-a", "dry_run": false})
		if !res.IsError {
			t.Fatalf("iteration %d: want an error, got %s", i, wire(t, res))
		}
		if code, hint := errCode(t, res); code == "" || hint == "" {
			t.Fatalf("iteration %d: error needs a code and a hint: %s", i, wire(t, res))
		}
	}
	if execs.Load() != 0 {
		t.Fatalf("a real write ran %d times after shutdown began (%d with a live ctx)", execs.Load(), sawLive.Load())
	}
	recs := audit.records(t)
	if len(recs) == 0 {
		t.Fatal("no audit record")
	}
	for _, a := range recs {
		if a["outcome"] != "cancelled" || a["executed"] != false {
			t.Fatalf("audit = %v", a)
		}
	}
}

func TestHugeCameraIDIsNotScrubbedWholeOnTheCancelledPath(t *testing.T) {
	base, cancelBase := context.WithCancel(context.Background())
	cancelBase()
	policy := safety.NewPolicy(safety.PolicyOptions{ControlEnabled: true, Log: quietLog()})
	h := guardedHandler(Deps{Base: base, Policy: policy}, "test.nudge", nudgeNoop, nudgeNoop)
	big := make([]byte, 10<<20)
	for i := range big {
		big[i] = "a:b@"[i%4]
	}
	in := nudgeIn{WriteBase: safety.WriteBase{Camera: string(big), DryRun: new(bool)}}
	t0 := time.Now()
	res, out, err := h(context.Background(), nil, in)
	if el := time.Since(t0); el > 500*time.Millisecond {
		t.Errorf("handler took %v", el)
	}
	if err != nil || !res.IsError || out.Error == nil || len(out.Error.Camera) > 300 {
		t.Errorf("res=%v err=%v out=%+v", res, err, out.Error)
	}
}
