package safety

import (
	"context"
	"testing"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
)

func remoteCtx(t *testing.T) context.Context {
	t.Helper()
	c, err := RemoteCaller("laptop-agent", "http")
	if err != nil {
		t.Fatal(err)
	}
	return WithCaller(context.Background(), c)
}

func lastReason(t *testing.T, buf *syncBuf) (string, map[string]any) {
	t.Helper()
	recs := buf.records(t)
	if len(recs) == 0 {
		t.Fatal("no audit record was written")
	}
	r := recs[len(recs)-1]
	reason, _ := r["reason"].(string)
	return reason, r
}

func TestEvaluateRefusesWithoutACallerBeforeAnythingElse(t *testing.T) {
	for _, dry := range []bool{false, true} {
		p, buf, _ := newPolicy(true)
		d := p.Evaluate(context.Background(), "cam-a", tool, dry)
		if d.Blocked == nil || d.Blocked.Code != mcperr.CodeBlockedByPolicy {
			t.Fatalf("dry=%v: no caller must be blocked_by_policy, got %+v", dry, d.Blocked)
		}
		if d.Refund != nil {
			t.Error("a refusal must carry no refund")
		}
		if reason, _ := lastReason(t, buf); reason != ReasonCallerUnidentified {
			t.Errorf("audit reason = %q, want %q", reason, ReasonCallerUnidentified)
		}
		if got := p.Limiter.size(); got != 0 {
			t.Errorf("a refused caller consumed limiter state (%d keys)", got)
		}
	}
}

func TestEvaluateRefusesAZeroCallerStoredInContext(t *testing.T) {
	p, _, _ := newPolicy(true)
	ctx := WithCaller(context.Background(), Caller{})
	if d := p.Evaluate(ctx, "cam-a", tool, false); d.Blocked == nil {
		t.Fatal("a zero Caller in the context must be refused")
	}
}

func TestEvaluateRefusesAValidCallerWithoutControl(t *testing.T) {
	for _, dry := range []bool{false, true} {
		p, buf, _ := newPolicy(true)
		d := p.Evaluate(remoteCtx(t), "cam-a", tool, dry)
		if d.Blocked == nil || d.Blocked.Code != mcperr.CodeBlockedByPolicy {
			t.Fatalf("dry=%v: remote caller must be blocked_by_policy, got %+v", dry, d.Blocked)
		}
		reason, rec := lastReason(t, buf)
		if reason != ReasonCallerNotGranted {
			t.Errorf("audit reason = %q, want %q", reason, ReasonCallerNotGranted)
		}
		if rec["caller"] != "laptop-agent" {
			t.Errorf("refusal audit must name the caller, got %v", rec["caller"])
		}
		if got := p.Limiter.size(); got != 0 {
			t.Errorf("a refused caller consumed limiter state (%d keys)", got)
		}
	}
	// The refusal cost no rate budget: the operator's first real call still passes.
	p, _, _ := newPolicy(true)
	for i := 0; i < 5; i++ {
		p.Evaluate(remoteCtx(t), "cam-a", tool, false)
	}
	if d := p.Evaluate(opCtx(), "cam-a", tool, false); d.Blocked != nil {
		t.Fatalf("operator call after refused remote calls: %+v", d.Blocked)
	}
}

// A caller without control gets one answer whatever camera it names, so it
// cannot probe which ids exist or which are granted.
func TestCallerRefusalIsIdenticalForEveryCameraId(t *testing.T) {
	p, _, _ := newPolicy(true)
	type shape struct {
		code      mcperr.Code
		msg, hint string
		retry     bool
	}
	var want *shape
	for _, ctx := range []context.Context{context.Background(), remoteCtx(t)} {
		want = nil
		for _, cam := range []string{"cam-a", "cam-fixed", "no-such-camera", ""} {
			for _, d := range []Decision{p.Evaluate(ctx, cam, tool, false), p.Evaluate(ctx, cam, tool, true), p.EvaluateHalt(ctx, cam, haltTool)} {
				if d.Blocked == nil {
					t.Fatalf("camera %q was not refused", cam)
				}
				got := shape{d.Blocked.Code, d.Blocked.Message, d.Blocked.Hint, d.Blocked.Retryable}
				if want == nil {
					want = &got
				} else if got != *want {
					t.Fatalf("refusal for %q differs: %+v vs %+v", cam, got, *want)
				}
			}
		}
	}
}

func TestEvaluateHaltIsCallerGated(t *testing.T) {
	p, buf, _ := newPolicy(true)
	if d := p.EvaluateHalt(context.Background(), "cam-a", haltTool); d.Blocked == nil {
		t.Fatal("halt with no caller must be refused")
	} else if r, _ := lastReason(t, buf); r != ReasonCallerUnidentified {
		t.Errorf("reason %q", r)
	}
	if d := p.EvaluateHalt(remoteCtx(t), "cam-a", haltTool); d.Blocked == nil {
		t.Fatal("halt by a caller without control must be refused")
	} else if r, _ := lastReason(t, buf); r != ReasonCallerNotGranted {
		t.Errorf("reason %q", r)
	}
	if d := p.EvaluateHalt(opCtx(), "cam-a", haltTool); d.Blocked != nil {
		t.Fatalf("operator halt refused: %+v", d.Blocked)
	}
}

func TestStdioOperatorKeepsTheExistingGateOrder(t *testing.T) {
	p, _, _ := newPolicy(true)
	if d := p.Evaluate(opCtx(), "nope", tool, false); d.Blocked == nil || d.Blocked.Code != mcperr.CodeNotFound {
		t.Errorf("operator + unknown camera must still be not_found, got %+v", d.Blocked)
	}
	if d := p.Evaluate(opCtx(), "cam-fixed", tool, false); d.Blocked == nil || d.Blocked.Code != mcperr.CodeBlockedByPolicy {
		t.Errorf("operator + ungranted camera must still be blocked, got %+v", d.Blocked)
	}
}
