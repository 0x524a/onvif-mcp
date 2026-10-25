package safety

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// kills M24: a backwards clock step must not rewind bucket.last.
func TestBackwardsClockDoesNotRewindRefillAnchor(t *testing.T) {
	clk := newFakeClock()
	l := NewLimiter(2*time.Second, 1, WithClock(clk.Now))
	if ok, _ := l.Allow("c"); !ok {
		t.Fatal("first must pass")
	}
	clk.Advance(-10 * time.Second)
	if ok, _ := l.Allow("c"); ok {
		t.Fatal("backwards clock must not allow")
	}
	clk.Advance(11 * time.Second) // now = t0+1s, only 1s after the real move
	if ok, _ := l.Allow("c"); ok {
		t.Fatal("only 1s of a 2s interval elapsed since the last real move; clock jitter minted a token")
	}
}

// kills M22: a backwards step must not remove tokens either.
func TestBackwardsClockDoesNotDrainTokens(t *testing.T) {
	clk := newFakeClock()
	l := NewLimiter(2*time.Second, 2, WithClock(clk.Now))
	l.Allow("c")
	clk.Advance(-10 * time.Second)
	if ok, _ := l.Allow("c"); !ok {
		t.Fatal("second token of burst 2 was lost to a backwards clock")
	}
}

// kills M26 (and documents M25 floor is dead): retry hint must round up.
func TestRetryAfterRoundsUpFractionalSeconds(t *testing.T) {
	p, _, clk := newPolicy(true)
	p.Limiter = NewLimiter(1500*time.Millisecond, 1, WithClock(clk.Now))
	evalDone(opCtx(), p, "cam-a", tool, false)
	d := evalDone(opCtx(), p, "cam-a", tool, false)
	if d.Blocked == nil || d.Blocked.RetryAfterSeconds == nil || *d.Blocked.RetryAfterSeconds != 2 {
		t.Fatalf("1.5s wait must report retry_after_seconds=2, got %+v", d.Blocked)
	}
}

// kills M101
func TestAllowSuccessReportsZeroWait(t *testing.T) {
	l := NewLimiter(time.Second, 1, WithClock(newFakeClock().Now))
	if ok, w := l.Allow("c"); !ok || w != 0 {
		t.Fatalf("got %v %v", ok, w)
	}
}

// kills M94
func TestBlockedAuditIsWarnLevel(t *testing.T) {
	p, buf, _ := newPolicy(true)
	evalDone(opCtx(), p, "cam-fixed", tool, false)
	r := buf.records(t)
	if len(r) != 1 || r[0]["level"] != "WARN" {
		t.Fatalf("refusal must log at WARN: %v", r)
	}
}

// kills M100/M96
func TestBlockedDecisionKeepsDryRunFlag(t *testing.T) {
	p, _, _ := newPolicy(true)
	if d := evalDone(opCtx(), p, "cam-fixed", tool, true); d.Blocked == nil || !d.DryRun {
		t.Fatalf("%+v", d)
	}
}

// kills M69: a camera func returning nil must serialise as [], not null.
func TestPolicyResourceCamerasNeverNull(t *testing.T) {
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterPolicyResource(srv, nil, func() []CameraGrant { return nil })
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	res, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: PolicyURI})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Contents[0].Text; !strings.Contains(got, `"cameras": []`) {
		t.Fatalf("cameras must be [] not null: %s", got)
	}
}

// Race detector tests: the gated set and the target slot are shared between
// the goroutines of concurrent calls.
func TestGatedSetIsSafeForConcurrentUse(t *testing.T) {
	p := &Policy{}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(2)
		go func(i int) { defer wg.Done(); p.NoteGated(fmt.Sprintf("tool.%d", i%4)) }(i)
		go func() { defer wg.Done(); _ = p.GatedTools() }()
	}
	wg.Wait()
	if got := p.GatedTools(); len(got) != 4 {
		t.Errorf("gated = %v", got)
	}
}

func TestTargetSlotIsSafeForConcurrentUse(t *testing.T) {
	ctx, slot := WithTargetSlot(context.Background())
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); NoteTarget(ctx, "p1") }()
		go func() { defer wg.Done(); _ = slot.Get() }()
	}
	wg.Wait()
	if slot.Get() != "p1" {
		t.Errorf("target = %q", slot.Get())
	}
}
