package safety

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a manually advanced clock, so no test sleeps.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestDryRunDefaultsToTrueWhenAbsent(t *testing.T) {
	var w WriteBase // DryRun nil, as it is when the agent omits the field
	if !w.IsDryRun() {
		t.Error("dry_run must default to true when omitted")
	}
	f := false
	w.DryRun = &f
	if w.IsDryRun() {
		t.Error("dry_run false must be honoured when explicit")
	}
	tr := true
	w.DryRun = &tr
	if !w.IsDryRun() {
		t.Error("dry_run true must be honoured when explicit")
	}
}

func TestWriteBaseSatisfiesWriteInput(t *testing.T) {
	var in WriteInput = WriteBase{Camera: "cam-a"}
	if in.CameraID() != "cam-a" {
		t.Errorf("CameraID = %q", in.CameraID())
	}
}

func TestWriteAnnotationsAreExplicit(t *testing.T) {
	a := WriteAnnotations("Go to preset")
	if a.Title != "Go to preset" || a.ReadOnlyHint {
		t.Errorf("title/readonly wrong: %+v", a)
	}
	if a.DestructiveHint == nil || !*a.DestructiveHint {
		t.Error("destructive hint must be explicitly true")
	}
	if a.OpenWorldHint == nil || *a.OpenWorldHint {
		t.Error("open-world hint must be explicitly false")
	}
	if !a.IdempotentHint {
		t.Error("idempotent hint must be true")
	}
}

func TestLimiterAllowsBurstThenRefuses(t *testing.T) {
	clk := newFakeClock()
	l := NewLimiter(2*time.Second, 1, WithClock(clk.Now))
	if ok, _ := l.Allow("cam-a"); !ok {
		t.Fatal("first call must be allowed")
	}
	ok, after := l.Allow("cam-a")
	if ok {
		t.Error("second call must be refused")
	}
	if after <= 0 || after > 2*time.Second {
		t.Errorf("retry-after = %v, want in (0, 2s]", after)
	}
}

func TestLimiterBurstOfTwo(t *testing.T) {
	clk := newFakeClock()
	l := NewLimiter(time.Second, 2, WithClock(clk.Now))
	for i := 0; i < 2; i++ {
		if ok, _ := l.Allow("cam-a"); !ok {
			t.Fatalf("call %d within burst refused", i)
		}
	}
	if ok, _ := l.Allow("cam-a"); ok {
		t.Error("third call must be refused")
	}
}

func TestLimiterIsPerCamera(t *testing.T) {
	clk := newFakeClock()
	l := NewLimiter(time.Hour, 1, WithClock(clk.Now))
	l.Allow("cam-a")
	if ok, _ := l.Allow("cam-b"); !ok {
		t.Error("throttling one camera must not throttle another")
	}
}

func TestLimiterRefillsWithFakeClock(t *testing.T) {
	clk := newFakeClock()
	l := NewLimiter(2*time.Second, 1, WithClock(clk.Now))
	l.Allow("cam-a")
	clk.Advance(1 * time.Second)
	ok, after := l.Allow("cam-a")
	if ok {
		t.Fatal("half an interval must not refill a token")
	}
	if after != time.Second {
		t.Errorf("retry-after = %v, want 1s", after)
	}
	clk.Advance(1 * time.Second)
	if ok, _ := l.Allow("cam-a"); !ok {
		t.Error("a token must become available after the full interval")
	}
}

func TestLimiterRefillIsCappedAtBurst(t *testing.T) {
	clk := newFakeClock()
	l := NewLimiter(time.Second, 2, WithClock(clk.Now))
	l.Allow("cam-a")
	clk.Advance(time.Hour)
	allowed := 0
	for i := 0; i < 5; i++ {
		if ok, _ := l.Allow("cam-a"); ok {
			allowed++
		}
	}
	if allowed != 2 {
		t.Errorf("allowed %d after a long idle, want exactly the burst (2)", allowed)
	}
}

func TestLimiterSurvivesClockGoingBackwards(t *testing.T) {
	clk := newFakeClock()
	l := NewLimiter(time.Second, 1, WithClock(clk.Now))
	l.Allow("cam-a")
	clk.Advance(-time.Hour)
	if ok, _ := l.Allow("cam-a"); ok {
		t.Error("a backwards clock must not mint tokens")
	}
}

func TestLimiterDefaultsForNonsenseConfig(t *testing.T) {
	clk := newFakeClock()
	l := NewLimiter(0, 0, WithClock(clk.Now))
	if ok, _ := l.Allow("cam-a"); !ok {
		t.Fatal("first call must be allowed")
	}
	if ok, _ := l.Allow("cam-a"); ok {
		t.Error("defaults must be burst 1")
	}
	clk.Advance(DefaultInterval)
	if ok, _ := l.Allow("cam-a"); !ok {
		t.Error("default interval must be DefaultInterval")
	}
}

// With burst 1 and a frozen clock, exactly one of N concurrent callers wins.
func TestLimiterConcurrentAllowGrantsExactlyOne(t *testing.T) {
	clk := newFakeClock()
	l := NewLimiter(time.Hour, 1, WithClock(clk.Now))
	const n = 64
	var allowed atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if ok, _ := l.Allow("cam-a"); ok {
				allowed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := allowed.Load(); got != 1 {
		t.Errorf("%d of %d concurrent calls allowed, want exactly 1", got, n)
	}
}

func TestLimiterMapIsBounded(t *testing.T) {
	clk := newFakeClock()
	l := NewLimiter(time.Hour, 1, WithClock(clk.Now), WithMaxKeys(4))
	refused := 0
	for i := 0; i < 100; i++ {
		if ok, after := l.Allow(fmt.Sprintf("cam-%d", i)); !ok {
			refused++
			if after <= 0 {
				t.Error("a refusal must report a wait")
			}
		}
	}
	if got := l.size(); got > 4 {
		t.Errorf("limiter tracks %d keys, cap is 4", got)
	}
	if refused != 96 {
		t.Errorf("refused %d, want 96 (fail closed once the cap is full)", refused)
	}
}

func TestLimiterCapReclaimsFullyRefilledBuckets(t *testing.T) {
	clk := newFakeClock()
	l := NewLimiter(time.Second, 1, WithClock(clk.Now), WithMaxKeys(2))
	l.Allow("a")
	l.Allow("b")
	if ok, _ := l.Allow("c"); ok {
		t.Fatal("cap full of busy buckets must refuse a new key")
	}
	clk.Advance(2 * time.Second) // a and b are idle and full again
	if ok, _ := l.Allow("c"); !ok {
		t.Error("idle full buckets must be reclaimed to make room")
	}
	if got := l.size(); got > 2 {
		t.Errorf("limiter tracks %d keys, cap is 2", got)
	}
}
