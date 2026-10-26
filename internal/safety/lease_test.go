package safety

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLeaseTryAcquireIsExclusivePerKeyUnderRace(t *testing.T) {
	ls := NewLeases(nil)
	const n = 64
	var won atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	got := make(chan *Lease, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if l, _ := ls.TryAcquire("dev"); l != nil {
				won.Add(1)
				got <- l
			}
		}()
	}
	close(start)
	wg.Wait()
	close(got)
	if won.Load() != 1 {
		t.Fatalf("%d goroutines acquired one key's lease, want exactly 1", won.Load())
	}
	if l, _ := ls.TryAcquire("other"); l == nil {
		t.Error("a different key must not be blocked")
	}
	(<-got).Release()
	if l, _ := ls.TryAcquire("dev"); l == nil {
		t.Error("released lease is still held")
	}
}

func TestLeaseRetryComesFromTheHoldersDeadline(t *testing.T) {
	clk := newFakeClock()
	ls := NewLeases(clk.Now)
	l, _ := ls.TryAcquire("dev")
	if _, wait := ls.TryAcquire("dev"); wait != time.Second {
		t.Errorf("a short write holder: wait = %v, want 1s", wait)
	}
	l.markTimed()
	l.SetUntil(clk.Now().Add(3500 * time.Millisecond))
	if _, wait := ls.TryAcquire("dev"); wait < 3500*time.Millisecond || wait > 5*time.Second {
		t.Errorf("a timed holder 3.5s from its deadline: wait = %v", wait)
	}
	clk.Advance(time.Hour) // past the deadline: the holder is stopping, not gone
	if l2, wait := ls.TryAcquire("dev"); l2 != nil || wait != time.Second {
		t.Errorf("a lease is held until released, whatever its deadline: %v %v", l2, wait)
	}
}

func TestLeaseReleaseIsIdempotentAndNeverFreesALaterHolder(t *testing.T) {
	ls := NewLeases(nil)
	a, _ := ls.TryAcquire("dev")
	a.Release()
	b, _ := ls.TryAcquire("dev")
	if b == nil {
		t.Fatal("not reacquired")
	}
	a.Release() // stale: must not free b
	if l, _ := ls.TryAcquire("dev"); l != nil {
		t.Fatal("a second Release of an old lease freed the current holder")
	}
	b.Release()
	b.Release()
	if ls.heldCount() != 0 {
		t.Errorf("held = %d after release", ls.heldCount())
	}
	var nilLease *Lease
	nilLease.Release()
	if nilLease.SetUntil(time.Now()) {
		t.Error("a nil lease cannot start a motion")
	}
	if nilLease.Interrupted() != nil {
		t.Error("a nil lease has no interrupt channel")
	}
}

func TestLeaseInterruptWakesOnlyATimedMotion(t *testing.T) {
	ls := NewLeases(nil)
	if ls.Interrupt("dev") {
		t.Error("nothing held: Interrupt must report false")
	}
	short, _ := ls.TryAcquire("dev")
	if ls.Interrupt("dev") {
		t.Error("a short write is not interruptible motion")
	}
	select {
	case <-short.Interrupted():
		t.Fatal("a short write's channel was closed")
	default:
	}
	short.Release()

	timed, _ := ls.TryAcquire("dev")
	timed.markTimed()
	timed.SetUntil(time.Now().Add(time.Second))
	if !ls.Interrupt("dev") {
		t.Error("Interrupt must report a timed motion")
	}
	if !ls.Interrupt("dev") {
		t.Error("a second Interrupt must still report it (idempotent)")
	}
	select {
	case <-timed.Interrupted():
	default:
		t.Fatal("the timed lease was not woken")
	}
	timed.Release()
	if ls.Interrupt("dev") {
		t.Error("after release there is nothing to interrupt")
	}
}

func TestLeasesNilIsSafe(t *testing.T) {
	var ls *Leases
	if l, _ := ls.TryAcquire("x"); l != nil {
		t.Error("a nil Leases grants nothing")
	}
	if ls.Interrupt("x") {
		t.Error("a nil Leases interrupts nothing")
	}
}

// A timed motion that has not been sent yet (still validating) is interrupted
// too: its SetUntil then reports false, so it must not send. Without this a
// ptz.stop arriving during validation would be overtaken by the move.
func TestInterruptBeforeTheMotionStartsCancelsIt(t *testing.T) {
	ls := NewLeases(nil)
	l, _ := ls.TryAcquire("dev")
	l.markTimed()
	if !ls.Interrupt("dev") {
		t.Fatal("a pending timed motion must count as interrupted")
	}
	if l.SetUntil(time.Now().Add(time.Second)) {
		t.Fatal("SetUntil must refuse a motion that was interrupted before it started")
	}
	l.Release()

	l, _ = ls.TryAcquire("dev")
	l.markTimed()
	if !l.SetUntil(time.Now().Add(time.Second)) {
		t.Fatal("an uninterrupted motion may start")
	}
	if !ls.Interrupt("dev") {
		t.Fatal("a running timed motion is interrupted")
	}
	l.Release()
}

func TestRequireTimeoutAttestationMakesTheLeaseInterruptibleFromTheStart(t *testing.T) {
	p := NewPolicy(PolicyOptions{ControlEnabled: true, Cameras: attestRegistry(), Interval: time.Millisecond, Burst: 5, Log: quiet()})
	d := p.Evaluate(opCtx(), "cam-t", contTool, false, RequireTimeoutAttestation())
	defer d.Lease.Release()
	if !p.InterruptMotion("cam-t") {
		t.Fatal("a continuous move's lease must be interruptible before its deadline is set")
	}
	w := p.Evaluate(opCtx(), "cam-a", tool, false)
	defer w.Lease.Release()
	if p.InterruptMotion("cam-a") {
		t.Error("a short write is not interruptible motion")
	}
}
