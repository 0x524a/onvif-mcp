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
	nilLease.SetUntil(time.Now())
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
