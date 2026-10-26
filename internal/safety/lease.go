package safety

import (
	"context"
	"math"
	"sync"
	"time"
)

// Leases is the per-device busy gate: at most one real write holds a device at a
// time. Policy.Evaluate acquires the lease for a real write after the camera and
// grant checks and before the rate token, atomically (TryAcquire), so two calls
// can never both pass and then both move the camera. The holder keeps it for the
// whole handler and releases it when the handler returns, panics or is
// cancelled (the guarded handler defers Release).
//
// Keys are device keys (registry.Entry.DeviceKey) of configured cameras only,
// because Evaluate refuses an unknown camera first, so the table is bounded by
// the config. A key is present only while held.
//
// A continuous move's lease is timed from the moment Evaluate grants it
// (RequireTimeoutAttestation), and SetUntil records its deadline just before
// the command is sent. ptz.stop interrupts the device's timed lease
// (Interrupt): before the send that cancels the move (SetUntil reports false,
// so a stop that arrives while the move is still being validated is never
// overtaken by it); after the send it wakes the move's wait so its own stop goes
// out at once. A halt never takes a lease.
type Leases struct {
	mu   sync.Mutex
	held map[string]*Lease
	now  func() time.Time
}

// Lease is one holder's claim on a device. A nil *Lease is valid and inert.
type Lease struct {
	ls  *Leases
	key string

	// Guarded by ls.mu.
	until       time.Time
	timed       bool
	interrupted bool
	released    bool
	interrupt   chan struct{}
}

// shortWriteRetry is the retry hint for a device held by a write that is not
// timed (a relative or preset move, which lasts one request).
const shortWriteRetry = time.Second

// NewLeases builds an empty lease table. now is the clock; nil means time.Now.
func NewLeases(now func() time.Time) *Leases {
	if now == nil {
		now = time.Now
	}
	return &Leases{held: map[string]*Lease{}, now: now}
}

// TryAcquire takes the lease for key if nobody holds it. Otherwise it returns
// nil and how long the current holder expects to keep the device: until its
// motion deadline for a timed holder, rounded up to whole seconds, plus one
// second for its stop; shortWriteRetry otherwise. A nil Leases grants nothing.
func (ls *Leases) TryAcquire(key string) (*Lease, time.Duration) {
	if ls == nil {
		return nil, shortWriteRetry
	}
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if h, ok := ls.held[key]; ok {
		wait := shortWriteRetry
		if h.timed && !h.until.IsZero() {
			if left := h.until.Sub(ls.now()); left > 0 {
				wait = time.Duration(math.Ceil(left.Seconds()))*time.Second + time.Second
			}
		}
		return nil, wait
	}
	l := &Lease{ls: ls, key: key, interrupt: make(chan struct{})}
	ls.held[key] = l
	return l, 0
}

// Interrupt wakes the timed motion holding key, if any, and reports whether
// there was one. It never releases the lease and never stops anything itself:
// the holder wakes and sends its own stop. Idempotent; nil-safe.
func (ls *Leases) Interrupt(key string) bool {
	if ls == nil {
		return false
	}
	ls.mu.Lock()
	defer ls.mu.Unlock()
	h, ok := ls.held[key]
	if !ok || !h.timed {
		return false
	}
	if !h.interrupted {
		h.interrupted = true
		close(h.interrupt)
	}
	return true
}

// heldCount reports how many devices are held. Test hook.
func (ls *Leases) heldCount() int {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return len(ls.held)
}

// markTimed makes the lease interruptible before its deadline is known. Evaluate
// calls it for a tool that needs the timeout attestation, which is exactly the
// set of timed motions.
func (l *Lease) markTimed() {
	l.ls.mu.Lock()
	defer l.ls.mu.Unlock()
	l.timed = true
}

// SetUntil records that the timed motion holding the lease is about to start
// and intends to end at t; that deadline is what a refused caller is told to
// wait for. It reports false, and changes nothing, when the lease was already
// interrupted: the motion must then not be started. Checking and setting
// happen under one lock, so an Interrupt is either seen here or, if it comes
// later, wakes Interrupted. A nil lease reports false.
func (l *Lease) SetUntil(t time.Time) bool {
	if l == nil {
		return false
	}
	l.ls.mu.Lock()
	defer l.ls.mu.Unlock()
	if l.interrupted {
		return false
	}
	l.until, l.timed = t, true
	return true
}

// Interrupted is closed when ptz.stop interrupts this lease. A nil lease returns
// a nil channel, which never fires.
func (l *Lease) Interrupted() <-chan struct{} {
	if l == nil {
		return nil
	}
	return l.interrupt
}

type leaseKey struct{}

// WithLease returns ctx carrying l, so the tool the guarded handler runs can
// reach the lease Evaluate granted it (LeaseFrom). A nil l is carried as nil.
func WithLease(ctx context.Context, l *Lease) context.Context {
	return context.WithValue(ctx, leaseKey{}, l)
}

// LeaseFrom returns the lease carried by ctx, or nil.
func LeaseFrom(ctx context.Context) *Lease {
	l, _ := ctx.Value(leaseKey{}).(*Lease)
	return l
}

// Release frees the device. Calling it more than once, or after a later holder
// acquired the key, does nothing to that holder. Nil-safe.
func (l *Lease) Release() {
	if l == nil {
		return
	}
	l.ls.mu.Lock()
	defer l.ls.mu.Unlock()
	if l.released {
		return
	}
	l.released = true
	if l.ls.held[l.key] == l {
		delete(l.ls.held, l.key)
	}
}
