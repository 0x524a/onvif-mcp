package tools

import (
	"context"
	"errors"
	"sync"
	"time"
)

// flight bounds concurrent identical device work, per key, without ever handing
// a caller a result that predates it. It is the gate behind ptz.stop (and, in a
// second instance, the status reads that confirm a stop).
//
// A round is one unit of device work covering a set of tokens. Rules:
//
//   - At most maxRounds rounds are in flight per key. An arrival with fewer in
//     flight starts a round immediately, so a stop arriving behind a hung round
//     reaches the camera at once, not after the hung round's timeout.
//   - An arrival with maxRounds in flight attaches to the single pending round
//     (created if nil), which starts when a slot frees. A caller therefore only
//     ever receives the result of a round that started after it arrived.
//   - A round in flight longer than stallAfter stops occupying a slot for
//     scheduling (its goroutine still ends at its own deadline), so two hung
//     rounds delay a new arrival by about stallAfter, not by their timeouts.
//   - A pending round holds at most maxRoundTokens distinct tokens; the rest are
//     refused with errFlightFull. The key is agent-independent (a device key);
//     the tokens are agent-chosen text and are bounded here.
//   - A key with nothing in flight or pending is deleted.
type flight[R any] struct {
	mu         sync.Mutex
	keys       map[string]*flightKey[R]
	stallAfter time.Duration
	// after schedules fn after d and returns a stop function. It is a seam so
	// tests run on a fake clock; production uses time.AfterFunc.
	after func(d time.Duration, fn func()) (stop func() bool)
}

const (
	maxRounds      = 2
	maxRoundTokens = 64
)

// errFlightFull is returned to a caller whose token does not fit in the pending
// round. It is never a camera result.
var errFlightFull = errors.New("too many different tokens are waiting for a round")

// errNoResult is returned when a round ended without a result for a token (the
// round panicked).
var errNoResult = errors.New("the round ended without a result")

type flightKey[R any] struct {
	inflight []*flightRound[R]
	pending  *flightRound[R]
}

type flightRound[R any] struct {
	run     func(tokens []string) map[string]R
	tokens  []string
	set     map[string]struct{}
	done    chan struct{}
	results map[string]R // written before done is closed
	stalled bool         // guarded by flight.mu
	stop    func() bool
}

func newFlight[R any](stallAfter time.Duration, after func(time.Duration, func()) func() bool) *flight[R] {
	if after == nil {
		after = func(d time.Duration, fn func()) func() bool {
			t := time.AfterFunc(d, fn)
			return t.Stop
		}
	}
	return &flight[R]{keys: map[string]*flightKey[R]{}, stallAfter: stallAfter, after: after}
}

func (r *flightRound[R]) add(token string) bool {
	if _, ok := r.set[token]; ok {
		return true
	}
	if len(r.tokens) >= maxRoundTokens {
		return false
	}
	r.set[token] = struct{}{}
	r.tokens = append(r.tokens, token)
	return true
}

func (k *flightKey[R]) active() int {
	n := 0
	for _, r := range k.inflight {
		if !r.stalled {
			n++
		}
	}
	return n
}

// keyCount reports how many keys currently have work, for tests and leak checks.
func (f *flight[R]) keyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.keys)
}

// do returns the result for token from a round that started after do was called.
// run performs a round for a set of tokens; the caller that creates a round
// supplies it.
func (f *flight[R]) do(ctx context.Context, key, token string, run func(tokens []string) map[string]R) (R, error) {
	var zero R
	f.mu.Lock()
	k := f.keys[key]
	if k == nil {
		k = &flightKey[R]{}
		f.keys[key] = k
	}
	var r *flightRound[R]
	if k.active() < maxRounds {
		r = newRound(run)
		r.add(token)
		f.start(key, k, r)
	} else {
		if k.pending == nil {
			k.pending = newRound(run)
		}
		r = k.pending
		if !r.add(token) {
			f.mu.Unlock()
			return zero, errFlightFull
		}
	}
	f.mu.Unlock()

	select {
	case <-r.done:
		res, ok := r.results[token]
		if !ok {
			return zero, errNoResult
		}
		return res, nil
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}

func newRound[R any](run func([]string) map[string]R) *flightRound[R] {
	return &flightRound[R]{run: run, set: map[string]struct{}{}, done: make(chan struct{})}
}

// start launches r. f.mu must be held.
func (f *flight[R]) start(key string, k *flightKey[R], r *flightRound[R]) {
	k.inflight = append(k.inflight, r)
	r.stop = f.after(f.stallAfter, func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		r.stalled = true
		f.kick(key, k)
	})
	tokens := append([]string(nil), r.tokens...)
	go func() {
		var res map[string]R
		func() {
			defer func() { _ = recover() }() // a panicking round yields no result, never a hang
			res = r.run(tokens)
		}()
		f.mu.Lock()
		r.results = res
		if r.stop != nil {
			r.stop()
		}
		for i, x := range k.inflight {
			if x == r {
				k.inflight = append(k.inflight[:i], k.inflight[i+1:]...)
				break
			}
		}
		close(r.done)
		f.kick(key, k)
		f.mu.Unlock()
	}()
}

// kick starts the pending round while a slot is free, and deletes an idle key.
// f.mu must be held.
func (f *flight[R]) kick(key string, k *flightKey[R]) {
	for k.pending != nil && k.active() < maxRounds {
		r := k.pending
		k.pending = nil
		f.start(key, k, r)
	}
	if len(k.inflight) == 0 && k.pending == nil && f.keys[key] == k {
		delete(f.keys, key)
	}
}
