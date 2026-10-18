package safety

import (
	"sync"
	"time"
)

const (
	// DefaultInterval is the default refill interval: one movement per 2s.
	DefaultInterval = 2 * time.Second
	// DefaultBurst is the default bucket size.
	DefaultBurst = 1
	// DefaultMaxKeys bounds how many cameras a Limiter tracks.
	DefaultMaxKeys = 1024
)

// Limiter is a token bucket per key. Callers key it by physical device (the
// normalised endpoint), not by camera id, so two ids for one device share one
// budget, while driving one device does not throttle a fleet.
//
// The reason for limiting at all is physical: PTZ motors wear, and some cameras
// wedge under rapid repeated commands. An agent looping is the expected failure
// mode, not an edge case.
//
// Memory is bounded. A key can originate in agent input, so callers must only
// pass keys of configured cameras (Policy.Evaluate enforces this before
// reaching the limiter, which makes the key set at most the config's size). As a second line of defence the
// limiter never tracks more than its key cap: when full it first reclaims
// buckets that have refilled completely (indistinguishable from never seen),
// and if none can be reclaimed it refuses the new key.
type Limiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	interval time.Duration
	burst    float64
	maxKeys  int
	now      func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
	// grants counts tokens handed out, so a refund can tell whether anyone
	// else has been granted one since.
	grants uint64
}

// LimiterOption customises a Limiter.
type LimiterOption func(*Limiter)

// WithClock replaces the time source; tests use it to avoid sleeping.
func WithClock(now func() time.Time) LimiterOption {
	return func(l *Limiter) {
		if now != nil {
			l.now = now
		}
	}
}

// WithMaxKeys sets the cap on tracked cameras. Values below 1 are ignored.
func WithMaxKeys(n int) LimiterOption {
	return func(l *Limiter) {
		if n >= 1 {
			l.maxKeys = n
		}
	}
}

// NewLimiter builds a limiter granting one token per interval, up to burst.
// A non-positive interval or burst falls back to DefaultInterval or
// DefaultBurst.
func NewLimiter(interval time.Duration, burst int, opts ...LimiterOption) *Limiter {
	if interval <= 0 {
		interval = DefaultInterval
	}
	if burst < 1 {
		burst = DefaultBurst
	}
	l := &Limiter{
		buckets:  make(map[string]*bucket),
		interval: interval,
		burst:    float64(burst),
		maxKeys:  DefaultMaxKeys,
		now:      time.Now,
	}
	for _, o := range opts {
		o(l)
	}
	return l
}

// refilled returns b's token count at now, capped at burst. A clock that moved
// backwards mints nothing.
func (l *Limiter) refilled(b *bucket, now time.Time) float64 {
	elapsed := now.Sub(b.last)
	if elapsed <= 0 {
		return b.tokens
	}
	t := b.tokens + float64(elapsed)/float64(l.interval)
	if t > l.burst {
		t = l.burst
	}
	return t
}

// Interval is the refill interval: one token per Interval.
func (l *Limiter) Interval() time.Duration { return l.interval }

// Burst is the bucket size.
func (l *Limiter) Burst() int { return int(l.burst) }

// Allow consumes a token for key. On refusal it reports how long to wait.
// It is safe for concurrent use.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	ok, wait, _ := l.AllowGrant(key)
	return ok, wait
}

// AllowGrant is Allow that also returns the grant number of the token it
// consumed, for RefundGrant. The number is 0 on refusal.
func (l *Limiter) AllowGrant(key string) (bool, time.Duration, uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, seen := l.buckets[key]
	if !seen {
		if len(l.buckets) >= l.maxKeys {
			l.reclaim(now)
		}
		if len(l.buckets) >= l.maxKeys {
			// Fail closed: an unbounded map is worse than a refused move.
			return false, l.interval, 0
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	} else {
		b.tokens = l.refilled(b, now)
		if now.After(b.last) {
			b.last = now
		}
	}

	if b.tokens >= 1 {
		b.tokens--
		b.grants++
		return true, 0, b.grants
	}
	missing := 1 - b.tokens
	wait := time.Duration(missing * float64(l.interval))
	if wait < time.Nanosecond {
		wait = time.Nanosecond
	}
	return false, wait, 0
}

// Refund returns the token a refused-to-send call took, for a call that ended
// before anything reached the camera. It is atomic with Allow under the same
// lock, never lifts the bucket above its burst, and does nothing for a key the
// limiter does not track (that bucket was reclaimed because it had refilled
// completely, which already is the refunded state).
func (l *Limiter) Refund(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refundLocked(key)
}

func (l *Limiter) refundLocked(key string) {
	b, ok := l.buckets[key]
	if !ok {
		return
	}
	now := l.now()
	b.tokens = l.refilled(b, now) + 1
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	if now.After(b.last) {
		b.last = now
	}
}

// RefundGrant is Refund for the grant numbered grant, and does nothing if any
// later grant has been handed out for the key. Without that check a slow call
// whose bucket refilled while it ran would, on refund, add a second token on
// top of the refilled one, and two real moves could land inside one interval.
func (l *Limiter) RefundGrant(key string, grant uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, ok := l.buckets[key]; ok && b.grants == grant {
		l.refundLocked(key)
	}
}

// reclaim drops buckets that have refilled completely. Caller holds l.mu.
func (l *Limiter) reclaim(now time.Time) {
	for k, b := range l.buckets {
		if l.refilled(b, now) >= l.burst {
			delete(l.buckets, k)
		}
	}
}

// size reports how many cameras are tracked. Test hook.
func (l *Limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
