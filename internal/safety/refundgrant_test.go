package safety

import (
	"testing"
	"time"
)

// A slow call whose bucket refilled while it ran must not, on refund, mint a
// second token that lets two real moves land inside one interval.
func TestRefundGrantIgnoredAfterLaterGrant(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewLimiter(time.Second, 1, WithClock(func() time.Time { return now }))
	ok, _, a := l.AllowGrant("k") // call a takes the token
	if !ok {
		t.Fatal("first grant refused")
	}
	now = now.Add(1100 * time.Millisecond)  // bucket refills while a validates
	if ok, _, _ := l.AllowGrant("k"); !ok { // call b takes the refilled token
		t.Fatal("refilled token refused")
	}
	l.RefundGrant("k", a) // a ends not-sent: must not mint a token
	if ok, _ := l.Allow("k"); ok {
		t.Error("a stale refund let a third move through inside one interval")
	}
}

func TestRefundGrantRestoresWhenNobodyElseWasGranted(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewLimiter(time.Hour, 1, WithClock(func() time.Time { return now }))
	_, _, g := l.AllowGrant("k")
	l.RefundGrant("k", g)
	if ok, _ := l.Allow("k"); !ok {
		t.Error("refund of the latest grant must restore the token")
	}
}
