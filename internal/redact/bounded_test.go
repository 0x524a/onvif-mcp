package redact

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestScrubBoundedIsFastOnHugeInput(t *testing.T) {
	for _, big := range []string{
		strings.Repeat("a:b@", 2_500_000),
		strings.Repeat("password=x ", 1_000_000),
		strings.Repeat("é", 5_000_000),
	} {
		t0 := time.Now()
		got := ScrubBounded(big, 64, "...")
		if d := time.Since(t0); d > 500*time.Millisecond {
			t.Errorf("took %v on %d bytes", d, len(big))
		}
		if len(got) > 64 || !utf8.ValidString(got) || !strings.HasSuffix(got, "...") {
			t.Errorf("got %q", got)
		}
	}
}

func TestScrubBoundedKeepsShortTextAndMarksEveryCut(t *testing.T) {
	if got := ScrubBounded("hello", 64, "..."); got != "hello" {
		t.Errorf("short text changed: %q", got)
	}
	if got := ScrubBounded(strings.Repeat("x", 200), 64, "..."); len(got) != 64 || !strings.HasSuffix(got, "...") {
		t.Errorf("cut text: %q", got)
	}
	if got := ScrubBounded(strings.Repeat("x", 100_000), 64, "…"); len(got) > 64 || !strings.HasSuffix(got, "…") {
		t.Errorf("cut huge text: %q", got)
	}
}

// A registered secret that straddles the cut must not come out whole or as a
// fragment, even when scrubbing the earlier occurrences shrinks the text so
// that the cut region lands inside the output window.
func TestScrubBoundedNeverEmitsAFragmentOfASecretAtTheCut(t *testing.T) {
	secret := "QzXvBnMkLpOiUyTrEwAs" + strings.Repeat("0123456789", 8)
	if !RegisterSecret(secret) {
		t.Fatal("register")
	}
	const limit = 200
	P, L := boundedPrefix(limit), len(secret)
	for off := 1; off < L; off += 3 {
		c := (P - off) / L
		head := strings.Repeat(secret, c)
		in := head + strings.Repeat(" ", P-off-len(head)) + secret + secret
		got := ScrubBounded(in, limit, "...")
		if off >= 6 && strings.Contains(got, secret[:6]) {
			t.Fatalf("off %d: the secret's first bytes leaked in %q", off, got)
		}
		if !strings.HasSuffix(got, "...") {
			t.Fatalf("off %d: no ellipsis on a cut result: %q", off, got)
		}
	}
}
