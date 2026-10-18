// Package probe wraps rtspeek behind an interface onvif-mcp can fake.
//
// The interface exists for two reasons. rtspeek's StreamInfo is an interface
// whose only implementation is unexported with no constructor, so a fake cannot
// be built at that boundary. And rtspeek is a young dependency with no
// stability guarantee, so keeping it behind a narrow port keeps it swappable.
//
// The real prober treats the stream server as hostile. Output is bounded
// (track count, string length, dimensions, latency), the call always returns
// within the timeout plus a small slack, nothing is written to stdout or
// stderr (stdout is the JSON-RPC channel), and no error it returns contains the
// URL or its userinfo.
package probe

import (
	"context"
	"errors"
	"math"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/0x524A/rtspeek/pkg/rtspeek"

	"github.com/0x524a/onvif-mcp/internal/redact"
)

// Bounds applied to every Result the real prober returns.
const (
	// MaxTracks caps the tracks reported from one DESCRIBE.
	MaxTracks = 32
	// MaxStringBytes caps every string field, in bytes.
	MaxStringBytes = 64
	// MaxDimension caps a reported width or height.
	MaxDimension = 65535

	defaultTimeout = 10 * time.Second
	maxTimeout     = 60 * time.Second
	// guardSlack is how long past the timeout the outer guard waits for
	// rtspeek before giving up on it.
	guardSlack = 500 * time.Millisecond
	// maxErrorBytes bounds the error text taken from the library.
	maxErrorBytes = 512
)

// Track is one media track, reduced to what an agent needs.
type Track struct {
	Index  int    `json:"index"`
	Type   string `json:"type"`
	Format string `json:"format,omitempty"`
	Width  int    `json:"width,omitempty"`
	Height int    `json:"height,omitempty"`
}

// Result is a stream probe outcome.
type Result struct {
	Reachable  bool    `json:"reachable"`
	DescribeOK bool    `json:"describe_ok"`
	Protocol   string  `json:"protocol,omitempty"`
	LatencyMs  float64 `json:"latency_ms"`
	Tracks     []Track `json:"tracks"`
}

// Prober performs an RTSP OPTIONS + DESCRIBE handshake.
type Prober interface {
	Describe(ctx context.Context, rtspURL string, timeout time.Duration) (*Result, error)
}

type rtspeekProber struct{}

// NewRTSPeek returns a Prober backed by rtspeek.DescribeStream
// (rtspeek pkg/rtspeek/client.go). A non-positive timeout means 10s; it is
// capped at 60s.
func NewRTSPeek() Prober { return rtspeekProber{} }

type outcome struct {
	info rtspeek.StreamInfo
	err  error
}

func (rtspeekProber) Describe(ctx context.Context, rtspURL string, timeout time.Duration) (*Result, error) {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if timeout > maxTimeout {
		timeout = maxTimeout
	}
	secrets := secretsOf(rtspURL)

	// A fresh context linked only by cancellation: values from the caller are
	// dropped, so rtspeek's debug-trace switch (a context value) can never be
	// turned on from outside.
	cctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	stop := context.AfterFunc(ctx, cancel)
	defer stop()

	done := make(chan outcome, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- outcome{err: errors.New("stream probe failed internally")}
			}
		}()
		si, err := rtspeek.DescribeStream(cctx, rtspURL, timeout)
		done <- outcome{info: si, err: err}
	}()

	guard := time.NewTimer(timeout + guardSlack)
	defer guard.Stop()

	var o outcome
	select {
	case o = <-done:
	case <-guard.C:
		return nil, newError("stream probe timed out", context.DeadlineExceeded)
	}

	if o.err != nil {
		return nil, wrapError(ctx, cctx, o.err, secrets)
	}
	if o.info == nil {
		return nil, errors.New("stream probe returned no data")
	}
	out := &Result{
		Reachable:  o.info.IsReachable(),
		DescribeOK: o.info.IsDescribeSucceeded(),
		Protocol:   o.info.GetProtocolName(),
		LatencyMs:  o.info.LatencyMs(),
	}
	for i, m := range o.info.GetMedias() {
		if i >= MaxTracks {
			break
		}
		tr := Track{Index: m.Index, Type: m.Type, Format: m.Format}
		if m.Resolution != nil {
			tr.Width, tr.Height = m.Resolution.Width, m.Resolution.Height
		}
		out.Tracks = append(out.Tracks, tr)
	}
	return Bound(out), nil
}

// Bound returns a copy of r that is safe to hand to an agent: at most
// MaxTracks tracks, strings clipped and stripped of control characters,
// dimensions in [0, MaxDimension], and a finite non-negative latency.
func Bound(r *Result) *Result {
	if r == nil {
		return nil
	}
	out := &Result{
		Reachable:  r.Reachable,
		DescribeOK: r.DescribeOK,
		Protocol:   clean(r.Protocol),
		LatencyMs:  r.LatencyMs,
		Tracks:     []Track{},
	}
	if math.IsNaN(out.LatencyMs) || math.IsInf(out.LatencyMs, 0) || out.LatencyMs < 0 {
		out.LatencyMs = 0
	}
	for i, t := range r.Tracks {
		if i >= MaxTracks {
			break
		}
		out.Tracks = append(out.Tracks, Track{
			Index:  t.Index,
			Type:   clean(t.Type),
			Format: clean(t.Format),
			Width:  dim(t.Width),
			Height: dim(t.Height),
		})
	}
	return out
}

func dim(n int) int {
	switch {
	case n < 0:
		return 0
	case n > MaxDimension:
		return MaxDimension
	}
	return n
}

// clean removes control, format and invalid characters, then clips to
// MaxStringBytes without splitting a rune.
func clean(s string) string {
	if len(s) > 4*MaxStringBytes {
		s = s[:4*MaxStringBytes]
	}
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 {
			return -1
		}
		return r
	}, s)
	for len(s) > MaxStringBytes {
		_, n := utf8.DecodeLastRuneInString(s[:MaxStringBytes])
		cut := MaxStringBytes
		if !utf8.ValidString(s[:cut]) {
			cut -= n
		}
		s = s[:cut]
	}
	return s
}

// secretsOf extracts the literal userinfo parts of rawURL so they can be
// removed from library error text even when no URL-shaped substring survives.
func secretsOf(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil || u.User == nil {
		return nil
	}
	var s []string
	if p, ok := u.User.Password(); ok && p != "" {
		s = append(s, p)
	}
	if n := u.User.Username(); len(n) >= 3 {
		s = append(s, n)
	}
	return s
}

// sentinels are the error identities downstream classification relies on.
// They are re-attached by identity, never by carrying the library's error
// chain, which can hold text derived from the URL.
var sentinels = []error{rtspeek.ErrInvalidURL, context.DeadlineExceeded, context.Canceled}

type probeError struct {
	msg   string
	kinds []error
}

func (e *probeError) Error() string   { return e.msg }
func (e *probeError) Unwrap() []error { return e.kinds }

func newError(msg string, kinds ...error) error { return &probeError{msg: msg, kinds: kinds} }

// wrapError converts a library error into one whose text carries no URL and
// no credential. The wording keeps the substrings mcperr.FromStreamError
// classifies on (it reuses rtspeek's text classifier), and the timeout and
// cancellation paths are normalised because rtspeek's own timeout text
// ("operation timed out") is not recognised by that classifier.
func wrapError(caller, probe context.Context, err error, secrets []string) error {
	switch {
	case caller.Err() != nil:
		return newError("stream probe canceled: "+caller.Err().Error(), caller.Err())
	case errors.Is(err, context.DeadlineExceeded) || probe.Err() != nil ||
		strings.Contains(strings.ToLower(err.Error()), "timed out"):
		return newError("stream probe timed out: context deadline exceeded", context.DeadlineExceeded)
	}
	msg := err.Error()
	if len(msg) > maxErrorBytes {
		msg = msg[:maxErrorBytes]
	}
	for _, s := range secrets {
		msg = strings.ReplaceAll(msg, s, "REDACTED")
	}
	msg = clean2(redact.Scrub(msg))
	var kinds []error
	for _, k := range sentinels {
		if errors.Is(err, k) {
			kinds = append(kinds, k)
		}
	}
	return newError(msg, kinds...)
}

// clean2 is clean with a larger bound, for error text.
func clean2(s string) string {
	s = strings.ToValidUTF8(s, "")
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}

// FakeProber returns a canned result. Exported for use in other packages' tests.
type FakeProber struct {
	Result *Result
	Err    error
}

// Describe returns the canned result or error.
func (f FakeProber) Describe(context.Context, string, time.Duration) (*Result, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return f.Result, nil
}
