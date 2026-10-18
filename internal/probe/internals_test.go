package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x524A/rtspeek/pkg/rtspeek"
	"github.com/bluenviron/gortsplib/v5/pkg/base"
)

func TestNormaliseTimeout(t *testing.T) {
	for in, want := range map[time.Duration]time.Duration{
		-time.Second: defaultTimeout, 0: defaultTimeout, time.Second: time.Second,
		maxTimeout: maxTimeout, maxTimeout + time.Nanosecond: maxTimeout, time.Hour: maxTimeout,
	} {
		if got := normaliseTimeout(in); got != want {
			t.Errorf("normaliseTimeout(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestCanonicalAddrDefaultPorts(t *testing.T) {
	for in, want := range map[string]string{
		"rtsp://h/s": "h:554", "rtsps://h/s": "h:322", "rtsp://h:8554/s": "h:8554", "rtsp://[::1]/s": "[::1]:554",
	} {
		u, err := base.ParseURL(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := canonicalAddr(u); got != want {
			t.Errorf("canonicalAddr(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestPinnedDialRules(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	pinned := ln.Addr().String()
	ctx := context.Background()

	var redirected atomic.Bool
	dial := pinnedDial("cam.example:554", pinned, &redirected)
	if _, err := dial(ctx, "tcp", "other.example:554"); !errors.Is(err, errDialRefused) {
		t.Errorf("other address: err = %v, want refusal", err)
	}
	// The refusal above must not have used up the one allowed dial.
	c, err := dial(ctx, "tcp", "cam.example:554")
	if err != nil {
		t.Fatalf("the probed address was refused: %v", err)
	}
	if got := c.RemoteAddr().String(); got != pinned {
		t.Errorf("connected to %s, want the pinned %s", got, pinned)
	}
	_ = c.Close()
	if _, err := dial(ctx, "tcp", "cam.example:554"); !errors.Is(err, errDialRefused) {
		t.Errorf("second dial: err = %v, want refusal", err)
	}

	redirected.Store(true)
	fresh := pinnedDial("cam.example:554", pinned, &redirected)
	if _, err := fresh(ctx, "tcp", "cam.example:554"); !errors.Is(err, errDialRefused) {
		t.Errorf("dial after a redirect: err = %v, want refusal", err)
	}
}

// A resolver that never answers must not hold the call past timeout + slack,
// and one that panics must not take the process down.
func TestHungOrPanickingResolverIsContained(t *testing.T) {
	old := lookupNetIP
	t.Cleanup(func() { lookupNetIP = old })

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	lookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
		<-release
		return nil, errors.New("late")
	}
	start := time.Now()
	_, err := NewRTSP().Describe(context.Background(), probeWithCreds("camera.invalid:554"), 200*time.Millisecond)
	if d := time.Since(start); d > 200*time.Millisecond+guardSlack+time.Second {
		t.Errorf("returned after %v", d)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want deadline", err)
	}

	lookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) { panic("boom " + testPass) }
	_, err = NewRTSP().Describe(context.Background(), probeWithCreds("camera.invalid:554"), time.Second)
	if err == nil || !strings.Contains(err.Error(), "failed internally") {
		t.Fatalf("err = %v, want an internal failure", err)
	}
	assertNoLeak(t, err)
}

func TestWrapErrorScrubsAndBounds(t *testing.T) {
	ctx := context.Background()
	secrets := secretsOf("rtsp://operator:zqxv-unregistered@h/s")

	msg := wrapError(ctx, ctx, errors.New("bad zqxv-unregistered and operator and token=abcdef123456 here"), secrets).Error()
	for _, leak := range []string{"zqxv-unregistered", "operator", "abcdef123456"} {
		if strings.Contains(msg, leak) {
			t.Errorf("message keeps %q: %q", leak, msg)
		}
	}

	long := wrapError(ctx, ctx, errors.New(strings.Repeat("x", 5000)), nil).Error()
	if len(long) > maxErrorBytes {
		t.Errorf("message is %d bytes, want at most %d", len(long), maxErrorBytes)
	}

	if got := wrapError(ctx, ctx, errors.New("bad \x1b[31m\x00 text"), nil).Error(); strings.ContainsAny(got, "\x1b\x00") {
		t.Errorf("control characters survive: %q", got)
	}
}

func TestSecretsOfShortUsernameIsNotRegistered(t *testing.T) {
	if got := secretsOf("rtsp://ab:longenough@h/s"); len(got) != 1 || got[0] != "longenough" {
		t.Errorf("secrets = %v", got)
	}
	if got := secretsOf("rtsp://abc@h/s"); len(got) != 1 || got[0] != "abc" {
		t.Errorf("secrets = %v", got)
	}
}

// A one or two character password must not be replaced everywhere in error
// text, where it would garble unrelated words (the registry applies the same
// floor).
func TestSecretsOfShortPasswordIsNotRegistered(t *testing.T) {
	for _, u := range []string{"rtsp://operator:a@h/s", "rtsp://operator:ab@h/s"} {
		for _, s := range secretsOf(u) {
			if len(s) < 3 {
				t.Errorf("%s registers %q", u, s)
			}
		}
	}
	ctx := context.Background()
	msg := wrapError(ctx, ctx, errors.New("bad status: not found"), secretsOf("rtsp://operator:a@h/s")).Error()
	if strings.Contains(msg, "REDACTED") {
		t.Errorf("unrelated words garbled: %q", msg)
	}
	if got := secretsOf("rtsp://operator:abc@h/s"); len(got) != 2 || got[0] != "abc" {
		t.Errorf("secrets = %v", got)
	}
}

func TestSuccessReportsIndexesLatencyAndFlags(t *testing.T) {
	srv := startRaw(t, "sdp", sdpWithVideoTracks(3))
	res, err := NewRTSP().Describe(context.Background(), probeWithCreds(srv.hostPort()), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reachable || !res.DescribeOK || res.Protocol != "rtsp" || res.LatencyMs <= 0 {
		t.Errorf("result = %+v", res)
	}
	if len(res.Tracks) != 3 {
		t.Fatalf("tracks = %+v", res.Tracks)
	}
	for i, tr := range res.Tracks {
		if tr.Index != i || tr.Type != "video" || tr.Format != "H264" {
			t.Errorf("track %d = %+v", i, tr)
		}
	}
}

func TestSuccessfulProbeLeavesNoGoroutineBehind(t *testing.T) {
	addr, stop := startGortsplib(t)
	defer stop()
	// Warm up so lazily started runtime goroutines are in the baseline.
	if _, err := NewRTSP().Describe(context.Background(), "rtsp://"+addr+"/test", 3*time.Second); err != nil {
		t.Fatal(err)
	}
	goroutinesBackTo(t, runtime.NumGoroutine())
	base := runtime.NumGoroutine()
	for i := 0; i < 5; i++ {
		if _, err := NewRTSP().Describe(context.Background(), "rtsp://"+addr+"/test", 3*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	goroutinesBackTo(t, base)
}

func TestURLWithoutAHostIsInvalid(t *testing.T) {
	for _, u := range []string{"rtsp:///x", "rtsp:x", "http://h/x", "ftp://h/x"} {
		_, err := NewRTSP().Describe(context.Background(), u, time.Second)
		if !errors.Is(err, rtspeek.ErrInvalidURL) {
			t.Errorf("%s: err = %v, want ErrInvalidURL", u, err)
		}
	}
}
