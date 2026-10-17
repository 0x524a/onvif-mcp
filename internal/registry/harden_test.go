package registry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/mcperr"
)

const (
	leakPW  = "S3cretPw!zz"
	leakEPW = "EndpointPw99" //nolint:gosec // fake credential for a leak test
)

func leakRegistry() *Registry {
	return New(&config.Config{Cameras: map[string]*config.Camera{
		"c": {ID: "c", Endpoint: "http://admin:" + leakEPW + "@10.0.0.9/onvif/device_service?token=QSECRET77", //nolint:gosec // fake credential for a leak test
			Username: "admin", Password: leakPW, Control: true},
	}})
}

func assertClean(t *testing.T, what, out string) {
	t.Helper()
	for _, bad := range []string{leakPW, leakEPW, "QSECRET77", "admin:"} {
		if strings.Contains(out, bad) {
			t.Errorf("%s leaks %q: %s", what, bad, out)
		}
	}
}

func TestFmtOfEntryAndRegistryNeverPrintsSecrets(t *testing.T) {
	r := leakRegistry()
	e, _ := r.Get("c")
	type wrap struct {
		E  *Entry
		V  Entry
		R  *Registry
		in struct{ E *Entry }
	}
	w := wrap{E: e, V: *e, R: r}
	w.in.E = e
	values := map[string]any{
		"*Entry":          e,
		"Entry":           *e,
		"*Registry":       r,
		"Registry":        *r,
		"entries map":     r.entries,
		"[]*Entry":        []*Entry{e},
		"[]Entry":         []Entry{*e},
		"wrapper struct":  w,
		"wrapper pointer": &w,
		"credentials":     e.cred,
	}
	for name, v := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d", "%T"} {
			assertClean(t, name+" "+verb, fmt.Sprintf(verb, v))
		}
		assertClean(t, name+" Sprint", fmt.Sprint(v))
		assertClean(t, name+" Sprintln", fmt.Sprintln(v))
	}
	if got := fmt.Sprintf("%+v", e); !strings.Contains(got, `id:"c"`) || !strings.Contains(got, "control:true") {
		t.Errorf("entry text lost its identity: %s", got)
	}
}

func TestSlogOfEntryAndRegistryNeverPrintsSecrets(t *testing.T) {
	r := leakRegistry()
	e, _ := r.Get("c")
	for name, mk := range map[string]func(*bytes.Buffer) *slog.Logger{
		"text": func(b *bytes.Buffer) *slog.Logger { return slog.New(slog.NewTextHandler(b, nil)) },
		"json": func(b *bytes.Buffer) *slog.Logger { return slog.New(slog.NewJSONHandler(b, nil)) },
	} {
		var buf bytes.Buffer
		mk(&buf).Info("x", slog.Any("entry", e), slog.Any("value", *e), slog.Any("reg", r),
			slog.Any("regv", *r), slog.Any("entries", r.entries), slog.Any("cred", e.cred),
			slog.Any("list", []*Entry{e}))
		assertClean(t, "slog "+name, buf.String())
		if !strings.Contains(buf.String(), "10.0.0.9") {
			t.Errorf("slog %s lost the scrubbed endpoint: %s", name, buf.String())
		}
	}
}

func TestTransportHasNoProxy(t *testing.T) {
	if newTransport().Proxy != nil {
		t.Error("registry transport must not use a proxy (onvif-go default has none)")
	}
}

// ProxyFromEnvironment never proxies loopback, so this uses a non-loopback
// name. It also only bites if the environment was not already cached by an
// earlier use in the process; TestTransportHasNoProxy is the reliable guard.
func TestProxyEnvDoesNotDivertCameraTraffic(t *testing.T) {
	var hits atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "")
	e, _ := New(&config.Config{Cameras: map[string]*config.Camera{
		"p": {ID: "p", Endpoint: "http://camera.example.invalid/onvif/device_service", TimeoutSeconds: 2},
	}}).Get("p")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = e.Client(ctx)
	if hits.Load() != 0 {
		t.Errorf("camera traffic reached the environment proxy %d times", hits.Load())
	}
}

func TestProbeHasOverallBudget(t *testing.T) {
	h := newHangListener(t)
	r := New(manyCameras(h.endpoint(), 17, 30))
	r.probeBudget = time.Second
	start := time.Now()
	got := r.Probe(context.Background())
	// Unbounded this is three waves of 30s.
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("Probe took %v with a 1s budget", d)
	}
	if len(got) != 17 {
		t.Fatalf("got %d statuses", len(got))
	}
	for _, s := range got {
		if s.State != StateUnreachable || s.ErrorCode != string(mcperr.CodeTimeout) {
			t.Errorf("%s = %+v, want unreachable/timeout", s.ID, s)
		}
	}
}

func TestDefaultProbeBudgetIsFifteenSeconds(t *testing.T) {
	if r := New(nil); r.probeBudget != 15*time.Second {
		t.Errorf("budget = %v", r.probeBudget)
	}
}

func TestClientErrorTextIsScrubbedAndChainSurvives(t *testing.T) {
	const pw = "pw-in-userinfo-77" //nolint:gosec // fake credential for a leak test
	cfg := &config.Config{Cameras: map[string]*config.Camera{
		"d": {ID: "d", Endpoint: "http://admin:" + pw + "@127.0.0.1:1/onvif/device_service?token=QSECRET77"}, //nolint:gosec // fake credential
	}}
	e, _ := New(cfg).Get("d")
	_, err := e.Client(context.Background())
	if err == nil {
		t.Fatal("expected failure")
	}
	for _, bad := range []string{pw, "QSECRET77", "admin:"} {
		if strings.Contains(err.Error(), bad) {
			t.Errorf("error text leaks %q: %v", bad, err)
		}
		if strings.Contains(fmt.Sprintf("%+v %#v", err, err), bad) {
			t.Errorf("formatted error leaks %q", bad)
		}
	}
	var oe *net.OpError
	if !errors.As(err, &oe) {
		t.Errorf("chain lost the *net.OpError: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Client(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is(context.Canceled) = false for %v", err)
	}
}

// FromError alone must classify a raw Client error, with no registry
// wrapper in between.
func TestRawClientErrorsClassifyThroughMcperrAlone(t *testing.T) {
	status := func(code int, loc string) string {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if loc != "" {
				w.Header().Set("Location", loc)
			}
			w.WriteHeader(code)
			if code == 404 {
				_, _ = w.Write([]byte("404 page not found"))
			}
		}))
		t.Cleanup(s.Close)
		return s.URL + "/onvif/device_service"
	}
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer tlsSrv.Close()
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer plain.Close()
	garbage, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = garbage.Close() }()
	go func() {
		for {
			c, err := garbage.Accept()
			if err != nil {
				return
			}
			// Answer only after the request arrives, so net/http reports the
			// bad status line rather than an unsolicited response.
			_, _ = c.Read(make([]byte, 4096))
			_, _ = c.Write([]byte("\x00\x01not http at all\r\n\r\n"))
			_ = c.Close()
		}
	}()
	eof, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = eof.Close() }()
	go func() {
		for {
			c, err := eof.Accept()
			if err != nil {
				return
			}
			_, _ = c.Read(make([]byte, 4096))
			_ = c.Close()
		}
	}()

	cases := []struct {
		name, endpoint string
		want           mcperr.Code
		hint           string
	}{
		{"404 at endpoint", status(404, ""), mcperr.CodeInvalidArgument, "endpoint path"},
		{"401", status(401, ""), mcperr.CodeAuthFailed, "username and password"},
		{"403", status(403, ""), mcperr.CodeAuthFailed, "username and password"},
		{"503", status(503, ""), mcperr.CodeUnreachable, "temporarily unavailable"},
		{"302", status(302, "http://elsewhere.invalid/"), mcperr.CodeInvalidArgument, "redirect"},
		{"self-signed https", tlsSrv.URL + "/onvif/device_service", mcperr.CodeInvalidArgument, "certificate"},
		{"https to plain port", "https://" + strings.TrimPrefix(plain.URL, "http://") + "/x", mcperr.CodeInvalidArgument, "http vs https"},
		{"not http", "http://" + garbage.Addr().String() + "/x", mcperr.CodeDeviceFault, "not an ONVIF"},
		{"closed on connect", "http://" + eof.Addr().String() + "/x", mcperr.CodeUnreachable, ""},
	}
	for _, c := range cases {
		e, _ := New(&config.Config{Cameras: map[string]*config.Camera{
			"x": {ID: "x", Endpoint: c.endpoint, TimeoutSeconds: 5},
		}}).Get("x")
		_, err := e.Client(context.Background())
		if err == nil {
			t.Errorf("%s: expected failure", c.name)
			continue
		}
		te := mcperr.FromError(err, "x", "test")
		if te.Code != c.want {
			t.Errorf("%s: code = %s (%v), want %s", c.name, te.Code, err, c.want)
		}
		if !strings.Contains(te.Hint, c.hint) || te.Hint == "" {
			t.Errorf("%s: hint = %q, want it to contain %q", c.name, te.Hint, c.hint)
		}
		if strings.Contains(te.Hint, "list the available tokens") {
			t.Errorf("%s: misleading token hint", c.name)
		}
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/onvif/device_service", http.StatusFound)
	}))
	defer redirector.Close()
	e, _ := New(&config.Config{Cameras: map[string]*config.Camera{
		"r": {ID: "r", Endpoint: redirector.URL + "/onvif/device_service"},
	}}).Get("r")
	if _, err := e.Client(context.Background()); err == nil {
		t.Fatal("expected failure on a 302")
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("redirect target received %d requests, want 0", n)
	}
}

func TestCancelledContextMakesNoRequest(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	e, _ := New(&config.Config{Cameras: map[string]*config.Camera{
		"c": {ID: "c", Endpoint: srv.URL + "/onvif/device_service"},
	}}).Get("c")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Client(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("%d requests with a cancelled context, want 0", n)
	}
	te := mcperr.FromError(func() error { _, err := e.Client(ctx); return err }(), "c", "x")
	if te.Code != mcperr.CodeInternal || te.Retryable || te.Hint != "the call was cancelled before the camera answered" {
		t.Errorf("cancel payload = %+v", te)
	}
}

// A probe cancelled by its caller (client cancellation, server shutdown) is
// not a statement about the camera: it must not be reported as unreachable or
// as an internal error.
func TestProbeCancelledIsNotACameraState(t *testing.T) {
	h := newHangListener(t)
	r := New(manyCameras(h.endpoint(), 3, 30))
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	got := r.Probe(ctx)
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("Probe took %v after cancellation", d)
	}
	if len(got) != 3 {
		t.Fatalf("got %d statuses", len(got))
	}
	for _, s := range got {
		if s.State != "" {
			t.Errorf("%s: cancelled probe reported state %q", s.ID, s.State)
		}
		if s.ErrorCode != ErrorCodeCancelled {
			t.Errorf("%s: error_code = %q, want %q", s.ID, s.ErrorCode, ErrorCodeCancelled)
		}
	}
}

func TestProbeCancelledBeforeStart(t *testing.T) {
	r := New(manyCameras("http://127.0.0.1:1/onvif/device_service", 2, 5))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, s := range r.Probe(ctx) {
		if s.State != "" || s.ErrorCode != ErrorCodeCancelled {
			t.Errorf("%s = %+v, want not probed / cancelled", s.ID, s)
		}
	}
}
