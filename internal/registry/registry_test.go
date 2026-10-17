package registry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/testcam"
)

func cfgFor(cam *testcam.Cam, control bool) *config.Config {
	return &config.Config{
		Cameras: map[string]*config.Camera{
			"cam-a": {
				ID: "cam-a", Endpoint: cam.Endpoint(),
				Username: cam.Username(), Password: cam.Password(),
				Control: control,
			},
		},
	}
}

func TestClientIsUsable(t *testing.T) {
	cam := testcam.Start(t)
	r := New(cfgFor(cam, true))

	e, err := r.Get("cam-a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	c, err := e.Client(context.Background())
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	if _, err := c.GetProfiles(context.Background()); err != nil {
		t.Errorf("GetProfiles through registry client: %v", err)
	}
	if !e.ControlAllowed() {
		t.Error("camera opted in to control but ControlAllowed() is false")
	}
}

func TestEachCallGetsItsOwnClient(t *testing.T) {
	cam := testcam.Start(t)
	e, _ := New(cfgFor(cam, false)).Get("cam-a")
	a, err := e.Client(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.Client(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("Client() returned a shared instance; clients must be per call")
	}
}

func TestUnknownCamera(t *testing.T) {
	r := New(&config.Config{Cameras: map[string]*config.Camera{}})
	if _, err := r.Get("nope"); !errors.Is(err, ErrUnknownCamera) {
		t.Errorf("got %v, want ErrUnknownCamera", err)
	}
}

func TestListIsConfiguredOnlyAndNeedsNoNetwork(t *testing.T) {
	cfg := &config.Config{Cameras: map[string]*config.Camera{
		// Port 1 on loopback refuses connections; List must not care.
		"dead": {ID: "dead", Endpoint: "http://127.0.0.1:1/onvif/device_service"},
	}}
	list := New(cfg).List()
	if len(list) != 1 || list[0].ID != "dead" {
		t.Fatalf("List() = %+v, want the one configured camera", list)
	}
	if list[0].State != "" || list[0].Error != "" {
		t.Errorf("List() must not report reachability, got %+v", list[0])
	}
}

func TestProbeReportsReachableAndUnreachable(t *testing.T) {
	cam := testcam.Start(t)
	cfg := cfgFor(cam, false)
	cfg.Cameras["dead"] = &config.Camera{
		ID: "dead", Endpoint: "http://127.0.0.1:1/onvif/device_service",
	}

	got := map[string]Status{}
	for _, s := range New(cfg).Probe(context.Background()) {
		got[s.ID] = s
	}
	if got["cam-a"].State != "reachable" {
		t.Errorf("cam-a state = %q, want reachable", got["cam-a"].State)
	}
	if got["dead"].State != "unreachable" || got["dead"].Error == "" {
		t.Errorf("dead = %+v, want unreachable with a reason", got["dead"])
	}
}

func TestUnreachableCameraRecoversWithoutRestart(t *testing.T) {
	// Nothing is cached, so a camera that was down simply works on the next call.
	cam := testcam.Start(t)
	cfg := &config.Config{Cameras: map[string]*config.Camera{
		"cam-a": {ID: "cam-a", Endpoint: "http://127.0.0.1:1/onvif/device_service"},
	}}
	e, _ := New(cfg).Get("cam-a")
	if _, err := e.Client(context.Background()); err == nil {
		t.Fatal("expected the first call to fail")
	}

	e.setEndpointForTest(cam.Endpoint(), cam.Username(), cam.Password())
	if _, err := e.Client(context.Background()); err != nil {
		t.Errorf("next call did not recover: %v", err)
	}
}

func TestConcurrentCallsAreRaceFree(t *testing.T) {
	// Run with -race. Many goroutines ask for clients at once; each gets its
	// own, so none may share mutable state.
	cam := testcam.Start(t)
	e, err := New(cfgFor(cam, false)).Get("cam-a")
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := e.Client(context.Background())
			if err != nil {
				t.Errorf("Client: %v", err)
				return
			}
			if _, err := c.GetProfiles(context.Background()); err != nil {
				t.Errorf("GetProfiles: %v", err)
			}
		}()
	}
	wg.Wait()
}

// hangListener accepts connections and never answers. It tracks how many are
// open at once.
type hangListener struct {
	ln     net.Listener
	active atomic.Int64
	peak   atomic.Int64
	wg     sync.WaitGroup
}

func newHangListener(t *testing.T) *hangListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &hangListener{ln: ln}
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n := h.active.Add(1)
			for {
				p := h.peak.Load()
				if n <= p || h.peak.CompareAndSwap(p, n) {
					break
				}
			}
			h.wg.Add(1)
			go func() {
				defer h.wg.Done()
				defer func() { _ = c.Close() }()
				buf := make([]byte, 4096)
				for {
					if _, err := c.Read(buf); err != nil {
						h.active.Add(-1)
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); h.wg.Wait() })
	return h
}

func (h *hangListener) endpoint() string {
	return "http://" + h.ln.Addr().String() + "/onvif/device_service"
}

func codeOf(err error, id string) mcperr.Code {
	return mcperr.FromError(err, id, "test").Code
}

func TestClientErrorsClassify(t *testing.T) {
	t.Run("refused is unreachable", func(t *testing.T) {
		cfg := &config.Config{Cameras: map[string]*config.Camera{
			"d": {ID: "d", Endpoint: "http://127.0.0.1:1/onvif/device_service"},
		}}
		e, _ := New(cfg).Get("d")
		_, err := e.Client(context.Background())
		if got := codeOf(err, "d"); got != mcperr.CodeUnreachable {
			t.Errorf("code = %s (%v), want unreachable", got, err)
		}
	})
	t.Run("wrong password is auth_failed", func(t *testing.T) {
		cam := testcam.Start(t)
		cfg := cfgFor(cam, false)
		cfg.Cameras["cam-a"].Password = "definitely-wrong"
		e, _ := New(cfg).Get("cam-a")
		_, err := e.Client(context.Background())
		if err == nil {
			t.Fatal("expected failure")
		}
		if got := codeOf(err, "cam-a"); got != mcperr.CodeAuthFailed {
			t.Errorf("code = %s (%v), want auth_failed", got, err)
		}
	})
	t.Run("silent camera is timeout", func(t *testing.T) {
		h := newHangListener(t)
		cfg := &config.Config{Cameras: map[string]*config.Camera{
			"h": {ID: "h", Endpoint: h.endpoint(), TimeoutSeconds: 1},
		}}
		e, _ := New(cfg).Get("h")
		start := time.Now()
		_, err := e.Client(context.Background())
		if got := codeOf(err, "h"); got != mcperr.CodeTimeout {
			t.Errorf("code = %s (%v), want timeout", got, err)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("took %v, per-camera timeout not honoured", d)
		}
	})
}

func TestClientHonoursContext(t *testing.T) {
	t.Run("already cancelled", func(t *testing.T) {
		cam := testcam.Start(t)
		e, _ := New(cfgFor(cam, false)).Get("cam-a")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := e.Client(ctx); !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	})
	t.Run("cancelled while hung", func(t *testing.T) {
		h := newHangListener(t)
		cfg := &config.Config{Cameras: map[string]*config.Camera{
			"h": {ID: "h", Endpoint: h.endpoint(), TimeoutSeconds: 30},
		}}
		e, _ := New(cfg).Get("h")
		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(150 * time.Millisecond); cancel() }()
		start := time.Now()
		_, err := e.Client(ctx)
		if err == nil {
			t.Fatal("expected error")
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("returned after %v, want prompt return on cancel", d)
		}
	})
}

func TestProbeErrorIsScrubbedAndClassified(t *testing.T) {
	const pw = "s3cr3tpw-xyz"
	cfg := &config.Config{Cameras: map[string]*config.Camera{
		"d": {ID: "d", Endpoint: "http://admin:" + pw + "@127.0.0.1:1/onvif/device_service", Password: pw},
	}}
	r := New(cfg)
	for _, s := range append(r.Probe(context.Background()), r.List()...) {
		blob := fmt.Sprintf("%+v %#v", s, s)
		if strings.Contains(blob, pw) {
			t.Errorf("status leaks password: %s", blob)
		}
	}
	s := r.Probe(context.Background())[0]
	if s.State != StateUnreachable || s.ErrorCode != string(mcperr.CodeUnreachable) || s.Error == "" {
		t.Errorf("status = %+v, want unreachable/unreachable with message", s)
	}
}

func TestProbeNilAndEmpty(t *testing.T) {
	for name, r := range map[string]*Registry{
		"nil config":   New(nil),
		"empty config": New(&config.Config{}),
		"nil registry": nil,
		"nil camera":   New(&config.Config{Cameras: map[string]*config.Camera{"x": nil}}),
	} {
		if got := r.Probe(context.Background()); len(got) != 0 {
			t.Errorf("%s: Probe = %+v", name, got)
		}
		if got := r.List(); len(got) != 0 {
			t.Errorf("%s: List = %+v", name, got)
		}
		if _, err := r.Get("x"); !errors.Is(err, ErrUnknownCamera) {
			t.Errorf("%s: Get err = %v", name, err)
		}
	}
}

func manyCameras(endpoint string, n int, timeoutSecs int) *config.Config {
	cfg := &config.Config{Cameras: map[string]*config.Camera{}}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("cam-%02d", i)
		cfg.Cameras[id] = &config.Camera{ID: id, Endpoint: endpoint, TimeoutSeconds: timeoutSecs}
	}
	return cfg
}

func TestProbeBoundedSortedPromptOnCancel(t *testing.T) {
	h := newHangListener(t)
	r := New(manyCameras(h.endpoint(), 20, 30))

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	got := r.Probe(ctx)
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Probe took %v after ctx expiry", d)
	}
	if len(got) != 20 {
		t.Fatalf("got %d statuses, want 20", len(got))
	}
	for i, s := range got {
		if want := fmt.Sprintf("cam-%02d", i); s.ID != want {
			t.Fatalf("status %d = %s, want %s (sorted by ID)", i, s.ID, want)
		}
		if s.State != StateUnreachable || s.Error == "" {
			t.Errorf("%s = %+v, want unreachable with reason", s.ID, s)
		}
	}
	if p := h.peak.Load(); p > maxProbeInFlight || p == 0 {
		t.Errorf("peak concurrent connections = %d, want 1..%d", p, maxProbeInFlight)
	}
}

func TestProbeTwentyReachableUnderRace(t *testing.T) {
	cam := testcam.Start(t)
	cfg := &config.Config{Cameras: map[string]*config.Camera{}}
	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("cam-%02d", i)
		cfg.Cameras[id] = &config.Camera{ID: id, Endpoint: cam.Endpoint(),
			Username: cam.Username(), Password: cam.Password()}
	}
	for _, s := range New(cfg).Probe(context.Background()) {
		if s.State != StateReachable {
			t.Errorf("%s = %+v, want reachable", s.ID, s)
		}
	}
}

func TestListSortedCopiesNoPassword(t *testing.T) {
	cfg := &config.Config{Cameras: map[string]*config.Camera{
		"b": {ID: "b", Endpoint: "http://u:pw-b-secret@10.0.0.2/x", Password: "pw-b-secret"}, //nolint:gosec // fake credential for a leak test
		"a": {ID: "a", Endpoint: "http://10.0.0.1/x", Password: "pw-a-secret"},
	}}
	r := New(cfg)
	l := r.List()
	if l[0].ID != "a" || l[1].ID != "b" {
		t.Fatalf("not sorted: %+v", l)
	}
	l[0].ID, l[0].Endpoint, l[0].Control = "zzz", "mutated", true
	again := r.List()
	if len(again) != 2 || again[0].ID != "a" || again[0].Endpoint == "mutated" || again[0].Control {
		t.Errorf("registry affected by mutating List result: %+v", again)
	}
	if strings.Contains(fmt.Sprintf("%+v", again), "pw-") {
		t.Errorf("List leaks password: %+v", again)
	}
	// Mutating the source config afterwards must not reach the registry either.
	cfg.Cameras["a"].Endpoint = "http://changed/"
	if r.List()[0].Endpoint != "http://10.0.0.1/x" {
		t.Error("registry shares the config's Camera struct")
	}
}

// settleGoroutines waits for the goroutine count to fall back to at most base.
func settleGoroutines(t *testing.T, base int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		n := runtime.NumGoroutine()
		if n <= base {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			buf = buf[:runtime.Stack(buf, true)]
			t.Fatalf("goroutines = %d, want <= %d (leak)\n%s", n, base, buf)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestProbeLeaksNoGoroutines(t *testing.T) {
	cam := testcam.Start(t)
	h := newHangListener(t)
	cfg := manyCameras(h.endpoint(), 10, 1)
	for i := 0; i < 10; i++ {
		id := fmt.Sprintf("ok-%02d", i)
		cfg.Cameras[id] = &config.Camera{ID: id, Endpoint: cam.Endpoint(),
			Username: cam.Username(), Password: cam.Password()}
	}
	cfg.Cameras["dead"] = &config.Camera{ID: "dead", Endpoint: "http://127.0.0.1:1/x"}

	base := runtime.NumGoroutine()
	r := New(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	_ = r.Probe(ctx)
	_ = r.Probe(context.Background())
	settleGoroutines(t, base)
}
