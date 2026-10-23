package httpserver

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *testLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *testLog) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

type rig struct {
	h     *Chain
	inner *atomic.Int32
	log   *testLog
	store *TokenStore
}

func newRig(t *testing.T, mut func(*ChainConfig)) *rig {
	t.Helper()
	r := &rig{inner: new(atomic.Int32), log: &testLog{}}
	store, err := ParseTokens([]byte(`{"tokens":[`+entry("alpha", tok(1), "")+`,`+entry("old", tok(3), `,"expires":"2026-10-01T00:00:00Z"`)+`]}`),
		func() time.Time { return fixedNow })
	if err != nil {
		t.Fatal(err)
	}
	r.store = store
	res, err := Validate(httpFlags())
	if err != nil {
		t.Fatal(err)
	}
	cfg := ChainConfig{
		Resolved: res, Tokens: store, MaxInFlight: MaxInFlight,
		Log: slog.New(slog.NewTextHandler(r.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Inner: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			r.inner.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "inner")
		}),
	}
	if mut != nil {
		mut(&cfg)
	}
	r.h = NewChain(cfg)
	return r
}

func (r *rig) do(method, target, host string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(""))
	req.Host = host
	req.RemoteAddr = "127.0.0.1:50000"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, req)
	return rec
}

func good() map[string]string { return map[string]string{"Authorization": "Bearer " + tok(1)} }

func flat(rec *httptest.ResponseRecorder) string {
	var sb strings.Builder
	sb.WriteString(rec.Result().Status + "\n")
	for _, k := range []string{"Www-Authenticate", "Content-Type", "Connection", "X-Content-Type-Options", "Retry-After"} {
		sb.WriteString(k + "=" + strings.Join(rec.Result().Header.Values(k), "|") + "\n")
	}
	sb.WriteString(rec.Body.String())
	return sb.String()
}

func TestHostileHostTable(t *testing.T) {
	r := newRig(t, nil)
	for host, want := range map[string]int{
		"localhost": 200, "LOCALHOST": 200, "localhost:8808": 200, "127.0.0.1": 200, "127.0.0.1:1": 200,
		"[::1]": 200, "[::1]:8808": 200, "[0:0:0:0:0:0:0:1]:8808": 200,
		"evil.com": 403, "localhost.evil.com": 403, "127.0.0.1.evil.com": 403, "localhost.": 403, "localhost.:8808": 403,
		"": 403, "localhost@evil.com": 403, "localhost:80@evil.com": 403, "evil.com:8808": 403,
		"[fe80::1%25eth0]": 403, "[FE80::1]": 403, "[::1%25lo]:8808": 403, "localhost:": 403, "localhost:99999": 403, "localhost:abc": 403,
		"192.0.2.1": 403, "0.0.0.0:8808": 403, " localhost": 403,
	} {
		rec := r.do("POST", "/mcp", host, good())
		if rec.Code != want {
			t.Errorf("Host %q: %d, want %d", host, rec.Code, want)
		}
		if want == 403 {
			if rec.Header().Get("Connection") != "close" {
				t.Errorf("Host %q: 403 without Connection: close", host)
			}
			if strings.Contains(rec.Body.String(), strings.TrimSpace(host)) && strings.TrimSpace(host) != "" {
				t.Errorf("Host %q reflected in the body", host)
			}
		}
	}
}

func TestOriginIsRefusedInEverySpelling(t *testing.T) {
	r := newRig(t, nil)
	for _, o := range []string{"null", "http://localhost:8808", "https://evil.example", ""} {
		before := r.inner.Load()
		req := httptest.NewRequest("POST", "/mcp", nil)
		req.Host = "localhost"
		req.Header["Origin"] = []string{o}
		req.Header.Set("Authorization", "Bearer "+tok(1))
		rec := httptest.NewRecorder()
		r.h.ServeHTTP(rec, req)
		if rec.Code != 403 || r.inner.Load() != before || rec.Header().Get("Connection") != "close" {
			t.Errorf("Origin %q: %d inner=%d conn=%q", o, rec.Code, r.inner.Load()-before, rec.Header().Get("Connection"))
		}
		for k := range rec.Header() {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") {
				t.Errorf("CORS header %s set", k)
			}
		}
		if strings.Contains(rec.Body.String(), o) && o != "" {
			t.Errorf("Origin %q reflected", o)
		}
	}
	// A preflight is just an unauthenticated OPTIONS with an Origin: 403, no CORS.
	rec := r.do("OPTIONS", "/mcp", "localhost", map[string]string{"Origin": "http://x", "Access-Control-Request-Method": "POST"})
	if rec.Code != 403 {
		t.Errorf("preflight %d", rec.Code)
	}
}

func TestMethodAndPath(t *testing.T) {
	r := newRig(t, nil)
	for target, want := range map[string]int{"/mcp": 200, "/mcp?x=1": 200, "/": 404, "/mcp/": 404, "/MCP": 404, "/healthz": 404, "/mcp/x": 404, "/metrics": 404} {
		rec := r.do("POST", target, "localhost", good())
		if rec.Code != want {
			t.Errorf("%s: %d, want %d", target, rec.Code, want)
		}
		if want == 404 && rec.Header().Get("Connection") != "close" {
			t.Errorf("%s: 404 without Connection: close", target)
		}
	}
	// "//mcp" parses as a path of "//mcp".
	req := httptest.NewRequest("POST", "http://localhost//mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok(1))
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Errorf("//mcp: %d", rec.Code)
	}
	// Non-POST methods on /mcp reach the next stage once authenticated; before
	// authentication they are 401 like everything else.
	if rec := r.do("GET", "/mcp", "localhost", nil); rec.Code != 401 {
		t.Errorf("unauthenticated GET: %d", rec.Code)
	}
}

func TestAuthenticationFailuresAreByteIdentical(t *testing.T) {
	r := newRig(t, nil)
	cases := map[string]map[string]string{
		"no header":           nil,
		"basic":               {"Authorization": "Basic dXNlcjpwYXNz"},
		"bearer alone":        {"Authorization": "Bearer"},
		"bearer empty":        {"Authorization": "Bearer "},
		"two tokens":          {"Authorization": "Bearer " + tok(1) + " " + tok(2)},
		"wrong":               {"Authorization": "Bearer " + tok(9)},
		"expired":             {"Authorization": "Bearer " + tok(3)},
		"well-formed unknown": {"Authorization": "Bearer " + tok(77)},
		"malformed":           {"Authorization": "Bearer not-a-token"},
		"uppercase":           {"Authorization": "Bearer " + strings.ToUpper(tok(11))},
		"scheme only token":   {"Authorization": tok(1)},
		"long":                {"Authorization": "Bearer " + strings.Repeat("a", 5000)},
		"token in query":      nil, // see below: query token with no header
	}
	var ref string
	for name, hdr := range cases {
		target := "/mcp"
		if name == "token in query" {
			target = "/mcp?access_token=" + tok(1) + "&token=" + tok(1)
		}
		rec := r.do("POST", target, "localhost", hdr)
		if rec.Code != 401 {
			t.Errorf("%s: %d, want 401", name, rec.Code)
			continue
		}
		got := flat(rec)
		if ref == "" {
			ref = got
		} else if got != ref {
			t.Errorf("%s: response differs from the others:\n%q\nvs\n%q", name, got, ref)
		}
	}
	for _, want := range []string{"Bearer", "close", "unauthorized\n"} {
		if !strings.Contains(ref, want) {
			t.Errorf("uniform 401 lacks %q: %q", want, ref)
		}
	}
	for _, leak := range []string{"no bearer token", "expired", "invalid"} {
		if strings.Contains(ref, leak) {
			t.Errorf("401 body carries SDK/oracle text %q", leak)
		}
	}
	if r.inner.Load() != 0 {
		t.Errorf("the inner handler ran %d times for unauthenticated requests", r.inner.Load())
	}
	// A header and a query token together: the header decides.
	rec := r.do("POST", "/mcp?access_token="+tok(1), "localhost", map[string]string{"Authorization": "Bearer " + tok(9)})
	if rec.Code != 401 {
		t.Errorf("query token rescued a bad header: %d", rec.Code)
	}
	// Duplicate Authorization headers are refused outright.
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Host = "localhost"
	req.Header["Authorization"] = []string{"Bearer " + tok(1), "Bearer " + tok(1)}
	rec2 := httptest.NewRecorder()
	r.h.ServeHTTP(rec2, req)
	if rec2.Code != 401 {
		t.Errorf("duplicate Authorization: %d", rec2.Code)
	}
}

// Every shape our stage accepts reaches the inner handler, i.e. the SDK stage
// that runs second never rejects (and so never writes its distinguishing text).
func TestSDKStageNeverWritesAResponse(t *testing.T) {
	r := newRig(t, nil)
	for _, h := range []string{
		"Bearer " + tok(1), "bearer " + tok(1), "BEARER " + tok(1), "Bearer  " + tok(1), "Bearer\t" + tok(1), " Bearer " + tok(1) + " ",
	} {
		before := r.inner.Load()
		rec := r.do("POST", "/mcp", "localhost", map[string]string{"Authorization": h})
		accepted := r.inner.Load() == before+1
		if !accepted && rec.Code != 401 {
			t.Errorf("%q: neither accepted nor our 401 (%d %q): the SDK stage wrote a response", h, rec.Code, rec.Body.String())
		}
		if rec.Code == 200 && rec.Body.String() != "inner" {
			t.Errorf("%q: body %q", h, rec.Body.String())
		}
		if rec.Code != 200 && rec.Body.String() != "unauthorized\n" {
			t.Errorf("%q: body %q", h, rec.Body.String())
		}
	}
	if r.inner.Load() == 0 {
		t.Fatal("no accepted shape reached the inner handler")
	}
}

func TestNoRejectionCallsTheStubAndNoneReflectsInput(t *testing.T) {
	r := newRig(t, nil)
	secret := "sentinel-" + tok(5)
	for _, tc := range []struct {
		host, path string
		hdr        map[string]string
	}{
		{"evil.example", "/mcp", good()},
		{"localhost", "/nope", good()},
		{"localhost", "/mcp", map[string]string{"Authorization": "Bearer " + secret}},
		{"localhost", "/mcp", map[string]string{"Authorization": "Bearer " + tok(1), "Origin": "http://" + secret}},
	} {
		rec := r.do("POST", tc.path, tc.host, tc.hdr)
		if rec.Code < 400 {
			t.Errorf("%+v accepted", tc)
		}
		if strings.Contains(rec.Body.String(), secret) || strings.Contains(rec.Body.String(), tc.host) && tc.host == "evil.example" {
			t.Errorf("body reflects input: %q", rec.Body.String())
		}
		for k, v := range rec.Header() {
			if strings.Contains(strings.Join(v, ""), secret) || strings.Contains(strings.Join(v, ""), "evil.example") {
				t.Errorf("header %s reflects input", k)
			}
		}
	}
	if r.inner.Load() != 0 {
		t.Errorf("inner ran %d times", r.inner.Load())
	}
	if strings.Contains(r.log.String(), secret) || strings.Contains(r.log.String(), tok(1)) || strings.Contains(r.log.String(), digestOf(tok(1))) {
		t.Errorf("a token or digest reached the log:\n%s", r.log.String())
	}
}

func TestDrainGate(t *testing.T) {
	r := newRig(t, nil)
	if rec := r.do("POST", "/mcp", "localhost", good()); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	r.h.Drain()
	rec := r.do("POST", "/mcp", "localhost", good())
	if rec.Code != 503 || rec.Header().Get("Connection") != "close" {
		t.Errorf("draining: %d conn=%q", rec.Code, rec.Header().Get("Connection"))
	}
}

func TestInFlightCap(t *testing.T) {
	release := make(chan struct{})
	r := newRig(t, func(c *ChainConfig) {
		c.Inner = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Query().Get("hold") != "" {
				<-release
			}
			if req.URL.Query().Get("panic") != "" {
				panic("boom")
			}
			w.WriteHeader(200)
		})
	})
	var wg sync.WaitGroup
	for i := 0; i < MaxInFlight; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r.do("POST", "/mcp?hold=1", "localhost", good()) }()
	}
	deadline := time.Now().Add(5 * time.Second)
	for r.h.InFlight() != MaxInFlight && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if r.h.InFlight() != MaxInFlight {
		t.Fatalf("in flight %d", r.h.InFlight())
	}
	rec := r.do("POST", "/mcp", "localhost", good())
	if rec.Code != 503 || rec.Header().Get("Retry-After") != "1" {
		t.Errorf("33rd request: %d retry-after=%q", rec.Code, rec.Header().Get("Retry-After"))
	}
	close(release)
	wg.Wait()
	if n := r.h.InFlight(); n != 0 {
		t.Errorf("gauge %d after completion", n)
	}
	// A panic in the handler is a fixed 500 and still frees the slot.
	rec = r.do("POST", "/mcp?panic=1", "localhost", good())
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "boom") || strings.Contains(r.log.String(), "boom") {
		t.Errorf("panic: %d %q", rec.Code, rec.Body.String())
	}
	if n := r.h.InFlight(); n != 0 {
		t.Errorf("gauge %d after a panic", n)
	}
}

func TestFailedAuthLogIsRateLimited(t *testing.T) {
	now := fixedNow
	var mu sync.Mutex
	r := newRig(t, func(c *ChainConfig) {
		c.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	})
	for i := 0; i < 1000; i++ {
		r.do("POST", "/mcp", "localhost", map[string]string{"Authorization": "Bearer " + tok(9)})
	}
	n := strings.Count(r.log.String(), "authentication failed")
	if n < 1 || n > 3 {
		t.Fatalf("%d auth-failure log lines for 1000 failures; want a handful", n)
	}
	mu.Lock()
	now = now.Add(2 * time.Second)
	mu.Unlock()
	r.do("POST", "/mcp", "localhost", map[string]string{"Authorization": "Bearer " + tok(9)})
	if !strings.Contains(r.log.String(), "suppressed=") {
		t.Errorf("no suppressed count after the window:\n%s", r.log.String())
	}
}

func TestAccessLogHasCallerAndNoSecrets(t *testing.T) {
	r := newRig(t, nil)
	r.do("POST", "/mcp?x=secretquery", "localhost", good())
	out := r.log.String()
	for _, want := range []string{"caller=alpha", "status=200", "remote="} {
		if !strings.Contains(out, want) {
			t.Errorf("access log lacks %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{tok(1), "secretquery", "Authorization", "Bearer"} {
		if strings.Contains(out, bad) {
			t.Errorf("access log contains %q", bad)
		}
	}
}

func slogTo(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
