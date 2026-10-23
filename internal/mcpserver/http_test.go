package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
	"github.com/0x524a/onvif-mcp/internal/testcam"
)

// newOp is New with the stdio operator as the caller, which is what the
// pre-existing tests exercise.
func newOp(reg *registry.Registry, log *slog.Logger, p *safety.Policy, opts ...Option) *mcp.Server {
	return New(reg, log, p, append([]Option{WithCallerSource(StdioOperator())}, opts...)...)
}

type guardIn struct {
	Camera string `json:"camera,omitempty"`
	Ms     int    `json:"ms,omitempty"`
}

type guardOut struct {
	OK bool `json:"ok"`
}

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) lines(t *testing.T) []map[string]any {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []map[string]any
	for _, ln := range strings.Split(strings.TrimSpace(l.b.String()), "\n") {
		if ln == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", ln)
		}
		out = append(out, m)
	}
	return out
}

// whoSource picks the caller from the request's _meta "who", so one in-memory
// session can act as several tokens. The real mapping (TokenInfo.UserID) is
// tested through the real HTTP stack in cmd/onvif-mcp.
func whoSource(_ context.Context, req mcp.Request) (safety.Caller, bool) {
	who := "tok-default"
	if p := req.GetParams(); p != nil {
		if m := p.GetMeta(); m != nil {
			if s, ok := m["who"].(string); ok {
				who = s
			}
		}
	}
	c, err := safety.RemoteCaller(who, "http")
	return c, err == nil
}

type grants map[string][]string

func (g grants) Grants(id string) []string { return g[id] }

type guardRig struct {
	cs      *mcp.ClientSession
	log     *logBuf
	running atomic.Int32
	peak    atomic.Int32
	release chan struct{}
	ctxErr  atomic.Value
}

// newGuardRig builds a bare server (no cameras) with tools named like the real
// ones, wrapped in callerContext + httpGuard, so the middleware is tested alone.
func newGuardRig(t *testing.T, o HTTPGuardOptions) *guardRig {
	t.Helper()
	r := &guardRig{log: &logBuf{}, release: make(chan struct{})}
	o.Log = slog.New(slog.NewJSONHandler(r.log, nil))
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	srv.AddReceivingMiddleware(callerContext(whoSource), httpGuard(o))
	add := func(name string, h func(ctx context.Context, in guardIn)) {
		mcp.AddTool(srv, &mcp.Tool{Name: name, Description: "x"},
			func(ctx context.Context, _ *mcp.CallToolRequest, in guardIn) (*mcp.CallToolResult, guardOut, error) {
				h(ctx, in)
				return nil, guardOut{OK: true}, nil
			})
	}
	add("camera.list", func(context.Context, guardIn) {})
	add("camera.snapshot", func(context.Context, guardIn) {})
	add("camera.discover", func(context.Context, guardIn) {})
	add("stream.inspect", func(context.Context, guardIn) {})
	add("slow", func(ctx context.Context, _ guardIn) {
		n := r.running.Add(1)
		for {
			p := r.peak.Load()
			if n <= p || r.peak.CompareAndSwap(p, n) {
				break
			}
		}
		defer r.running.Add(-1)
		select {
		case <-r.release:
		case <-ctx.Done():
			r.ctxErr.Store(struct{ error }{ctx.Err()})
		}
	})
	add("boom", func(context.Context, guardIn) { panic("boom") })
	r.cs = connect(t, srv)
	return r
}

func (r *guardRig) call(who, tool string, args any) (*mcp.CallToolResult, error) {
	return r.cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: tool, Arguments: args, Meta: mcp.Meta{"who": who},
	})
}

func toolNames(t *testing.T, r *guardRig, who string) []string {
	t.Helper()
	res, err := r.cs.ListTools(context.Background(), &mcp.ListToolsParams{Meta: mcp.Meta{"who": who}})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	return names
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func errCodeOf(res *mcp.CallToolResult) string {
	m, _ := res.StructuredContent.(map[string]any)
	e, _ := m["error"].(map[string]any)
	c, _ := e["code"].(string)
	return c
}

func TestNewWithoutACallerSourceRefusesCallsAndReads(t *testing.T) {
	cam := testcam.Start(t)
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a": {ID: "cam-a", Endpoint: cam.Endpoint(), Username: cam.Username(), Password: cam.Password(), Control: true},
	}})
	cs := connect(t, New(reg, quietLog(), testPolicy(reg, true))) // no WithCallerSource
	if _, err := cs.ListTools(context.Background(), nil); err != nil {
		t.Fatalf("tools/list must still work without a caller: %v", err)
	}
	for _, name := range []string{"camera.list", "ptz.goto_preset"} {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: map[string]any{"camera": "cam-a", "dry_run": false, "preset": "1"}})
		if err == nil {
			t.Errorf("%s with no caller: got a result %+v, want a protocol error", name, res)
		}
	}
	if _, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: safety.PolicyURI}); err == nil {
		t.Error("resources/read with no caller must be refused")
	}
}

func TestACallerSourceThatResolvesNothingIsRefused(t *testing.T) {
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	srv.AddReceivingMiddleware(callerContext(func(context.Context, mcp.Request) (safety.Caller, bool) {
		return safety.Caller{}, true // ok=true but an invalid Caller
	}))
	mcp.AddTool(srv, &mcp.Tool{Name: "x", Description: "x"},
		func(context.Context, *mcp.CallToolRequest, guardIn) (*mcp.CallToolResult, guardOut, error) {
			t.Error("handler ran without a valid caller")
			return nil, guardOut{}, nil
		})
	if _, err := connect(t, srv).CallTool(context.Background(), &mcp.CallToolParams{Name: "x"}); err == nil {
		t.Fatal("an invalid Caller must not pass")
	}
}

func TestHTTPCallersNeedsATokenInfo(t *testing.T) {
	// The in-memory transport has no TokenInfo, so HTTPCallers resolves nothing.
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	srv.AddReceivingMiddleware(callerContext(HTTPCallers()))
	mcp.AddTool(srv, &mcp.Tool{Name: "x", Description: "x"},
		func(context.Context, *mcp.CallToolRequest, guardIn) (*mcp.CallToolResult, guardOut, error) {
			t.Error("handler ran without a token")
			return nil, guardOut{}, nil
		})
	if _, err := connect(t, srv).CallTool(context.Background(), &mcp.CallToolParams{Name: "x"}); err == nil {
		t.Fatal("no TokenInfo must mean no caller")
	}
}

func TestHTTPGuardRejectsSubscriptionsListenImmediately(t *testing.T) {
	r := newGuardRig(t, HTTPGuardOptions{})
	// The SDK client cannot send the method, so drive the middleware directly.
	h := httpGuard(HTTPGuardOptions{})(func(context.Context, string, mcp.Request) (mcp.Result, error) {
		t.Fatal("subscriptions/listen reached the SDK handler")
		return nil, nil
	})
	start := time.Now()
	_, err := h(context.Background(), "subscriptions/listen", nil)
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("err=%v after %v", err, time.Since(start))
	}
	_ = r
}

func TestHTTPGuardHidesAndRefusesOptInToolsWithoutGrants(t *testing.T) {
	r := newGuardRig(t, HTTPGuardOptions{Grants: grants{"granted": {"camera.snapshot"}}})
	opt := safety.OptInTools()

	names := toolNames(t, r, "plain")
	for _, o := range opt {
		if contains(names, o) {
			t.Errorf("token without grants sees %s", o)
		}
	}
	if !contains(names, "camera.list") || !contains(names, "slow") {
		t.Errorf("default tools missing: %v", names)
	}
	// Every argument shape gets the same refusal: no camera-existence oracle.
	var first string
	for _, args := range []any{map[string]any{"camera": "exists"}, map[string]any{"camera": "no-such"}, map[string]any{}, nil} {
		for _, o := range opt {
			res, err := r.call("plain", o, args)
			if err != nil || !res.IsError || errCodeOf(res) != "blocked_by_policy" {
				t.Fatalf("%s %v: res=%+v err=%v", o, args, res, err)
			}
			txt := res.Content[0].(*mcp.TextContent).Text
			txt = strings.ReplaceAll(txt, o, "TOOL")
			if first == "" {
				first = txt
			} else if txt != first {
				t.Errorf("refusal text varies: %q vs %q", txt, first)
			}
		}
	}

	names = toolNames(t, r, "granted")
	if !contains(names, "camera.snapshot") || contains(names, "camera.discover") || contains(names, "stream.inspect") {
		t.Errorf("granted token sees %v", names)
	}
	if res, err := r.call("granted", "camera.snapshot", map[string]any{}); err != nil || res.IsError {
		t.Errorf("granted snapshot: %+v %v", res, err)
	}
	if res, _ := r.call("granted", "camera.discover", map[string]any{}); !res.IsError {
		t.Error("granted for snapshot only, but discover ran")
	}
}

func TestHTTPGuardAuditsEveryToolCallWithTheCaller(t *testing.T) {
	r := newGuardRig(t, HTTPGuardOptions{})
	_, _ = r.call("ops", "camera.list", map[string]any{})          // ok
	_, _ = r.call("ops", "camera.snapshot", map[string]any{})      // refused (no grant)
	_, _ = r.call("ops", "camera.list", map[string]any{"ms": "x"}) // schema failure: tool_error
	var got []string
	for _, l := range r.log.lines(t) {
		if l["msg"] != "tool call" {
			continue
		}
		if l["caller"] != "ops" || l["transport"] != "http" {
			t.Errorf("line lacks caller/transport: %v", l)
		}
		got = append(got, l["tool"].(string)+"="+l["outcome"].(string))
		if _, leaked := l["camera"]; leaked {
			t.Errorf("audit line carries the camera argument: %v", l)
		}
	}
	want := []string{"camera.list=ok", "camera.snapshot=refused", "camera.list=tool_error"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("audit = %v, want %v", got, want)
	}
}

func startSlow(r *guardRig, who string, n int) *sync.WaitGroup {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = r.call(who, "slow", map[string]any{})
		}()
	}
	return &wg
}

func waitRunning(t *testing.T, r *guardRig, n int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for r.running.Load() != n {
		if time.Now().After(deadline) {
			t.Fatalf("running = %d, want %d", r.running.Load(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestHTTPGuardPerTokenAndGlobalCaps(t *testing.T) {
	r := newGuardRig(t, HTTPGuardOptions{MaxCalls: 4, MaxCallsPerToken: 2})
	wg := startSlow(r, "a", 2)
	waitRunning(t, r, 2)

	res, err := r.call("a", "slow", map[string]any{})
	if err != nil || !res.IsError || errCodeOf(res) != "blocked_by_policy" {
		t.Fatalf("third call of token a: %+v %v", res, err)
	}
	e := res.StructuredContent.(map[string]any)["error"].(map[string]any)
	if e["retry_after_seconds"] != float64(1) {
		t.Errorf("retry_after_seconds = %v", e["retry_after_seconds"])
	}
	// Another token still gets through while a is at its cap.
	if res, err := r.call("b", "camera.list", map[string]any{}); err != nil || res.IsError {
		t.Fatalf("token b blocked by token a's cap: %+v %v", res, err)
	}
	// Fill the global cap with b, then c is refused too.
	wg2 := startSlow(r, "b", 2)
	waitRunning(t, r, 4)
	if res, _ := r.call("c", "camera.list", map[string]any{}); !res.IsError {
		t.Error("global cap not enforced")
	}
	close(r.release)
	wg.Wait()
	wg2.Wait()
	waitRunning(t, r, 0)
	if res, err := r.call("a", "camera.list", map[string]any{}); err != nil || res.IsError {
		t.Fatalf("slots not freed: %+v %v", res, err)
	}
}

func TestHTTPGuardBatchOf40NeverRunsMoreThan32(t *testing.T) {
	r := newGuardRig(t, HTTPGuardOptions{MaxCallsPerToken: 64}) // global default 32
	var wg sync.WaitGroup
	var refused atomic.Int32
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := r.call("tok-"+string(rune('a'+i%26)), "slow", map[string]any{})
			if err == nil && res.IsError {
				refused.Add(1)
			}
		}(i)
	}
	deadline := time.Now().Add(5 * time.Second)
	for refused.Load() < 8 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(r.release)
	wg.Wait()
	if p := r.peak.Load(); p > 32 {
		t.Fatalf("peak concurrency %d exceeds the global cap of 32", p)
	}
	if refused.Load() < 8 {
		t.Errorf("only %d of the 8 surplus calls were refused", refused.Load())
	}
}

func TestHTTPGuardFreesTheSlotOnPanic(t *testing.T) {
	r := newGuardRig(t, HTTPGuardOptions{MaxCalls: 1, MaxCallsPerToken: 1})
	for i := 0; i < 3; i++ {
		res, err := r.call("a", "boom", map[string]any{})
		if err != nil || res == nil || !res.IsError || errCodeOf(res) != "internal" {
			t.Fatalf("call %d: a panic must become an internal tool error, got %+v %v", i, res, err)
		}
		if strings.Contains(res.Content[0].(*mcp.TextContent).Text, "boom") {
			t.Error("panic value leaked into the reply")
		}
	}
	if res, err := r.call("a", "camera.list", map[string]any{}); err != nil || res.IsError {
		t.Fatalf("slot leaked after panics: %+v %v", res, err)
	}
}

func TestHTTPGuardCallDeadlineCancelsTheHandler(t *testing.T) {
	r := newGuardRig(t, HTTPGuardOptions{CallDeadline: 50 * time.Millisecond})
	start := time.Now()
	_, _ = r.call("a", "slow", map[string]any{})
	if time.Since(start) > 3*time.Second {
		t.Fatal("deadline did not cancel the handler")
	}
	if e, _ := r.ctxErr.Load().(struct{ error }); !errors.Is(e.error, context.DeadlineExceeded) {
		t.Errorf("handler ctx error = %v, want DeadlineExceeded", e.error)
	}
}

func TestNewPanicsWhenAnHTTPServerIsGivenAControlPolicy(t *testing.T) {
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a": {ID: "cam-a", Endpoint: "http://192.0.2.1/x", Control: true},
	}})
	defer func() {
		if recover() == nil {
			t.Fatal("New must panic: write tools may never be registered on HTTP")
		}
	}()
	New(reg, quietLog(), testPolicy(reg, true), WithHTTPGuard(HTTPGuardOptions{}))
}

func TestHTTPServerRegistersNoWriteToolAndPolicyIsReadOnly(t *testing.T) {
	cam := testcam.Start(t)
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a": {ID: "cam-a", Endpoint: cam.Endpoint(), Username: cam.Username(), Password: cam.Password(), Control: true},
	}})
	srv := New(reg, quietLog(), testPolicy(reg, false),
		WithCallerSource(whoSource), WithHTTPGuard(HTTPGuardOptions{Grants: grants{"g": safety.OptInTools()}}))
	cs := connect(t, srv)
	for _, who := range []string{"a", "g"} {
		res, err := cs.ListTools(context.Background(), &mcp.ListToolsParams{Meta: mcp.Meta{"who": who}})
		if err != nil {
			t.Fatal(err)
		}
		for _, tl := range res.Tools {
			if strings.HasPrefix(tl.Name, "ptz.") && !strings.HasPrefix(tl.Name, "ptz.status") && !strings.HasPrefix(tl.Name, "ptz.presets") {
				t.Errorf("write tool %s is listed over HTTP", tl.Name)
			}
		}
	}
	// Direct calls to the write tools fail: not registered.
	for _, name := range []string{"ptz.stop", "ptz.move_relative", "ptz.goto_preset"} {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Meta: mcp.Meta{"who": "g"},
			Arguments: map[string]any{"camera": "cam-a", "dry_run": false}})
		if err == nil && (res == nil || !res.IsError) {
			t.Errorf("%s ran over HTTP: %+v", name, res)
		}
	}
	// The policy resource is identical for two callers and gives no enable advice.
	read := func(who string) string {
		res, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: safety.PolicyURI, Meta: mcp.Meta{"who": who}})
		if err != nil {
			t.Fatal(err)
		}
		return res.Contents[0].Text
	}
	a, b := read("a"), read("g")
	if a != b {
		t.Error("policy resource differs between callers")
	}
	for _, bad := range []string{"--enable-control", "ptz.stop", "ptz.goto_preset", "ptz.move_relative"} {
		if strings.Contains(a, bad) {
			t.Errorf("policy mentions %q: %s", bad, a)
		}
	}
	if !strings.Contains(a, HTTPWritesUnavailable) || !strings.Contains(a, `"mode": "read-only"`) {
		t.Errorf("policy = %s", a)
	}
}

func TestOptInToolsAreRealRegisteredTools(t *testing.T) {
	srv, _ := newTestServer(t, false)
	cs := connect(t, srv)
	for _, o := range safety.OptInTools() {
		findTool(t, cs, o)
	}
}
