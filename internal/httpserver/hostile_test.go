package httpserver

// Task 13b.7: hostile and abuse tests against the assembled server: the real
// Serve, the real middleware chain, the real SDK handler, the real mcpserver tool
// surface and a virtual camera. Each test is named for the threat.
//
// Not testable here with real sockets: the per-IP connection cap, because every
// test peer is loopback and loopback peers are exempt by design. It is covered
// with fake peer addresses in listen_test.go.

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/mcpserver"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
	"github.com/0x524a/onvif-mcp/internal/testcam"
)

type realRig struct {
	addr  string
	log   *testLog
	cam   *testcam.Cam
	srv   *Server
	token string
	fin   chan struct{}
	stop  context.CancelFunc
}

type realOpts struct {
	cameras map[string]*config.Camera
	grants  string // json fragment for the alpha entry, e.g. `,"grant":["camera.snapshot"]`
	flags   func(*Flags)
	tm      *timeouts
}

func startReal(t *testing.T, o realOpts) *realRig {
	t.Helper()
	r := &realRig{log: &testLog{}, fin: make(chan struct{})}
	r.cam = testcam.Start(t)
	cams := o.cameras
	if cams == nil {
		cams = map[string]*config.Camera{"cam1": {
			ID: "cam1", Endpoint: r.cam.Endpoint(), Username: r.cam.Username(), Password: r.cam.Password(), Control: true,
		}}
	}
	reg := registry.New(&config.Config{Cameras: cams})
	policy := safety.NewPolicy(safety.PolicyOptions{Cameras: reg, Log: slogTo(r.log)})
	store, err := ParseTokens([]byte(`{"tokens":[`+entry("alpha", tok(1), o.grants)+`]}`), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	r.token = tok(1)
	mcpSrv := mcpserver.New(reg, slogTo(r.log), policy,
		mcpserver.WithCallerSource(mcpserver.HTTPCallers()),
		mcpserver.WithHTTPGuard(mcpserver.HTTPGuardOptions{Grants: store, Log: slogTo(r.log)}))
	f := httpFlags()
	if o.flags != nil {
		o.flags(&f)
	}
	res, err := Validate(f)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Resolved: res, Tokens: store, MCP: mcpSrv, Log: slogTo(r.log), tm: o.tm})
	if err != nil {
		t.Fatal(err)
	}
	l, err := Listen(Resolved{HTTP: true, Listen: "127.0.0.1:0", Loopback: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.srv, r.addr, r.stop = s, l.Addr().String(), cancel
	go func() { _ = s.Serve(ctx, l); close(r.fin) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.fin:
		case <-time.After(10 * time.Second):
		}
	})
	return r
}

func (r *realRig) post(t *testing.T, hdr map[string]string, body string) (int, http.Header, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", "http://"+r.addr+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+r.token)
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
		} else if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

const listCall = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"camera.list","arguments":{}}}`

func (r *realRig) serving(t *testing.T) {
	t.Helper()
	if code, _, body := r.post(t, nil, listCall); code != 200 || !strings.Contains(body, "camera") {
		t.Fatalf("the server stopped serving: %d %.200s", code, body)
	}
}

func TestHostileDNSRebindingNeverReachesATool(t *testing.T) {
	r := startReal(t, realOpts{flags: func(f *Flags) { f.AllowedHosts = "cams.example"; setExplicit(f, "http-allowed-hosts") }})
	if code, _, _ := r.post(t, map[string]string{"Host": "evil.example"}, listCall); code != 403 {
		t.Errorf("foreign Host: %d", code)
	}
	if code, _, _ := r.post(t, map[string]string{"Host": "localhost.evil.example:8808"}, listCall); code != 403 {
		t.Errorf("suffix Host: %d", code)
	}
	if strings.Contains(r.log.String(), `tool=camera.list`) {
		t.Error("a tool ran for a rebinding request")
	}
	if code, _, _ := r.post(t, map[string]string{"Host": "cams.example"}, listCall); code != 200 {
		t.Errorf("an allowed proxy host was refused: %d", code)
	}
	if code, _, _ := r.post(t, map[string]string{"Host": "localhost"}, listCall); code != 200 {
		t.Errorf("loopback default refused on a loopback bind: %d", code)
	}
}

func TestHostileBrowserOriginAndPreflight(t *testing.T) {
	r := startReal(t, realOpts{})
	code, h, _ := r.post(t, map[string]string{"Origin": "http://localhost:8808"}, listCall)
	if code != 403 {
		t.Errorf("Origin: %d", code)
	}
	req, _ := http.NewRequest("OPTIONS", "http://"+r.addr+"/mcp", nil)
	req.Header.Set("Origin", "http://evil.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	for _, hh := range []http.Header{h, resp.Header} {
		for k := range hh {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") {
				t.Errorf("CORS header %s", k)
			}
		}
	}
}

func TestHostileOversizedBodies(t *testing.T) {
	r := startReal(t, realOpts{})
	pad := strings.Repeat("a", 3*MaxBodyBytes)
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"camera.list","arguments":{},"pad":"` + pad + `"}}`
	if code, _, _ := r.post(t, nil, big); code != 413 {
		t.Errorf("Content-Length oversize: %d", code)
	}
	// Chunked, no Content-Length.
	req, _ := http.NewRequest("POST", "http://"+r.addr+"/mcp", io.NopCloser(strings.NewReader(big)))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+r.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Errorf("chunked oversize: %d", resp.StatusCode)
	}
	// A lying Content-Length: the declared 10 bytes are not valid JSON-RPC, and the
	// rest is not read as a body.
	c, _ := net.Dial("tcp", r.addr)
	defer func() { _ = c.Close() }()
	_, _ = fmt.Fprintf(c, "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: 10\r\n\r\n%s", r.token, big)
	line, _ := bufio.NewReader(c).ReadString('\n')
	if !strings.Contains(line, "400") {
		t.Errorf("lying Content-Length: %q", line)
	}
	r.serving(t)
}

func TestHostileMalformedBatchesAndIDs(t *testing.T) {
	r := startReal(t, realOpts{})
	var batch []string
	for i := 0; i < 40; i++ {
		batch = append(batch, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"camera.list","arguments":{}}}`, i+1))
	}
	for name, body := range map[string]string{
		"not json":       `{`,
		"empty object":   `{}`,
		"empty batch":    `[]`,
		"batch of 40":    "[" + strings.Join(batch, ",") + "]",
		"duplicate ids":  "[" + batch[0] + "," + batch[0] + "]",
		"huge id":        `{"jsonrpc":"2.0","id":` + strings.Repeat("9", 400) + `,"method":"tools/list"}`,
		"string id":      `{"jsonrpc":"2.0","id":"` + strings.Repeat("x", 5000) + `","method":"tools/list"}`,
		"unknown method": `{"jsonrpc":"2.0","id":1,"method":"nope/nope"}`,
		"deep nesting":   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"camera.list","arguments":` + strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + `}}`,
	} {
		code, _, _ := r.post(t, nil, body)
		if code >= 500 {
			t.Errorf("%s: %d", name, code)
		}
	}
	r.serving(t)
}

func TestHostileSubscriptionsListenReturnsPromptlyAndFreesTheConnection(t *testing.T) {
	r := startReal(t, realOpts{})
	newFamily := `{"jsonrpc":"2.0","id":7,"method":"subscriptions/listen","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"c","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}},"notifications":{"toolsListChanged":true}}}`
	oldFamily := `{"jsonrpc":"2.0","id":7,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true}}}`
	for name, tc := range map[string]struct {
		hdr  map[string]string
		body string
	}{
		"2026-07-28": {map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "subscriptions/listen"}, newFamily},
		"2025-06-18": {map[string]string{"MCP-Protocol-Version": "2025-06-18"}, oldFamily},
	} {
		// One keep-alive connection: listen, then a normal call on the same socket.
		c, err := net.Dial("tcp", r.addr)
		if err != nil {
			t.Fatal(err)
		}
		br := bufio.NewReader(c)
		send := func(hdr map[string]string, body string) (int, string, time.Duration) {
			start := time.Now()
			h := "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + r.token +
				"\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\n"
			for k, v := range hdr {
				h += k + ": " + v + "\r\n"
			}
			_, _ = fmt.Fprintf(c, "%sContent-Length: %d\r\n\r\n%s", h, len(body), body)
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return resp.StatusCode, string(b), time.Since(start)
		}
		_, _, took := send(tc.hdr, tc.body)
		if took > time.Second {
			t.Errorf("%s: listen took %v", name, took)
		}
		status, body, _ := send(nil, listCall)
		if status != 200 || !strings.Contains(body, "camera") {
			t.Errorf("%s: the connection was not reusable: %d %.100s", name, status, body)
		}
		_ = c.Close()
	}
	deadline := time.Now().Add(2 * time.Second)
	for r.srv.Chain().InFlight() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := r.srv.Chain().InFlight(); n != 0 {
		t.Errorf("in-flight gauge %d after listen attempts", n)
	}
}

// countingCamera accepts connections and holds each for hold before closing it,
// counting the peak number open at once: a probe for how many tool handlers are
// talking to the camera concurrently.
type countingCamera struct {
	l          net.Listener
	open, peak atomic.Int32
}

func newCountingCamera(t *testing.T, hold time.Duration) *countingCamera {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &countingCamera{l: l}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			n := c.open.Add(1)
			for {
				p := c.peak.Load()
				if n <= p || c.peak.CompareAndSwap(p, n) {
					break
				}
			}
			go func() {
				time.Sleep(hold)
				_ = conn.Close()
				c.open.Add(-1)
			}()
		}
	}()
	t.Cleanup(func() { _ = l.Close() })
	return c
}

func TestHostileClientAbortLoopNeverExceedsTheToolCap(t *testing.T) {
	cc := newCountingCamera(t, 400*time.Millisecond)
	r := startReal(t, realOpts{cameras: map[string]*config.Camera{"cam1": {
		ID: "cam1", Endpoint: "http://" + cc.l.Addr().String() + "/onvif/device_service", Username: "u", Password: "pw-sentinel", TimeoutSeconds: 2,
	}}})
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"camera.describe","arguments":{"camera":"cam1"}}}`
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)
	for i := 0; i < 200; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "POST", "http://"+r.addr+"/mcp", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			req.Header.Set("MCP-Protocol-Version", "2025-06-18")
			req.Header.Set("Authorization", "Bearer "+r.token)
			if resp, err := http.DefaultClient.Do(req); err == nil {
				_ = resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	t.Logf("peak concurrent camera connections: %d (token cap %d)", cc.peak.Load(), mcpserver.HTTPMaxCallsPerToken)
	if cc.peak.Load() == 0 {
		t.Fatal("no tool handler ever reached the camera: the probe measured nothing")
	}
	if p := cc.peak.Load(); p > int32(mcpserver.HTTPMaxCallsPerToken) {
		t.Fatalf("peak concurrent camera connections %d exceeds the per-token tool cap %d", p, mcpserver.HTTPMaxCallsPerToken)
	}
	deadline := time.Now().Add(15 * time.Second)
	for (cc.open.Load() != 0 || r.srv.Chain().InFlight() != 0) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if cc.open.Load() != 0 || r.srv.Chain().InFlight() != 0 {
		t.Errorf("did not recover: camera conns=%d in flight=%d", cc.open.Load(), r.srv.Chain().InFlight())
	}
	// And the slots are free again.
	deadline = time.Now().Add(10 * time.Second)
	for {
		code, _, b := r.post(t, nil, listCall)
		if code == 200 && !strings.Contains(b, "too many tool calls") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tool slots never freed: %d %.200s", code, b)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestHostileUnauthenticatedConnectionsDoNotAccumulate(t *testing.T) {
	r := startReal(t, realOpts{tm: shortTimeouts()})
	var conns []net.Conn
	for i := 0; i < 20; i++ {
		c, err := net.Dial("tcp", r.addr)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	for _, c := range conns {
		if _, ok := closedWithin(c, 3*time.Second); !ok {
			t.Fatal("an idle unauthenticated connection outlived ReadHeaderTimeout")
		}
	}
	// A peer that sends one rejected request every moment cannot keep a connection.
	c, _ := net.Dial("tcp", r.addr)
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte("POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"))
	out, ok := closedWithin(c, 3*time.Second)
	if !ok || !strings.HasPrefix(out, "HTTP/1.1 401") {
		t.Fatalf("rejected request left the connection open: ok=%v %q", ok, out)
	}
}

func TestHostileSlowlorisDoesNotSlowALegitimateClient(t *testing.T) {
	r := startReal(t, realOpts{})
	var slow []net.Conn
	for i := 0; i < 50; i++ {
		c, err := net.Dial("tcp", r.addr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("POST /mcp HTTP/1.1\r\nHost: localhost\r\nX-Slow: "))
		slow = append(slow, c)
	}
	defer func() {
		for _, c := range slow {
			_ = c.Close()
		}
	}()
	start := time.Now()
	r.serving(t)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("a legitimate request took %v during a slowloris", d)
	}
}

func TestHostileTokenAndCredentialHygiene(t *testing.T) {
	r := startReal(t, realOpts{grants: `,"grant":["camera.snapshot","camera.discover","stream.inspect"]`})
	sentinel := strings.Repeat("c", 63) + "d"
	var seen strings.Builder
	record := func(code int, h http.Header, b string) {
		fmt.Fprintf(&seen, "%d %v %s\n", code, h, b)
	}
	code, h, b := r.post(t, map[string]string{"Authorization": "Bearer " + sentinel}, listCall)
	record(code, h, b)
	code, h, b = r.post(t, nil, listCall)
	record(code, h, b)
	// Every read tool, the opt-in ones included, against the virtual camera.
	prof := r.cam.ProfileToken()
	for i, tc := range []struct{ name, args string }{
		{"camera.list", `{"probe":true}`},
		{"camera.describe", `{"camera":"cam1"}`},
		{"media.profiles", `{"camera":"cam1"}`},
		{"media.stream_uri", `{"camera":"cam1","profile":"` + prof + `"}`},
		{"imaging.settings", `{"camera":"cam1"}`},
		{"ptz.status", `{"camera":"cam1","profile":"` + prof + `"}`},
		{"ptz.presets", `{"camera":"cam1","profile":"` + prof + `"}`},
		{"camera.snapshot", `{"camera":"cam1","profile":"` + prof + `"}`},
		{"stream.inspect", `{"camera":"cam1","profile":"` + prof + `"}`},
		{"camera.snapshot", `{"camera":"nope"}`},
	} {
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, i+1, tc.name, tc.args)
		code, h, b := r.post(t, nil, body)
		record(code, h, b)
		if code != 200 {
			t.Errorf("%s: %d %.200s", tc.name, code, b)
		}
	}
	pw := r.cam.Password()
	all := r.log.String() + seen.String()
	for what, secret := range map[string]string{
		"valid token": r.token, "its digest": digestOf(r.token), "presented sentinel": sentinel,
		"sentinel digest": digestOf(sentinel), "camera password": pw,
	} {
		if strings.Contains(all, secret) {
			t.Errorf("%s appears in a log, response body or header", what)
		}
	}
}

func TestHostileRequestSmugglingShapesAreRefusedByGo(t *testing.T) {
	r := startReal(t, realOpts{})
	for name, req := range map[string]string{
		"duplicate content-length": "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n12345",
		"TE and CL":                "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"bad TE":                   "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\nTransfer-Encoding: gzip, chunked, x\r\n\r\n",
	} {
		c, _ := net.Dial("tcp", r.addr)
		_, _ = fmt.Fprintf(c, req, r.token)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		line, _ := bufio.NewReader(c).ReadString('\n')
		_ = c.Close()
		// Go either refuses the shape (400/501) or normalises it (for TE plus CL it
		// drops Content-Length and closes the connection). Either way the request
		// must not succeed here: this one has no Content-Type, so the SDK says 415.
		if strings.Contains(line, " 200 ") {
			t.Errorf("%s: %q succeeded", name, line)
		}
	}
	if strings.Contains(r.log.String(), "tool call") {
		t.Error("a half-parsed request reached a tool")
	}
	r.serving(t)
}

// Step 3 of 13b.6: an 8 MiB image reply across the real chain, and a reader that
// stalls is cut at WriteTimeout.
func TestLargeReplyOverTheRealChain(t *testing.T) {
	tm := shortTimeouts()
	tm.read, tm.write = 10*time.Second, 10*time.Second
	r := startServer(t, tm)
	r.addBigTool(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"big","arguments":{"ms":8}}}`
	req, _ := http.NewRequest("POST", "http://"+r.addr+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+tok(1))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if len(b) < 8<<20 || !bytes.Contains(b[:200], []byte(`"content"`)) {
		t.Errorf("reply is %d bytes", len(b))
	}
}

func TestSlowReaderIsCutAtWriteTimeout(t *testing.T) {
	tm := shortTimeouts()
	tm.read, tm.write = 5*time.Second, 500*time.Millisecond
	r := startServer(t, tm)
	r.addBigTool(t)
	c, _ := net.Dial("tcp", r.addr)
	defer func() { _ = c.Close() }()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(4096)
	}
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"big","arguments":{"ms":8}}}`
	_, _ = c.Write([]byte(rawPost(tok(1), body)))
	// Read nothing for longer than WriteTimeout, then drain: the server must
	// have given up, so we cannot receive the whole reply.
	time.Sleep(1500 * time.Millisecond)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := io.Copy(io.Discard, c)
	if n >= 8<<20 {
		t.Errorf("a stalled reader still received the whole %d byte reply", n)
	}
}
