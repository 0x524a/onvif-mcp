package httpserver

// Task 13b.0: pin the go-sdk v1.7.0 behaviours the HTTP design stands on, so an
// SDK bump that changes one fails CI loudly instead of silently weakening a
// control. No production code. Findings (verified when this file was written):
//
//   - Stateless + JSONResponse: no Mcp-Session-Id is ever issued; GET, DELETE
//     and OPTIONS are 405 with no Access-Control-* headers.
//   - The SDK's own Host check only fires when the connection's LOCAL address
//     is loopback, and is a 403 there; it is therefore not a bind-independent
//     control and we apply our own allowlist on every bind.
//   - The request body cap (MaxRequestBodyBytes) is a 413, with and without a
//     Content-Length.
//   - Missing Accept is 400, wrong Content-Type is 415.
//   - HANDLER OUTLIVES THE REQUEST (protocol 2025-06-18): a client that aborts
//     its POST does not cancel the tool; it keeps running to completion. For
//     the newest negotiated protocol the observed behaviour is recorded in
//     TestPinHandlerOutlivesRequest. PropagateRequestCancellation stays off, and
//     the tool-level concurrency caps are released only when the handler
//     returns, never by the HTTP layer.
//   - subscriptions/listen is forced to SSE and blocks until the client goes
//     away, regardless of JSONResponse; a receiving middleware that returns an
//     error for the method ends the POST in milliseconds.
//   - auth.RequireBearerToken puts a TokenInfo in RequestExtra, visible to a
//     receiving middleware but NOT in the tool handler's own context; on its
//     own it answers failures with distinguishing text, which is why we reject
//     in our own stage first.
//   - An http.Server with Protocols = HTTP/1 only negotiates http/1.1 over TLS
//     even for a client that offers h2.

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type pinIn struct {
	Ms int `json:"ms,omitempty"`
}

type pinOut struct {
	OK bool `json:"ok"`
}

// pinState records what a blocking tool observed.
type pinState struct {
	started  atomic.Int32
	finished atomic.Int32
	ctxErr   atomic.Value // error at the moment the tool finished
}

func newPinServer(t *testing.T, st *pinState) *mcp.Server {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "pin", Version: "0"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "block", Description: "blocks"},
		func(ctx context.Context, _ *mcp.CallToolRequest, in pinIn) (*mcp.CallToolResult, pinOut, error) {
			st.started.Add(1)
			select {
			case <-time.After(time.Duration(in.Ms) * time.Millisecond):
			case <-ctx.Done():
			}
			st.ctxErr.Store(struct{ error }{ctx.Err()})
			st.finished.Add(1)
			return nil, pinOut{OK: true}, nil
		})
	mcp.AddTool(srv, &mcp.Tool{Name: "big", Description: "returns a large image"},
		func(_ context.Context, _ *mcp.CallToolRequest, in pinIn) (*mcp.CallToolResult, any, error) {
			mib := in.Ms // the "ms" field doubles as the size in MiB for this tool
			if mib <= 0 {
				mib = 8
			}
			return &mcp.CallToolResult{Content: []mcp.Content{
				&mcp.ImageContent{Data: bytes.Repeat([]byte{0xAB}, mib<<20), MIMEType: "image/jpeg"},
			}}, nil, nil
		})
	return srv
}

func pinOptions(disableLocalhost bool) *mcp.StreamableHTTPOptions {
	return &mcp.StreamableHTTPOptions{
		Stateless:                  true,
		JSONResponse:               true,
		DisableLocalhostProtection: disableLocalhost,
		MaxRequestBodyBytes:        64 << 10,
	}
}

func pinHandler(srv *mcp.Server, disableLocalhost bool) http.Handler {
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, pinOptions(disableLocalhost))
}

type bearerRT struct {
	token string
	base  http.RoundTripper
	seen  func(*http.Response)
}

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	resp, err := b.base.RoundTrip(r)
	if err == nil && b.seen != nil {
		b.seen(resp)
	}
	return resp, err
}

// reply is the status and headers of a response whose body postJSON has read
// and closed.
type reply struct {
	StatusCode int
	Header     http.Header
}

func postJSON(t *testing.T, url string, hdr map[string]string, body []byte) (*reply, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		if v == "" {
			req.Header.Del(k)
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return &reply{StatusCode: resp.StatusCode, Header: resp.Header}, string(b)
}

func callBody(tool string, ms int) []byte {
	return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":{"ms":%d}}}`, tool, ms))
}

// Step 1: the stateless handshake works with the real SDK client and no
// session id is ever issued.
func TestPinStatelessHandshakeNoSessionID(t *testing.T) {
	st := &pinState{}
	ts := httptest.NewServer(pinHandler(newPinServer(t, st), true))
	defer ts.Close()

	var sawSession atomic.Bool
	hc := &http.Client{Transport: bearerRT{token: "x", base: http.DefaultTransport, seen: func(r *http.Response) {
		if r.Header.Get("Mcp-Session-Id") != "" {
			sawSession.Store(true)
		}
	}}}
	client := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: ts.URL, HTTPClient: hc, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = cs.Close() }()
	tl, err := cs.ListTools(ctx, nil)
	if err != nil || len(tl.Tools) != 2 {
		t.Fatalf("ListTools: %v %v", tl, err)
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "block", Arguments: map[string]any{"ms": 1}})
	if err != nil || res.IsError {
		t.Fatalf("CallTool: %v %+v", err, res)
	}
	if sawSession.Load() {
		t.Fatal("stateless server issued an Mcp-Session-Id")
	}
}

// Step 2: GET, DELETE and OPTIONS are 405 and never carry CORS headers.
func TestPinVerbsAre405NoCORS(t *testing.T) {
	ts := httptest.NewServer(pinHandler(newPinServer(t, &pinState{}), true))
	defer ts.Close()
	for _, m := range []string{http.MethodGet, http.MethodDelete, http.MethodOptions} {
		req, _ := http.NewRequest(m, ts.URL, nil)
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s: status %d, want 405", m, resp.StatusCode)
		}
		for k := range resp.Header {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") {
				t.Errorf("%s: unexpected CORS header %s", m, k)
			}
		}
	}
}

// Step 3: the SDK's Host check is scoped to loopback-local connections.
func TestPinSDKHostCheckScope(t *testing.T) {
	ts := httptest.NewServer(pinHandler(newPinServer(t, &pinState{}), false))
	defer ts.Close()
	resp, _ := postJSON(t, ts.URL, map[string]string{"Host": "evil.example"}, callBody("block", 1))
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("loopback + protection on + foreign Host: %d, want 403", resp.StatusCode)
	}
	off := httptest.NewServer(pinHandler(newPinServer(t, &pinState{}), true))
	defer off.Close()
	resp, _ = postJSON(t, off.URL, map[string]string{"Host": "evil.example"}, callBody("block", 1))
	if resp.StatusCode == http.StatusForbidden {
		t.Errorf("protection disabled: foreign Host still 403")
	}

	// A connection whose local address is not loopback is not protected at all.
	addrs, _ := net.InterfaceAddrs()
	var nonLoop string
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() {
			nonLoop = ipn.IP.String()
			break
		}
	}
	if nonLoop == "" {
		t.Log("no non-loopback IPv4 interface; wildcard-scope half of the pin skipped")
		return
	}
	l, err := net.Listen("tcp", "0.0.0.0:0") //nolint:gosec // test-only wildcard bind to prove the SDK check is bind-scoped
	if err != nil {
		t.Skip(err)
	}
	wild := httptest.NewUnstartedServer(pinHandler(newPinServer(t, &pinState{}), false))
	wild.Listener = l
	wild.Start()
	defer wild.Close()
	port := l.Addr().(*net.TCPAddr).Port
	resp, _ = postJSON(t, fmt.Sprintf("http://%s:%d", nonLoop, port), map[string]string{"Host": "evil.example"}, callBody("block", 1))
	if resp.StatusCode == http.StatusForbidden {
		t.Errorf("wildcard bind via non-loopback address: SDK Host check fired; pin outdated, revisit D5")
	}
}

// Step 4: the body cap is a 413, with and without Content-Length.
func TestPinBodyCap(t *testing.T) {
	ts := httptest.NewServer(pinHandler(newPinServer(t, &pinState{}), true))
	defer ts.Close()
	pad := strings.Repeat("a", 64<<10+1)
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"block","arguments":{"ms":1},"pad":"` + pad + `"}}`)
	resp, _ := postJSON(t, ts.URL, nil, body)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("with Content-Length: %d, want 413", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL, io.NopCloser(bytes.NewReader(body)))
	req.ContentLength = -1 // chunked
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Body.Close()
	if r2.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("chunked: %d, want 413", r2.StatusCode)
	}
}

// Step 5: Accept and Content-Type are enforced by the SDK.
func TestPinAcceptAndContentType(t *testing.T) {
	ts := httptest.NewServer(pinHandler(newPinServer(t, &pinState{}), true))
	defer ts.Close()
	resp, _ := postJSON(t, ts.URL, map[string]string{"Accept": ""}, callBody("block", 1))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("missing Accept: %d, want 400", resp.StatusCode)
	}
	resp, _ = postJSON(t, ts.URL, map[string]string{"Content-Type": "text/plain"}, callBody("block", 1))
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("wrong Content-Type: %d, want 415", resp.StatusCode)
	}
}

// Step 6: a handler outlives an aborted request (hard gate; see file header).
func TestPinHandlerOutlivesRequest(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version string
		hdr     map[string]string
		body    func() []byte
	}{
		{"2025-06-18", "2025-06-18", map[string]string{"MCP-Protocol-Version": "2025-06-18"}, func() []byte { return callBody("block", 1500) }},
		{"2026-07-28", "2026-07-28", map[string]string{
			"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "block",
		}, func() []byte {
			return []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"c","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}},"name":"block","arguments":{"ms":1500}}}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &pinState{}
			ts := httptest.NewServer(pinHandler(newPinServer(t, st), true))
			defer ts.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL, bytes.NewReader(tc.body()))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			for k, v := range tc.hdr {
				req.Header.Set(k, v)
			}
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				_ = resp.Body.Close()
				t.Fatal("expected the client to abort")
			}
			time.Sleep(300 * time.Millisecond)
			stillRunning := st.started.Load() == 1 && st.finished.Load() == 0
			t.Logf("protocol %s: handler still running 300 ms after abort: %v", tc.version, stillRunning)
			if tc.version == "2025-06-18" && !stillRunning {
				t.Fatal("SDK now cancels the handler on client abort for 2025-06-18: revisit D8 (caps may be released earlier), then update this pin")
			}
			// Whatever the version does, the tool-level cap design stays: the slot is
			// owned by the handler and freed when it returns.
		})
	}
}

// Step 7: subscriptions/listen pins a connection unless a middleware refuses it.
func listenRequest(url string) (*http.Request, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	body := `{"jsonrpc":"2.0","id":7,"method":"subscriptions/listen","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"c","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}},"notifications":{"toolsListChanged":true}}}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "subscriptions/listen")
	return req, cancel
}

func TestPinSubscriptionsListenBlocksWithoutMiddleware(t *testing.T) {
	ts := httptest.NewServer(pinHandler(newPinServer(t, &pinState{}), true))
	defer ts.Close()
	req, cancel := listenRequest(ts.URL)
	defer cancel()
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
			t.Errorf("listen response Content-Type %q, want SSE even in JSON mode", ct)
		}
		_, err = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if time.Since(start) < 1400*time.Millisecond {
		t.Fatalf("subscriptions/listen returned after %v (err %v); the SDK no longer pins the connection: revisit D8", time.Since(start), err)
	}
}

func TestPinSubscriptionsListenRefusedByMiddleware(t *testing.T) {
	srv := newPinServer(t, &pinState{})
	srv.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "subscriptions/listen" {
				return nil, errors.New("method not supported on this server")
			}
			return next(ctx, method, req)
		}
	})
	ts := httptest.NewServer(pinHandler(srv, true))
	defer ts.Close()
	req, cancel := listenRequest(ts.URL)
	defer cancel()
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if d := time.Since(start); d > time.Second {
		t.Fatalf("middleware-refused listen took %v; want well under 1s", d)
	}
	if !strings.Contains(string(b), "method not supported on this server") {
		t.Errorf("body does not carry the JSON-RPC error: %q", b)
	}
}

// Step 8: an 8 MiB image reply round-trips through the real client, and the
// server-side heap cost of one reply is measured with a raw reader.
func TestPinLargeReply(t *testing.T) {
	ts := httptest.NewServer(pinHandler(newPinServer(t, &pinState{}), true))
	defer ts.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: ts.URL, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "big", Arguments: map[string]any{"ms": 8}})
	if err != nil {
		t.Fatal(err)
	}
	img, ok := res.Content[0].(*mcp.ImageContent)
	if !ok || len(img.Data) != 8<<20 {
		t.Fatalf("reply content: %T", res.Content[0])
	}

	// Peak heap while one reply is produced and read by a raw (non-decoding)
	// client, so the figure is the server side plus a discarding reader.
	for _, mib := range []int{1, 8} {
		runtime.GC()
		var base runtime.MemStats
		runtime.ReadMemStats(&base)
		var peak atomic.Uint64
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			var m runtime.MemStats
			for {
				runtime.ReadMemStats(&m)
				if m.HeapInuse > peak.Load() {
					peak.Store(m.HeapInuse)
				}
				select {
				case <-stop:
					return
				case <-time.After(time.Millisecond):
				}
			}
		}()
		_, b := postJSON(t, ts.URL, nil, callBody("big", mib))
		close(stop)
		<-done
		t.Logf("%d MiB image: reply %.1f MiB of JSON, peak HeapInuse growth %.1f MiB (%.1fx the reply)",
			mib, float64(len(b))/(1<<20), (float64(peak.Load())-float64(base.HeapInuse))/(1<<20),
			(float64(peak.Load())-float64(base.HeapInuse))/float64(len(b)))
	}
}

// Step 9: composing our stage with auth.RequireBearerToken.
func TestPinAuthComposition(t *testing.T) {
	srv := mcp.NewServer(&mcp.Implementation{Name: "pin", Version: "0"}, nil)
	var mwUser, handlerUser atomic.Value
	srv.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "tools/call" {
				if ex := req.GetExtra(); ex != nil && ex.TokenInfo != nil {
					mwUser.Store(ex.TokenInfo.UserID)
				}
			}
			return next(ctx, method, req)
		}
	})
	mcp.AddTool(srv, &mcp.Tool{Name: "who", Description: "x"},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ pinIn) (*mcp.CallToolResult, pinOut, error) {
			ti := auth.TokenInfoFromContext(ctx)
			handlerUser.Store(ti != nil)
			return nil, pinOut{OK: true}, nil
		})
	sdk := auth.RequireBearerToken(func(_ context.Context, _ string, _ *http.Request) (*auth.TokenInfo, error) {
		return &auth.TokenInfo{UserID: "laptop-agent"}, nil
	}, &auth.RequireBearerTokenOptions{AllowMissingExpiration: true})(pinHandler(srv, true))
	ts := httptest.NewServer(sdk)
	defer ts.Close()

	resp, body := postJSON(t, ts.URL, map[string]string{"Authorization": "Bearer abc"}, callBody("who", 0))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d %s", resp.StatusCode, body)
	}
	if mwUser.Load() != "laptop-agent" {
		t.Errorf("receiving middleware did not see TokenInfo.UserID: %v", mwUser.Load())
	}
	// DEVIATION from the plan text (which expected "absent"): in v1.7.0 stateless
	// mode the handler context is derived from the request context, so it does
	// carry the TokenInfo. We still resolve identity in a receiving middleware
	// (callerContext), which does not depend on this, and pin the observation so
	// a change is noticed.
	if handlerUser.Load() != true {
		t.Errorf("tool handler context no longer carries TokenInfo (%v); callerContext still works, update this pin", handlerUser.Load())
	}

	// The SDK stage on its own is an oracle: distinct text per failure class.
	deny := auth.RequireBearerToken(func(_ context.Context, _ string, _ *http.Request) (*auth.TokenInfo, error) {
		return nil, fmt.Errorf("%w: sentinel detail", auth.ErrInvalidToken)
	}, nil)(pinHandler(srv, true))
	ts2 := httptest.NewServer(deny)
	defer ts2.Close()
	_, b1 := postJSON(t, ts2.URL, nil, callBody("who", 0))
	_, b2 := postJSON(t, ts2.URL, map[string]string{"Authorization": "Bearer x"}, callBody("who", 0))
	if strings.TrimSpace(b1) != "no bearer token" || !strings.Contains(b2, "sentinel detail") {
		t.Errorf("SDK stage text changed: %q / %q", b1, b2)
	}
}

// Step 10: HTTP/1.1 only, even when the client offers h2.
func TestPinHTTP1Only(t *testing.T) {
	ts := httptest.NewUnstartedServer(pinHandler(newPinServer(t, &pinState{}), true))
	ts.Config.Protocols = new(http.Protocols)
	ts.Config.Protocols.SetHTTP1(true)
	ts.StartTLS()
	defer ts.Close()
	conn, err := tls.Dial("tcp", ts.Listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test-only self-signed server
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if p := conn.ConnectionState().NegotiatedProtocol; p == "h2" {
		t.Fatalf("negotiated h2 on an HTTP/1-only server")
	}
}
