package httpserver

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type srvRig struct {
	s      *Server
	addr   string
	fin    chan struct{}
	err    error
	cancel context.CancelFunc
	base   context.Context
	cb     context.CancelFunc
	inTool atomic.Int32
	hold   chan struct{}
	log    *testLog
}

func shortTimeouts() *timeouts {
	return &timeouts{readHeader: 300 * time.Millisecond, read: 600 * time.Millisecond, idle: 300 * time.Millisecond,
		write: 5 * time.Second, shutdown: 400 * time.Millisecond, grace: 300 * time.Millisecond}
}

// startServer starts a real Server on a loopback listener with a "hold" tool that
// blocks until released or until the tools' base context is cancelled.
func startServer(t *testing.T, tm *timeouts, tlsFiles ...string) *srvRig {
	t.Helper()
	r := &srvRig{hold: make(chan struct{}), log: &testLog{}}
	r.base, r.cb = context.WithCancel(context.Background())
	m := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	mcp.AddTool(m, &mcp.Tool{Name: "hold", Description: "x"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ pinIn) (*mcp.CallToolResult, pinOut, error) {
			r.inTool.Add(1)
			defer r.inTool.Add(-1)
			select {
			case <-r.hold:
				return nil, pinOut{OK: true}, nil
			case <-r.base.Done():
				return nil, pinOut{}, fmt.Errorf("cancelled by shutdown")
			}
		})
	store, err := ParseTokens([]byte(`{"tokens":[`+entry("alpha", tok(1), "")+`]}`), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Validate(httpFlags())
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Resolved: res, Tokens: store, MCP: m, Log: slogTo(r.log), CancelTools: r.cb, tm: tm}
	if len(tlsFiles) == 2 {
		cfg.TLSCert, cfg.TLSKey = tlsFiles[0], tlsFiles[1]
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	l, err := Listen(Resolved{HTTP: true, Listen: "127.0.0.1:0", Loopback: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.s, r.addr, r.cancel, r.fin = s, l.Addr().String(), cancel, make(chan struct{})
	go func() { r.err = s.Serve(ctx, l); close(r.fin) }()
	t.Cleanup(func() {
		cancel()
		r.cb()
		select {
		case <-r.fin:
		case <-time.After(5 * time.Second):
		}
	})
	return r
}

func holdBody() string {
	return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hold","arguments":{}}}`
}

func rawPost(auth, body string) string {
	h := "POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\n"
	if auth != "" {
		h += "Authorization: Bearer " + auth + "\r\n"
	}
	return h + fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)
}

// readAll reads until the peer closes or d passes; it reports whether the close
// (EOF) happened inside d.
func closedWithin(c net.Conn, d time.Duration) (string, bool) {
	_ = c.SetReadDeadline(time.Now().Add(d))
	b, err := io.ReadAll(c)
	return string(b), err == nil
}

func TestSlowlorisHeadersAreCutAtReadHeaderTimeout(t *testing.T) {
	r := startServer(t, shortTimeouts())
	c, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte("POST /mcp HTTP/1.1\r\nHost: localhost\r\nX-A: "))
	start := time.Now()
	if _, ok := closedWithin(c, 3*time.Second); !ok {
		t.Fatal("a half-sent header block held the connection past the header timeout")
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("closed after %v", time.Since(start))
	}
}

func TestSilentConnectionDiesAtReadHeaderTimeout(t *testing.T) {
	r := startServer(t, shortTimeouts())
	c, _ := net.Dial("tcp", r.addr)
	defer func() { _ = c.Close() }()
	if _, ok := closedWithin(c, 3*time.Second); !ok {
		t.Fatal("a connection that sends nothing outlived ReadHeaderTimeout")
	}
}

func TestSlowBodyIsCutAtReadTimeout(t *testing.T) {
	r := startServer(t, shortTimeouts())
	c, _ := net.Dial("tcp", r.addr)
	defer func() { _ = c.Close() }()
	body := holdBody()
	req := rawPost(tok(1), body)
	_, _ = c.Write([]byte(req[:len(req)-10])) // headers complete, body incomplete
	if _, ok := closedWithin(c, 3*time.Second); !ok {
		t.Fatal("a stalled body held the connection past ReadTimeout")
	}
}

func TestOversizeHeaderBlockIs431(t *testing.T) {
	r := startServer(t, shortTimeouts())
	c, _ := net.Dial("tcp", r.addr)
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte("POST /mcp HTTP/1.1\r\nHost: localhost\r\nX-Big: " + strings.Repeat("a", MaxHeaderBytes+8000) + "\r\n\r\n"))
	line, _ := bufio.NewReader(c).ReadString('\n')
	if !strings.Contains(line, "431") {
		t.Errorf("status line %q, want 431", line)
	}
}

func TestUnauthenticatedConnectionIsClosedAfterOneRejection(t *testing.T) {
	tm := shortTimeouts()
	tm.idle, tm.readHeader = 30*time.Second, 30*time.Second // only Connection: close can end it quickly
	r := startServer(t, tm)
	c, _ := net.Dial("tcp", r.addr)
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte(rawPost("", holdBody())))
	out, ok := closedWithin(c, 3*time.Second)
	if !ok || !strings.HasPrefix(out, "HTTP/1.1 401") || !strings.Contains(strings.ToLower(out), "connection: close") {
		t.Fatalf("closed=%v out=%q; an unauthenticated peer must not be able to keep the connection", ok, out)
	}
}

func TestAuthenticatedKeepAliveIsReapedAtIdleTimeout(t *testing.T) {
	r := startServer(t, shortTimeouts())
	c, _ := net.Dial("tcp", r.addr)
	defer func() { _ = c.Close() }()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	_, _ = c.Write([]byte(rawPost(tok(1), body)))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("authenticated request: %v %v", resp, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	// The connection stays usable for a moment (keep-alive), then dies at idle.
	if _, ok := closedWithin(c, 3*time.Second); !ok {
		t.Fatal("idle authenticated connection was not reaped")
	}
}

// --- TLS ---

func selfSigned(t *testing.T, dir string, keyMode os.FileMode) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certPath, keyPath = filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil { //nolint:gosec // public certificate
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), keyMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, keyMode); err != nil {
		t.Fatal(err)
	}
	return
}

func TestTLSServesHTTP11OnlyAndRefusesOldVersions(t *testing.T) {
	cert, key := selfSigned(t, t.TempDir(), 0o600)
	r := startServer(t, shortTimeouts(), cert, key)

	conn, err := tls.Dial("tcp", r.addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}}) //nolint:gosec // self-signed test server
	if err != nil {
		t.Fatal(err)
	}
	if p := conn.ConnectionState().NegotiatedProtocol; p != "http/1.1" {
		t.Errorf("negotiated %q, want http/1.1 (h2 must never be offered)", p)
	}
	_ = conn.Close()

	if c, err := tls.Dial("tcp", r.addr, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS11}); err == nil { //nolint:gosec // proving TLS 1.1 is refused
		_ = c.Close()
		t.Error("TLS 1.1 was accepted")
	}

	// And a request works end to end over TLS.
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // self-signed test server
	req, _ := http.NewRequest("POST", "https://"+r.addr+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Host = "localhost"
	req.Header.Set("Authorization", "Bearer "+tok(1))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 || resp.ProtoMajor != 1 {
		t.Errorf("status %d proto %s", resp.StatusCode, resp.Proto)
	}
}

func TestTLSKeyWithLoosePermissionsIsRefused(t *testing.T) {
	cert, key := selfSigned(t, t.TempDir(), 0o644)
	m := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	store, _ := ParseTokens([]byte(`{"tokens":[`+entry("a", tok(1), "")+`]}`), time.Now)
	res, _ := Validate(httpFlags())
	if _, err := New(Config{Resolved: res, Tokens: store, MCP: m, TLSCert: cert, TLSKey: key}); err == nil {
		t.Fatal("a world-readable TLS key was accepted")
	}
}

// --- shutdown ---

func clientCall(addr string) chan string {
	out := make(chan string, 1)
	go func() {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			out <- "dial: " + err.Error()
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = c.Write([]byte(rawPost(tok(1), holdBody())))
		b, _ := io.ReadAll(c)
		out <- string(b)
	}()
	return out
}

func waitTool(t *testing.T, r *srvRig, n int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for r.inTool.Load() != n {
		if time.Now().After(deadline) {
			t.Fatalf("tool concurrency %d, want %d", r.inTool.Load(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestShutdownOfAnIdleServerIsPrompt(t *testing.T) {
	r := startServer(t, shortTimeouts())
	start := time.Now()
	r.cancel()
	select {
	case <-r.fin:
		if r.err != nil || time.Since(start) > time.Second {
			t.Errorf("err=%v after %v", r.err, time.Since(start))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return")
	}
}

func TestInFlightCallCompletesDuringDrain(t *testing.T) {
	tm := shortTimeouts()
	tm.shutdown = 5 * time.Second
	r := startServer(t, tm)
	reply := clientCall(r.addr)
	waitTool(t, r, 1)
	r.cancel() // the signal
	time.Sleep(100 * time.Millisecond)
	// New work is refused while draining.
	if c, err := net.Dial("tcp", r.addr); err == nil {
		_, _ = c.Write([]byte(rawPost(tok(1), holdBody())))
		if out, _ := closedWithin(c, time.Second); strings.Contains(out, "200 OK") {
			t.Errorf("a new request was served while draining: %q", out)
		}
		_ = c.Close()
	}
	close(r.hold)
	select {
	case out := <-reply:
		if !strings.Contains(out, "200 OK") || !strings.Contains(out, `"ok":true`) {
			t.Errorf("in-flight call did not complete: %q", out)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no reply")
	}
	<-r.fin
	if r.err != nil {
		t.Errorf("Serve: %v", r.err)
	}
}

func TestCallOutlivingTheDrainIsCancelledAndTheClientSeesAToolError(t *testing.T) {
	r := startServer(t, shortTimeouts()) // 400 ms drain, 300 ms grace
	reply := clientCall(r.addr)
	waitTool(t, r, 1)
	r.cancel()
	select {
	case out := <-reply:
		if !strings.Contains(out, "cancelled by shutdown") || !strings.Contains(out, `"isError":true`) {
			t.Errorf("client did not receive the tool error: %q", out)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no reply")
	}
	<-r.fin
	if r.err != nil {
		t.Errorf("Serve: %v", r.err)
	}
	if !strings.Contains(r.log.String(), "shutdown deadline passed") {
		t.Errorf("the abort was not logged:\n%s", r.log.String())
	}
}

func TestNoGoroutineLeakAfterShutdown(t *testing.T) {
	before := runtime.NumGoroutine()
	r := startServer(t, shortTimeouts())
	for i := 0; i < 5; i++ {
		c, _ := net.Dial("tcp", r.addr)
		_, _ = c.Write([]byte(rawPost(tok(1), `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)))
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		if resp, err := http.ReadResponse(bufio.NewReader(c), nil); err == nil {
			_ = resp.Body.Close()
		}
		_ = c.Close()
	}
	r.cancel()
	<-r.fin
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before+2 {
		t.Errorf("goroutines: %d before, %d after shutdown", before, n)
	}
}
