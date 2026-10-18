package registry

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/0x524a/onvif-mcp/internal/config"
)

func basicServer(t *testing.T, l *reqLog) string {
	t.Helper()
	addr, _ := listen127(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.note(r)
		if _, _, ok := r.BasicAuth(); !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write(testJPEG(t, 4, 4))
	}))
	return addr
}

// An https-configured camera that advertises an http snapshot address never
// gets its credentials: the request is refused before anything is sent.
func TestSnapshotSchemeDowngradeIsRefusedWithoutAnyRequest(t *testing.T) {
	var l reqLog
	addr := basicServer(t, &l)
	e := snapEntry(config.Camera{Endpoint: "https://127.0.0.1:443/onvif/device_service", AllowBasicOverHTTP: true})
	_, err := fetch(t, e, "http://"+addr+"/s", 1<<20)
	var ref *SnapshotRefusal
	if !errors.As(err, &ref) || ref.Kind != RefusedSnapshotSchemeDowngrade {
		t.Fatalf("err = %v, want a scheme-downgrade refusal", err)
	}
	if l.count() != 0 {
		t.Errorf("%d request(s) sent, want none", l.count())
	}
}

// Basic over https is fine without any opt-in: the password is encrypted.
func TestSnapshotBasicOverHTTPSNeedsNoOptIn(t *testing.T) {
	var l reqLog
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.note(r)
		if _, _, ok := r.BasicAuth(); !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write(testJPEG(t, 4, 4))
	}))
	t.Cleanup(ts.Close)
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	snapshotTLSRoots = pool
	t.Cleanup(func() { snapshotTLSRoots = nil })
	_, port, _ := net.SplitHostPort(ts.Listener.Addr().String())
	e := snapEntryStrict(config.Camera{Endpoint: "https://127.0.0.1/onvif/device_service"})
	got, err := fetch(t, e, "https://127.0.0.1:"+port+"/s", 1<<20)
	if err != nil || !got.Authenticated {
		t.Fatalf("err=%v authenticated=%v", err, got.Authenticated)
	}
}

func TestSnapshotBasicOverHTTPRefusedUnlessAllowed(t *testing.T) {
	var l reqLog
	addr := basicServer(t, &l)
	_, err := fetch(t, snapEntryStrict(config.Camera{}), "http://"+addr+"/s", 1<<20)
	if se := snapErr(t, err); se.Kind != SnapshotBasicOverHTTP {
		t.Fatalf("kind = %v, want SnapshotBasicOverHTTP", se.Kind)
	}
	if l.count() != 1 || l.anyAuth() {
		t.Errorf("requests=%d anyAuth=%v: the password must not be sent", l.count(), l.anyAuth())
	}

	var l2 reqLog
	addr2 := basicServer(t, &l2)
	got, err := fetch(t, snapEntryStrict(config.Camera{AllowBasicOverHTTP: true}), "http://"+addr2+"/s", 1<<20)
	if err != nil || !got.Authenticated {
		t.Fatalf("opted-in Basic over http: err=%v", err)
	}
}

func TestSnapshotDigestOverHTTPNeedsNoOptIn(t *testing.T) {
	var l reqLog
	addr := digestServer(t, &l, testJPEG(t, 8, 8), true)
	if _, err := fetch(t, snapEntryStrict(config.Camera{}), "http://"+addr+"/s", 1<<20); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotTrailingDotHostIsNotTheConfiguredHost(t *testing.T) {
	var l reqLog
	addr, _ := listen127(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.note(r)
		w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
		w.WriteHeader(401)
	}))
	_, port, _ := splitHP(addr)
	old := lookupHost
	lookupHost = func(_ context.Context, h string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	t.Cleanup(func() { lookupHost = old })
	e := snapEntry(config.Camera{Endpoint: "http://nvr/onvif/device_service", AllowBasicOverHTTP: true})
	_, err := fetch(t, e, "http://NVR.:"+port+"/s", 1<<20)
	var ref *SnapshotRefusal
	if !errors.As(err, &ref) || ref.Kind != RefusedSnapshotForeignHost {
		t.Fatalf("err = %v, want foreign-host refusal", err)
	}
	if l.count() != 0 {
		t.Errorf("%d request(s) sent", l.count())
	}
	// The same spelling on both sides is the same host.
	e = snapEntry(config.Camera{Endpoint: "http://nvr./onvif/device_service", AllowBasicOverHTTP: true})
	if _, err := fetch(t, e, "http://nvr.:"+port+"/s", 1<<20); snapErrKind(err) != SnapshotCredentialsRejected {
		t.Errorf("dotted on both sides: err = %v", err)
	}
}

func snapErrKind(err error) SnapshotFailure {
	var se *SnapshotError
	if errors.As(err, &se) {
		return se.Kind
	}
	return 0
}

func splitHP(a string) (string, string, error) {
	for i := len(a) - 1; i >= 0; i-- {
		if a[i] == ':' {
			return a[:i], a[i+1:], nil
		}
	}
	return a, "", errors.New("no port")
}

// rawServer answers every connection with the given bytes, verbatim.
func rawServer(t *testing.T, reply string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte(reply))
			}()
		}
	}()
	return ln.Addr().String()
}

func TestSnapshotGarbledReplyIsAMalformedReplyError(t *testing.T) {
	for name, reply := range map[string]string{
		"negative length": "HTTP/1.1 200 OK\r\nContent-Length: -5\r\n\r\nxx",
		"not http":        "SSH-2.0-OpenSSH_9.6\r\n",
		"huge header":     "HTTP/1.1 200 OK\r\nX: " + strings.Repeat("a", 20<<10) + "\r\n\r\n",
		"bad chunk":       "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\nabc",
	} {
		t.Run(name, func(t *testing.T) {
			addr := rawServer(t, reply)
			_, err := fetch(t, snapEntry(config.Camera{}), "http://"+addr+"/s", 1<<20)
			if se := snapErr(t, err); se.Kind != SnapshotMalformedReply {
				t.Errorf("kind = %v", se.Kind)
			}
		})
	}
}

func TestSnapshotTruncatedBodyIsNotMalformed(t *testing.T) {
	addr := rawServer(t, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")
	_, err := fetch(t, snapEntry(config.Camera{}), "http://"+addr+"/s", 1<<20)
	var se *SnapshotError
	if errors.As(err, &se) {
		t.Errorf("a short body is a transport failure, got %v", se.Kind)
	}
	if err == nil || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("err = %v, want unexpected EOF in the chain", err)
	}
}

func TestSnapshotUntrustedCertificateIsItsOwnError(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(testJPEG(t, 4, 4)) }))
	t.Cleanup(ts.Close)
	_, port, _ := net.SplitHostPort(ts.Listener.Addr().String())
	e := snapEntry(config.Camera{Endpoint: "https://127.0.0.1/onvif/device_service"})
	_, err := fetch(t, e, "https://127.0.0.1:"+port+"/s", 1<<20)
	if se := snapErr(t, err); se.Kind != SnapshotUntrustedCertificate {
		t.Errorf("kind = %v", se.Kind)
	}
}

// With a known length the body is read into one exact allocation; with none it
// is read in chunks and copied once. Neither goes through geometric growth.
func TestSnapshotReadAllocatesLittleMoreThanTheBody(t *testing.T) {
	const size = 6 << 20
	body := bytes.Repeat([]byte{0xAB}, size)
	for name, chunked := range map[string]bool{"content-length": false, "chunked": true} {
		t.Run(name, func(t *testing.T) {
			addr, _ := listen127(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if chunked {
					w.(http.Flusher).Flush()
				} else {
					w.Header().Set("Content-Length", strconv.Itoa(size))
				}
				_, _ = w.Write(body)
			}))
			e := snapEntry(config.Camera{})
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			got, err := fetch(t, e, "http://"+addr+"/s", 8<<20)
			runtime.ReadMemStats(&after)
			if err != nil || len(got.Data) != size {
				t.Fatalf("err=%v len=%d", err, len(got.Data))
			}
			limit := uint64(size + size/4)
			if chunked {
				limit = uint64(2*size + size/4)
			}
			if grew := after.TotalAlloc - before.TotalAlloc; grew > limit {
				t.Errorf("allocated %d bytes for a %d byte body (limit %d)", grew, size, limit)
			}
		})
	}
}
