package registry

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // the test server verifies Digest, which is defined over MD5
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x524a/onvif-mcp/internal/config"
)

// snapPass has every character that is special in a URL, a header or a
// quoted-string.
//
//nolint:gosec // test fixture, not a credential
const snapPass = `Sn@p:p/w?x#y "q" \b z%41`

func testJPEG(t testing.TB, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for x := 0; x < w; x++ {
		for y := 0; y < h; y++ {
			img.Set(x, y, color.RGBA{R: uint8(x), G: uint8(y), B: 90, A: 255})
		}
	}
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, nil); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// snapEntry is a camera whose configured host is 127.0.0.1.
func snapEntry(cam config.Camera) Entry {
	if cam.Endpoint == "" {
		cam.Endpoint = "http://127.0.0.1:1/onvif/device_service"
	}
	if cam.Username == "" {
		cam.Username = "operator"
	}
	if cam.Password == "" {
		cam.Password = snapPass
	}
	r := New(&config.Config{Cameras: map[string]*config.Camera{"c": &cam}})
	e, _ := r.Get("c")
	return *e
}

// reqLog records every request a test server sees.
type reqLog struct {
	mu   sync.Mutex
	auth []string
	n    int
	hdr  []http.Header
}

func (l *reqLog) note(r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.n++
	l.auth = append(l.auth, r.Header.Get("Authorization"))
	l.hdr = append(l.hdr, r.Header.Clone())
}

func (l *reqLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.n
}

func (l *reqLog) anyAuth() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, a := range l.auth {
		if a != "" {
			return true
		}
	}
	return false
}

// listen127 serves h on 127.0.0.<last>:0 and counts accepted connections.
func listen127(t *testing.T, last int, h http.Handler) (addr string, conns *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.%d:0", last))
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.%d: %v", last, err)
	}
	conns = new(atomic.Int32)
	srv := &httptest.Server{
		Listener: &countingListener{Listener: ln, n: conns},
		Config:   &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second},
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return ln.Addr().String(), conns
}

type countingListener struct {
	net.Listener
	n *atomic.Int32
}

func (c *countingListener) Accept() (net.Conn, error) {
	conn, err := c.Listener.Accept()
	if err == nil {
		c.n.Add(1)
	}
	return conn, err
}

func fetch(t *testing.T, e Entry, uri string, limit int64) (SnapshotBody, error) {
	t.Helper()
	return e.FetchSnapshot(context.Background(), uri, limit, 5*time.Second)
}

func snapErr(t *testing.T, err error) *SnapshotError {
	t.Helper()
	var se *SnapshotError
	if !errors.As(err, &se) {
		t.Fatalf("want *SnapshotError, got %T %v", err, err)
	}
	return se
}

func TestSnapshotFetchedWithoutCredentialsWhenNoneAreDemanded(t *testing.T) {
	img := testJPEG(t, 32, 24)
	var l reqLog
	addr, _ := listen127(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.note(r)
		_, _ = w.Write(img)
	}))
	got, err := fetch(t, snapEntry(config.Camera{}), "http://"+addr+"/snap.jpg?x=1", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Data, img) || got.Authenticated {
		t.Errorf("data equal=%v authenticated=%v", bytes.Equal(got.Data, img), got.Authenticated)
	}
	if l.anyAuth() {
		t.Error("credentials were sent without a 401 challenge")
	}
	h := l.hdr[0]
	if h.Get("Connection") != "close" || h.Get("Accept-Encoding") != "" {
		t.Errorf("Connection=%q Accept-Encoding=%q: want keep-alive off and no compression", h.Get("Connection"), h.Get("Accept-Encoding"))
	}
}

func TestSnapshotBasicAuthAfterChallengeWithSpecialCharPassword(t *testing.T) {
	img := testJPEG(t, 8, 8)
	var l reqLog
	addr, _ := listen127(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.note(r)
		u, p, ok := r.BasicAuth()
		if !ok || u != "operator" || p != snapPass {
			w.Header().Set("WWW-Authenticate", `Basic realm="cam"`)
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write(img)
	}))
	got, err := fetch(t, snapEntry(config.Camera{}), "http://"+addr+"/s", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Authenticated || !bytes.Equal(got.Data, img) {
		t.Errorf("authenticated=%v", got.Authenticated)
	}
	if l.count() != 2 || l.auth[0] != "" {
		t.Errorf("requests=%d first-auth=%q: credentials must follow a challenge", l.count(), l.auth[0])
	}
}

var digestKV = regexp.MustCompile(`(\w+)=(?:"((?:[^"\\]|\\.)*)"|([^,\s]+))`)

// digestServer verifies the client's answer with its own implementation of
// RFC 2617 over MD5, so it does not share code with the client.
func digestServer(t *testing.T, l *reqLog, img []byte, qop bool) string {
	t.Helper()
	const realm, nonce = "cam realm", "dcd98b7102dd2f0e8b11d0f600bfb0c093"
	addr, _ := listen127(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.note(r)
		a := r.Header.Get("Authorization")
		if !strings.HasPrefix(a, "Digest ") {
			ch := fmt.Sprintf(`Basic realm="x", Digest realm=%q, nonce=%q, opaque="op,aque"`, realm, nonce)
			if qop {
				ch += `, qop="auth,auth-int"`
			}
			w.Header().Add("WWW-Authenticate", ch)
			w.WriteHeader(401)
			return
		}
		kv := map[string]string{}
		for _, m := range digestKV.FindAllStringSubmatch(a, -1) {
			v := m[2]
			if v == "" {
				v = m[3]
			}
			kv[m[1]] = strings.ReplaceAll(strings.ReplaceAll(v, `\"`, `"`), `\\`, `\`)
		}
		md := func(s string) string { x := md5.Sum([]byte(s)); return hex.EncodeToString(x[:]) } //nolint:gosec // see import
		ha1 := md(kv["username"] + ":" + realm + ":" + snapPass)
		ha2 := md("GET:" + r.URL.RequestURI())
		want := md(ha1 + ":" + nonce + ":" + ha2)
		if qop {
			want = md(ha1 + ":" + nonce + ":" + kv["nc"] + ":" + kv["cnonce"] + ":" + kv["qop"] + ":" + ha2)
		}
		if kv["username"] != "operator" || kv["response"] != want || kv["uri"] != r.URL.RequestURI() || kv["opaque"] != "op,aque" {
			w.Header().Add("WWW-Authenticate", fmt.Sprintf(`Digest realm=%q, nonce=%q`, realm, nonce))
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write(img)
	}))
	return addr
}

func TestSnapshotDigestAuthWithSpecialCharPassword(t *testing.T) {
	for _, qop := range []bool{true, false} {
		t.Run(fmt.Sprintf("qop=%v", qop), func(t *testing.T) {
			img := testJPEG(t, 8, 8)
			var l reqLog
			addr := digestServer(t, &l, img, qop)
			got, err := fetch(t, snapEntry(config.Camera{}), "http://"+addr+"/a%20b/snap?profile=p%201&x=y", 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Authenticated || !bytes.Equal(got.Data, img) {
				t.Error("digest did not authenticate")
			}
			for _, a := range l.auth {
				if strings.HasPrefix(a, "Basic ") {
					t.Error("Basic was used although Digest was offered")
				}
				if strings.Contains(a, "Sn@p") || strings.Contains(a, "p/w") {
					t.Errorf("password appears in the Digest header: %s", a)
				}
			}
		})
	}
}

// The RFC 2617 section 3.5 worked example.
func TestDigestResponseMatchesRFC2617Vector(t *testing.T) {
	got := digestResponse("MD5", "Mufasa", "testrealm@host.com", "Circle Of Life", "GET", "/dir/index.html",
		"dcd98b7102dd2f0e8b11d0f600bfb0c093", "00000001", "0a4f113b", "auth")
	if got != "6629fae49393a05397450978507c4ef1" {
		t.Errorf("response = %s", got)
	}
}

func TestSnapshotWrongPasswordIsRejectedAfterOneRetry(t *testing.T) {
	var l reqLog
	addr, _ := listen127(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.note(r)
		w.Header().Set("WWW-Authenticate", `Basic realm="cam"`)
		w.WriteHeader(401)
	}))
	_, err := fetch(t, snapEntry(config.Camera{}), "http://"+addr+"/s", 1<<20)
	se := snapErr(t, err)
	if se.Kind != SnapshotCredentialsRejected || !se.Authenticated {
		t.Errorf("kind=%v authenticated=%v", se.Kind, se.Authenticated)
	}
	if l.count() != 2 {
		t.Errorf("requests = %d, want exactly 2 (challenge, one authenticated retry)", l.count())
	}
}

func TestSnapshotUnsupportedChallenge(t *testing.T) {
	addr, _ := listen127(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("WWW-Authenticate", "Negotiate")
		w.Header().Add("WWW-Authenticate", `Bearer realm="x"`)
		w.Header().Add("WWW-Authenticate", `Digest realm="x", nonce="n", qop="auth-int"`)
		w.WriteHeader(401)
	}))
	_, err := fetch(t, snapEntry(config.Camera{}), "http://"+addr+"/s", 1<<20)
	if se := snapErr(t, err); se.Kind != SnapshotAuthUnsupported {
		t.Errorf("kind = %v", se.Kind)
	}
}

func TestSnapshotForeignHostRefusedAndTrustedWithoutCredentials(t *testing.T) {
	var l reqLog
	addr, conns := listen127(t, 2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.note(r)
		if r.URL.Path == "/auth" {
			w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write(testJPEG(t, 4, 4))
	}))
	for _, uri := range []string{"http://" + addr + "/s", "http://u:p@" + addr + "/s", "http://127.0.0.1@" + addr + "/s"} {
		_, err := fetch(t, snapEntry(config.Camera{}), uri, 1<<20)
		var ref *SnapshotRefusal
		if !errors.As(err, &ref) || ref.Kind != RefusedSnapshotForeignHost {
			t.Fatalf("%s: err = %v, want foreign-host refusal", uri, err)
		}
		if strings.Contains(err.Error(), "127.0.0.2") || strings.Contains(err.Error(), "u:p") {
			t.Errorf("refusal echoes the address: %v", err)
		}
	}
	if conns.Load() != 0 {
		t.Fatalf("foreign host saw %d connection(s) although it is untrusted", conns.Load())
	}

	trust := snapEntry(config.Camera{TrustAdvertisedHosts: true})
	got, err := fetch(t, trust, "http://"+addr+"/s", 1<<20)
	if err != nil || got.Authenticated || len(got.Data) == 0 {
		t.Fatalf("trusted fetch: err=%v authenticated=%v", err, got.Authenticated)
	}
	// A challenge from the foreign host is never answered.
	_, err = fetch(t, trust, "http://"+addr+"/auth", 1<<20)
	if se := snapErr(t, err); se.Kind != SnapshotUnauthorized || se.Authenticated {
		t.Errorf("kind=%v authenticated=%v", se.Kind, se.Authenticated)
	}
	if l.anyAuth() {
		t.Fatal("an Authorization header reached a foreign host")
	}
}

func TestSnapshotRedirectIsNeverFollowed(t *testing.T) {
	var fl reqLog
	faddr, fconns := listen127(t, 2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl.note(r)
		_, _ = w.Write(testJPEG(t, 4, 4))
	}))
	for _, afterAuth := range []bool{false, true} {
		t.Run(fmt.Sprintf("afterAuth=%v", afterAuth), func(t *testing.T) {
			var l reqLog
			addr, _ := listen127(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				l.note(r)
				if afterAuth && r.Header.Get("Authorization") == "" {
					w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
					w.WriteHeader(401)
					return
				}
				http.Redirect(w, r, "http://"+faddr+"/steal", http.StatusFound)
			}))
			for _, trust := range []bool{false, true} {
				_, err := fetch(t, snapEntry(config.Camera{TrustAdvertisedHosts: trust}), "http://"+addr+"/s", 1<<20)
				if se := snapErr(t, err); se.Kind != SnapshotRedirected || se.Status != 302 {
					t.Errorf("trust=%v: kind=%v status=%d", trust, se.Kind, se.Status)
				}
			}
		})
	}
	if fconns.Load() != 0 || fl.anyAuth() {
		t.Fatalf("redirect target saw %d connection(s) and credentials=%v", fconns.Load(), fl.anyAuth())
	}
}

func TestSnapshotMalformedAddressesSendNothing(t *testing.T) {
	var l reqLog
	addr, conns := listen127(t, 1, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { l.note(r) }))
	for _, uri := range []string{
		"", "ftp://" + addr + "/s", "file:///etc/passwd", "gopher://" + addr + "/", "rtsp://" + addr + "/s",
		"//" + addr + "/s", "/relative", "http:///nohost", "http://", "mailto:a@b", "http:opaque",
		"http://127.0.0.1:0/s", "http://127.0.0.1:99999/s", "http://127.0.0.1:x/s", "http://[::1/s",
		"http://" + addr + "/" + strings.Repeat("a", 3000), "\x00http://" + addr, "http://127.0.0.1\x00/s",
	} {
		_, err := fetch(t, snapEntry(config.Camera{TrustAdvertisedHosts: true}), uri, 1<<20)
		var ref *SnapshotRefusal
		if !errors.As(err, &ref) || ref.Kind != RefusedSnapshotMalformed {
			t.Errorf("%.40q: err = %v, want malformed refusal", uri, err)
		}
	}
	if conns.Load() != 0 || l.count() != 0 {
		t.Errorf("connections=%d requests=%d, want none", conns.Load(), l.count())
	}
	if _, err := (Entry{}).FetchSnapshot(context.Background(), "http://127.0.0.1/s", 10, time.Second); err == nil {
		t.Error("zero Entry must refuse")
	}
	for _, lim := range []int64{0, -1, hardSnapshotLimit + 1} {
		if _, err := snapEntry(config.Camera{}).FetchSnapshot(context.Background(), "http://127.0.0.1/s", lim, time.Second); err == nil {
			t.Errorf("limit %d accepted", lim)
		}
	}
}

func TestSnapshotNeverContactedAddresses(t *testing.T) {
	trust := snapEntry(config.Camera{TrustAdvertisedHosts: true})
	for _, h := range []string{
		"169.254.169.254", "[::ffff:169.254.169.254]", "0.0.0.0", "224.0.0.1", "255.255.255.255",
		"[fe80::1]", "2852039166", "0xa9fea9fe", "169.254.169.254.",
	} {
		_, err := fetch(t, trust, "http://"+h+"/latest/meta-data", 1<<20)
		var ref *SnapshotRefusal
		if !errors.As(err, &ref) || ref.Kind != RefusedSnapshotBlockedAddress {
			t.Errorf("%s: err = %v, want blocked-address refusal", h, err)
		}
	}
}

func TestSnapshotResolvesOnceAndRefusesBlockedResolution(t *testing.T) {
	var lookups atomic.Int32
	old := lookupHost
	t.Cleanup(func() { lookupHost = old })

	var l reqLog
	addr, _ := listen127(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.note(r)
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write(testJPEG(t, 4, 4))
	}))
	_, port, _ := net.SplitHostPort(addr)

	// First answer 127.0.0.1, any later one would be the metadata address.
	lookupHost = func(context.Context, string) ([]netip.Addr, error) {
		if lookups.Add(1) == 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	}
	e := snapEntry(config.Camera{Endpoint: "http://cam.test:80/onvif/device_service"})
	if _, err := fetch(t, e, "http://cam.test:"+port+"/s", 1<<20); err != nil {
		t.Fatal(err)
	}
	if lookups.Load() != 1 || l.count() != 2 {
		t.Errorf("lookups=%d requests=%d: want one lookup serving both requests", lookups.Load(), l.count())
	}

	// A name that resolves to a never-contacted address: no request at all.
	lookupHost = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	}
	_, err := fetch(t, e, "http://cam.test:"+port+"/s", 1<<20)
	var ref *SnapshotRefusal
	if !errors.As(err, &ref) || ref.Kind != RefusedSnapshotBlockedAddress {
		t.Errorf("err = %v, want blocked-address refusal", err)
	}
	if l.count() != 2 {
		t.Errorf("requests = %d, a blocked resolution still sent one", l.count())
	}
	// Same for a trusted foreign name.
	_, err = fetch(t, snapEntry(config.Camera{TrustAdvertisedHosts: true}), "http://evil.test:"+port+"/s", 1<<20)
	if !errors.As(err, &ref) || ref.Kind != RefusedSnapshotBlockedAddress {
		t.Errorf("trusted foreign name: err = %v", err)
	}
}

func TestSnapshotSizeLimit(t *testing.T) {
	img := testJPEG(t, 64, 64)
	addr, _ := listen127(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(img) }))
	e := snapEntry(config.Camera{})
	uri := "http://" + addr + "/s"

	if got, err := fetch(t, e, uri, int64(len(img))); err != nil || len(got.Data) != len(img) {
		t.Fatalf("exactly at the limit: err=%v len=%d", err, len(got.Data))
	}
	_, err := fetch(t, e, uri, int64(len(img))-1)
	se := snapErr(t, err)
	if se.Kind != SnapshotTooLarge || se.Size != int64(len(img)) || se.Limit != int64(len(img))-1 {
		t.Errorf("declared length: %+v", se)
	}
	_, err = fetch(t, e, uri, 1)
	if se := snapErr(t, err); se.Kind != SnapshotTooLarge || se.Limit != 1 {
		t.Errorf("1-byte cap: %+v", se)
	}
}

// A body of unknown length is cut off at limit+1 bytes. The server offers
// 50 MB; the process must not buffer it and the server must not get to write it.
func TestSnapshotDoesNotBufferAnEndlessBody(t *testing.T) {
	const total = 50 << 20
	var written atomic.Int64
	done := make(chan struct{})
	addr, _ := listen127(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		defer close(done)
		w.Header().Set("Content-Type", "image/jpeg")
		chunk := bytes.Repeat([]byte{0xFF, 0xD8, 0xFF, 0}, 16<<10) // 64 KiB
		for written.Load() < total {
			n, err := w.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}))
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := fetch(t, snapEntry(config.Camera{}), "http://"+addr+"/s", 1<<10)
	runtime.ReadMemStats(&after)
	if se := snapErr(t, err); se.Kind != SnapshotTooLarge || se.Size != -1 {
		t.Fatalf("err = %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the server was never cut off")
	}
	// Socket buffers absorb some of the stream after the client stops reading;
	// the point is that it is a small fraction of the 50 MB on offer.
	if w := written.Load(); w > 16<<20 {
		t.Errorf("server wrote %d bytes of %d: the client kept reading", w, total)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 8<<20 {
		t.Errorf("process allocated %d bytes for a 1 KiB cap", grew)
	}
}

func TestSnapshotDeclaredHugeBodyIsRefusedBeforeReading(t *testing.T) {
	var written atomic.Int64
	addr, _ := listen127(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(int64(2)<<30))
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		chunk := make([]byte, 64<<10)
		for i := 0; i < 400; i++ {
			n, err := w.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				return
			}
		}
	}))
	_, err := fetch(t, snapEntry(config.Camera{}), "http://"+addr+"/s", 1<<20)
	if se := snapErr(t, err); se.Kind != SnapshotTooLarge || se.Size != 2<<30 {
		t.Errorf("err = %+v", err)
	}
}

func TestSnapshotStatusesAreClassified(t *testing.T) {
	for code, want := range map[int]SnapshotFailure{
		403: SnapshotForbidden, 404: SnapshotBadStatus, 500: SnapshotBadStatus, 503: SnapshotBadStatus,
		301: SnapshotRedirected, 307: SnapshotRedirected,
	} {
		addr, _ := listen127(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "SECRET-BODY-TEXT unauthorized", code)
		}))
		_, err := fetch(t, snapEntry(config.Camera{}), "http://"+addr+"/s", 1<<20)
		se := snapErr(t, err)
		if se.Kind != want || se.Status != code {
			t.Errorf("%d: kind=%v status=%d", code, se.Kind, se.Status)
		}
		if strings.Contains(err.Error(), "SECRET-BODY") {
			t.Errorf("%d: reply body in the error: %v", code, err)
		}
	}
}

func TestSnapshotGzipReplyIsNotInflated(t *testing.T) {
	raw := []byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 1, 2, 3}
	addr, _ := listen127(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(raw)
	}))
	got, err := fetch(t, snapEntry(config.Camera{}), "http://"+addr+"/s", 1<<20)
	if err != nil || !bytes.Equal(got.Data, raw) {
		t.Errorf("err=%v data=%x", err, got.Data)
	}
}

func TestSnapshotHungServerHonoursTheTimeoutAndLeaksNothing(t *testing.T) {
	stuckHeaders := make(chan struct{})
	stuckBody := make(chan struct{})
	var release sync.Once
	unstick := func() { release.Do(func() { close(stuckHeaders); close(stuckBody) }) }
	t.Cleanup(unstick)
	addr, _ := listen127(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/body" {
			w.Header().Set("Content-Length", "100000")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("partial"))
			w.(http.Flusher).Flush()
			<-stuckBody
			return
		}
		<-stuckHeaders
	}))
	base := stableGoroutines(t)
	for _, p := range []string{"/headers", "/body"} {
		start := time.Now()
		_, err := snapEntry(config.Camera{}).FetchSnapshot(context.Background(), "http://"+addr+p, 1<<20, 300*time.Millisecond)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s: err = %v, want a deadline error", p, err)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("%s: took %v for a 300ms timeout", p, d)
		}
	}
	// A cancelled context ends the call at once.
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	if _, err := snapEntry(config.Camera{}).FetchSnapshot(ctx, "http://"+addr+"/headers", 1<<20, 30*time.Second); !errors.Is(err, context.Canceled) {
		t.Errorf("cancel: err = %v", err)
	}
	// Let the server handlers go; what remains would be the client's.
	unstick()
	settleGoroutines(t, base)
}

func TestSnapshotErrorsCarryNeitherURLNorPassword(t *testing.T) {
	const secretQ = "tok3n-QSECRET"
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := l.Addr().String()
	_ = l.Close()
	_, ferr := fetch(t, snapEntry(config.Camera{}), "http://"+dead+"/s?token="+secretQ, 1<<20)
	if ferr == nil {
		t.Fatal("expected a connection error")
	}
	if s := ferr.Error(); strings.Contains(s, secretQ) || strings.Contains(s, "/s?") || strings.Contains(s, snapPass) {
		t.Errorf("error carries the URL or password: %s", s)
	}
	var ue interface{ Unwrap() error }
	if !errors.As(ferr, &ue) {
		t.Error("the error chain is lost, so mcperr cannot classify it")
	}
}

func TestParseChallenges(t *testing.T) {
	chs := parseChallenges([]string{
		`Basic realm="a, Digest b"`,
		`Digest realm="r\"q", nonce=abc, qop="auth,auth-int", algorithm=SHA-256, Negotiate`,
	})
	if len(chs) != 3 {
		t.Fatalf("challenges = %+v", chs)
	}
	if chs[0].scheme != "basic" || chs[0].params["realm"] != "a, Digest b" {
		t.Errorf("basic = %+v", chs[0])
	}
	d := chs[1]
	if d.scheme != "digest" || d.params["realm"] != `r"q` || d.params["nonce"] != "abc" || d.params["algorithm"] != "SHA-256" {
		t.Errorf("digest = %+v", d)
	}
	if chs[2].scheme != "negotiate" {
		t.Errorf("third = %+v", chs[2])
	}
}
