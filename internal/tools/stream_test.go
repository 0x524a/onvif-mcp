package tools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bluenviron/gortsplib/v5"
	"github.com/bluenviron/gortsplib/v5/pkg/auth"
	"github.com/bluenviron/gortsplib/v5/pkg/base"
	"github.com/bluenviron/gortsplib/v5/pkg/description"
	"github.com/bluenviron/gortsplib/v5/pkg/format"
	"github.com/bluenviron/gortsplib/v5/pkg/liberrors"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/probe"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/testcam"
)

// canaryPass is planted as the camera password in the leak tests. Each special
// character the URL grammar treats as a delimiter is in it.
//
//nolint:gosec // test fixture, not a credential
const canaryPass = "Cn@ry:p/w?x#y z%41"

const canaryUser = "operator"

// captureProber records what it is asked and answers with a canned reply.
type captureProber struct {
	mu       sync.Mutex
	urls     []string
	timeouts []time.Duration
	res      *probe.Result
	err      func(rawURL string) error
}

func (c *captureProber) Describe(_ context.Context, rawURL string, timeout time.Duration) (*probe.Result, error) {
	c.mu.Lock()
	c.urls = append(c.urls, rawURL)
	c.timeouts = append(c.timeouts, timeout)
	c.mu.Unlock()
	if c.err != nil {
		return nil, c.err(rawURL)
	}
	return c.res, nil
}

func (c *captureProber) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.urls)
}

func h264Result() *probe.Result {
	return &probe.Result{Reachable: true, DescribeOK: true, Protocol: "rtsp", LatencyMs: 4,
		Tracks: []probe.Track{{Index: 0, Type: "video", Format: "H264", Width: 1920, Height: 1080}}}
}

type camEnv struct {
	profile, user, pass, endpoint string
}

func testCamSession(t *testing.T) camEnv {
	t.Helper()
	cam := testcam.Start(t)
	return camEnv{profile: cam.ProfileToken(), user: cam.Username(), pass: cam.Password(), endpoint: cam.Endpoint()}
}

// session serves stream.inspect over the virtual camera as cam-a.
func (c camEnv) session(t *testing.T, p probe.Prober) *mcp.ClientSession {
	t.Helper()
	d := Deps{
		Reg: registry.New(&config.Config{Cameras: map[string]*config.Camera{
			"cam-a": {ID: "cam-a", Endpoint: c.endpoint, Username: c.user, Password: c.pass},
		}}),
		Log: quietLog(), Prober: p,
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	RegisterStream(srv, d)
	return connectTo(t, srv)
}

func streamBody(uri string) map[string]string {
	return map[string]string{
		"GetStreamUri": `<trt:GetStreamUriResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl"><trt:MediaUri>` +
			`<tt:Uri xmlns:tt="http://www.onvif.org/ver10/schema">` + uri + `</tt:Uri>` +
			`</trt:MediaUri></trt:GetStreamUriResponse>`,
	}
}

type streamEnv struct {
	cs  *mcp.ClientSession
	log *bytes.Buffer
}

// streamSession serves stream.inspect over a camera whose ONVIF service is a
// fixture advertising uri as the stream of every profile.
func streamSession(t *testing.T, uri string, cam config.Camera, p probe.Prober) streamEnv {
	t.Helper()
	return streamSessionBase(nil, t, uri, cam, p) //nolint:staticcheck // nil Base means no shutdown scope
}

// streamSessionBase is streamSession with the server's shutdown context set.
func streamSessionBase(base context.Context, t *testing.T, uri string, cam config.Camera, p probe.Prober) streamEnv {
	t.Helper()
	fx := fixture(t, streamBody(uri))
	cam.ID = "fx"
	cam.Endpoint = fx.URL + "/device_service"
	if cam.Username == "" {
		cam.Username = canaryUser
	}
	if cam.Password == "" {
		cam.Password = canaryPass
	}
	var logBuf bytes.Buffer
	d := Deps{
		Reg:    registry.New(&config.Config{Cameras: map[string]*config.Camera{"fx": &cam}}),
		Log:    slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Prober: p,
		Base:   base,
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	RegisterStream(srv, d)
	return streamEnv{cs: connectTo(t, srv), log: &logBuf}
}

func inspect(t *testing.T, cs *mcp.ClientSession, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	if _, ok := args["camera"]; !ok {
		args["camera"] = "fx"
	}
	if _, ok := args["profile"]; !ok {
		args["profile"] = "p1"
	}
	return call(t, cs, "stream.inspect", args)
}

// leakForms is every spelling of the canary credentials that must not reach
// an output channel.
func leakForms() []string {
	ui := url.UserPassword(canaryUser, canaryPass).String()
	enc := ui[strings.IndexByte(ui, ':')+1:]
	return []string{canaryPass, enc, url.QueryEscape(canaryPass), url.PathEscape(canaryPass), canaryUser + ":", "Cn@ry", "Cn%40ry"}
}

func assertNoLeak(t *testing.T, channel, s string) {
	t.Helper()
	for _, f := range leakForms() {
		if strings.Contains(s, f) {
			t.Errorf("%s leaks %q: %s", channel, f, s)
		}
	}
}

// captureStd redirects stdout and stderr while fn runs and returns what was
// written to them.
func captureStd(t *testing.T, fn func()) string {
	t.Helper()
	oo, oe := os.Stdout, os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = w, w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	func() {
		defer func() { os.Stdout, os.Stderr = oo, oe }()
		fn()
	}()
	_ = w.Close()
	return <-done
}

// ---- in-process RTSP servers --------------------------------------------------

// 1280x720 High-profile H.264 parameter sets.
var (
	testSPS = []byte{0x67, 0x64, 0x00, 0x1f, 0xac, 0xd9, 0x40, 0x50, 0x05, 0xbb, 0x01, 0x10, 0x00, 0x00, 0x03, 0x00, 0x10, 0x00, 0x00, 0x03, 0x03, 0xc0, 0xf1, 0x83, 0x19, 0x60}
	testPPS = []byte{0x68, 0xeb, 0xe3, 0xcb, 0x22, 0xc0}
)

type rtspServer struct {
	addr  string
	conns atomic.Int32
	descs atomic.Int32
	mu    sync.Mutex
	auths []string
	user  string
	pass  string
	h     *gortsplibHandler
}

type gortsplibHandler struct {
	rs     *rtspServer
	stream atomic.Pointer[gortsplib.ServerStream]
}

func (h *gortsplibHandler) OnConnOpen(*gortsplib.ServerHandlerOnConnOpenCtx) { h.rs.conns.Add(1) }

func (h *gortsplibHandler) OnDescribe(ctx *gortsplib.ServerHandlerOnDescribeCtx) (*base.Response, *gortsplib.ServerStream, error) {
	h.rs.descs.Add(1)
	h.rs.mu.Lock()
	h.rs.auths = append(h.rs.auths, ctx.Request.Header["Authorization"]...)
	h.rs.mu.Unlock()
	if h.rs.user != "" && !ctx.Conn.VerifyCredentials(ctx.Request, h.rs.user, h.rs.pass) {
		return &base.Response{StatusCode: base.StatusUnauthorized}, nil, liberrors.ErrServerAuth{}
	}
	return &base.Response{StatusCode: base.StatusOK}, h.stream.Load(), nil
}

func (rs *rtspServer) authorizations() []string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return append([]string(nil), rs.auths...)
}

// startRTSP serves one H.264 stream on host:0. user "" means no authentication.
func startRTSP(t *testing.T, host, user, pass string, methods ...auth.VerifyMethod) *rtspServer {
	t.Helper()
	l, err := net.Listen("tcp", host+":0")
	if err != nil {
		t.Skipf("cannot listen on %s: %v", host, err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	rs := &rtspServer{addr: addr, user: user, pass: pass}
	h := &gortsplibHandler{rs: rs}
	rs.h = h
	s := &gortsplib.Server{RTSPAddress: addr, Handler: h, AuthMethods: methods}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	stream := &gortsplib.ServerStream{Server: s, Desc: &description.Session{Medias: []*description.Media{{
		Type:    description.MediaTypeVideo,
		Formats: []format.Format{&format.H264{PayloadTyp: 96, SPS: testSPS, PPS: testPPS}},
	}}}}
	if err := stream.Initialize(); err != nil {
		s.Close()
		t.Fatal(err)
	}
	h.stream.Store(stream)
	t.Cleanup(func() { stream.Close(); s.Close() })
	return rs
}

// rawServer is a TCP listener that counts connections and optionally speaks
// just enough RTSP to serve sdp (mode "sdp") or to hang after OPTIONS ("hang"
// answers nothing at all).
type rawServer struct {
	ln    net.Listener
	conns atomic.Int32
	mode  string
	sdp   string
	mu    sync.Mutex
	open  []net.Conn
	wg    sync.WaitGroup
}

func startRaw(t *testing.T, host, mode, sdp string) *rawServer {
	t.Helper()
	ln, err := net.Listen("tcp", host+":0")
	if err != nil {
		t.Skipf("cannot listen on %s: %v", host, err)
	}
	r := &rawServer{ln: ln, mode: mode, sdp: sdp}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			r.conns.Add(1)
			r.mu.Lock()
			r.open = append(r.open, c)
			r.mu.Unlock()
			r.wg.Add(1)
			go func() { defer r.wg.Done(); r.serve(c) }()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		r.mu.Lock()
		for _, c := range r.open {
			_ = c.Close()
		}
		r.mu.Unlock()
		r.wg.Wait()
	})
	return r
}

func (r *rawServer) addr() string { return r.ln.Addr().String() }

func (r *rawServer) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	if r.mode == "hang" {
		_, _ = io.Copy(io.Discard, c)
		return
	}
	br := bufio.NewReader(c)
	for {
		var method, cseq string
		first := true
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			if first {
				method = strings.Fields(line)[0]
				first = false
			}
			if strings.HasPrefix(strings.ToLower(line), "cseq:") {
				cseq = strings.TrimSpace(line[5:])
			}
		}
		switch method {
		case "OPTIONS":
			_, _ = fmt.Fprintf(c, "RTSP/1.0 200 OK\r\nCSeq: %s\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n", cseq)
		case "DESCRIBE":
			_, _ = fmt.Fprintf(c, "RTSP/1.0 200 OK\r\nCSeq: %s\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", cseq, len(r.sdp), r.sdp)
		default:
			_, _ = fmt.Fprintf(c, "RTSP/1.0 501 Not Implemented\r\nCSeq: %s\r\n\r\n", cseq)
		}
	}
}

func sdpTracks(n int) string {
	var b strings.Builder
	b.WriteString("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=hostile\r\nt=0 0\r\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:track%d\r\n", i)
	}
	return b.String()
}

func portOf(addr string) string { _, p, _ := net.SplitHostPort(addr); return p }

// ---- tests ---------------------------------------------------------------------

func TestInspectFullPathAgainstAuthenticatedServer(t *testing.T) {
	methods := map[string][]auth.VerifyMethod{
		"basic":  {auth.VerifyMethodBasic},
		"digest": {auth.VerifyMethodDigestMD5},
	}
	passwords := []string{"zqxv-plain", "zqxv-p@ss", "zqxv-a:b", "zqxv-a/b", "zqxv-a?b", "zqxv-a#b", "zqxv a b", "zqxv-100%", "zqxv-x%41y", canaryPass}
	for name, m := range methods {
		for _, pw := range passwords {
			t.Run(name+"/"+pw, func(t *testing.T) {
				if name == "basic" && strings.Contains(pw, ":") {
					// gortsplib's own Basic header parser (pkg/headers,
					// Authorization.Unmarshal) splits on every colon and
					// rejects a password containing one. That is the test
					// server's limit, not the URL builder's: the digest run
					// of the same password passes.
					t.Skip("test server cannot parse a colon in a Basic password")
				}
				srv := startRTSP(t, "127.0.0.1", canaryUser, pw, m...)
				env := streamSession(t, "rtsp://127.0.0.1:"+portOf(srv.addr)+"/s", config.Camera{Password: pw}, probe.NewRTSP())
				res := inspect(t, env.cs, map[string]any{"timeout_seconds": 5})
				d := dataMap(t, res)
				if d["authenticated"] != true || d["describe_ok"] != true {
					t.Fatalf("not authenticated / described: %s", wire(t, res))
				}
				tr, _ := d["tracks"].([]any)
				if len(tr) != 1 || !strings.Contains(wire(t, res), "H264") {
					t.Errorf("tracks: %s", wire(t, res))
				}
				if got := d["stream"]; got != "rtsp://127.0.0.1:"+portOf(srv.addr)+"/s" {
					t.Errorf("stream = %v", got)
				}
				if len(srv.authorizations()) == 0 {
					t.Error("server never saw an Authorization header")
				}
				if strings.Contains(wire(t, res), pw) && len(pw) > 5 {
					t.Errorf("password in output: %s", wire(t, res))
				}
			})
		}
	}
}

func TestInspectReportsResolutionFromSPS(t *testing.T) {
	srv := startRTSP(t, "127.0.0.1", "", "")
	env := streamSession(t, "rtsp://127.0.0.1:"+portOf(srv.addr)+"/s", config.Camera{}, probe.NewRTSP())
	res := inspect(t, env.cs, nil)
	d := dataMap(t, res)
	if d["authenticated"] != true { // anonymous server, but the camera has credentials configured
		t.Errorf("authenticated = %v", d["authenticated"])
	}
	tr := d["tracks"].([]any)[0].(map[string]any)
	if tr["width"] != float64(1280) || tr["height"] != float64(720) {
		t.Errorf("resolution = %vx%v, want 1280x720: %s", tr["width"], tr["height"], wire(t, res))
	}
}

func TestInspectWrongPasswordFailsLegiblyWithoutLeak(t *testing.T) {
	srv := startRTSP(t, "127.0.0.1", canaryUser, "the-real-one")
	env := streamSession(t, "rtsp://127.0.0.1:"+portOf(srv.addr)+"/s", config.Camera{}, probe.NewRTSP())
	res := inspect(t, env.cs, nil)
	if !res.IsError {
		t.Fatalf("expected an error: %s", wire(t, res))
	}
	assertNoLeak(t, "wire", wire(t, res))
	// A server that drops the connection after bad credentials is classified
	// by rtspeek's text classifier, which can say auth_failed, unreachable or
	// internal; all are acceptable, a leak is not.
	if code, _ := errCode(t, res); code != "auth_failed" && code != "unreachable" && code != "internal" {
		t.Errorf("code = %q: %s", code, wire(t, res))
	}
}

func TestInspectNeverLeaksCredentialsInAnyChannel(t *testing.T) {
	cases := map[string]*captureProber{
		"ok":                              {res: h264Result()},
		"error with the credentialed url": {err: func(u string) error { return fmt.Errorf("dial %s: connection refused", u) }},
		"error with only the encoded password": {err: func(u string) error {
			pu, _ := url.Parse(u)
			enc := strings.TrimPrefix(pu.User.String(), canaryUser+":")
			return fmt.Errorf("auth failed for password %s (%s)", enc, canaryPass)
		}},
		"error with a different casing of the escapes": {err: func(u string) error { return fmt.Errorf("bad %s", strings.ToLower(u)) }},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			env := streamSession(t, "rtsp://127.0.0.1:1/s", config.Camera{}, p)
			var res *mcp.CallToolResult
			std := captureStd(t, func() { res = inspect(t, env.cs, nil) })
			if p.calls() != 1 {
				t.Fatalf("prober calls = %d", p.calls())
			}
			// The credentials did reach the prober (that is the point) ...
			if !strings.Contains(p.urls[0], url.PathEscape(canaryUser)) || !strings.Contains(p.urls[0], "@127.0.0.1:1/s") {
				t.Fatalf("credentials were not injected: the test proves nothing (%s)", p.urls[0])
			}
			// ... and nowhere else.
			assertNoLeak(t, "wire", wire(t, res))
			assertNoLeak(t, "log", env.log.String())
			assertNoLeak(t, "std streams", std)
			for _, c := range res.Content {
				if tc, ok := c.(*mcp.TextContent); ok {
					assertNoLeak(t, "text", tc.Text)
				}
			}
			b, _ := json.Marshal(res.StructuredContent)
			assertNoLeak(t, "structured", string(b))
		})
	}
}

func TestInspectDoesNotLeakThroughAPanic(t *testing.T) {
	p := panicProber{}
	env := streamSession(t, "rtsp://127.0.0.1:1/s", config.Camera{}, p)
	res := inspect(t, env.cs, nil)
	if !res.IsError {
		t.Fatalf("expected an error: %s", wire(t, res))
	}
	assertNoLeak(t, "wire", wire(t, res))
	assertNoLeak(t, "log", env.log.String())
	if code, _ := errCode(t, res); code != "internal" {
		t.Errorf("code = %q", code)
	}
}

type panicProber struct{}

func (panicProber) Describe(_ context.Context, rawURL string, _ time.Duration) (*probe.Result, error) {
	panic("boom " + rawURL)
}

func TestInspectForeignHostIsRefusedAndNeverContacted(t *testing.T) {
	foreign := startRaw(t, "127.0.0.2", "sdp", sdpTracks(1))
	p := &captureProber{res: h264Result()}
	// Real prober and a counting listener: zero connections is observable
	// at the socket, not only at the fake.
	for name, prober := range map[string]probe.Prober{"real": probe.NewRTSP(), "fake": p} {
		t.Run(name, func(t *testing.T) {
			for _, uri := range []string{
				"rtsp://" + foreign.addr() + "/s",
				"rtsp://someone:else@" + foreign.addr() + "/s",
				"rtsp://127.0.0.1@" + foreign.addr() + "/s",
				"rtsp://localhost.evil.example:" + portOf(foreign.addr()) + "/s",
			} {
				env := streamSession(t, uri, config.Camera{}, prober)
				res := inspect(t, env.cs, nil)
				if !res.IsError {
					t.Fatalf("%s: expected refusal: %s", uri, wire(t, res))
				}
				code, hint := errCode(t, res)
				if code != "device_fault" {
					t.Errorf("code = %q, want device_fault", code)
				}
				if !strings.Contains(wire(t, res), "camera advertised a stream address on another host") {
					t.Errorf("message missing: %s", wire(t, res))
				}
				if !strings.Contains(hint, "trust_advertised_hosts") {
					t.Errorf("hint does not name the opt-out: %q", hint)
				}
				assertNoLeak(t, "wire", wire(t, res))
				if strings.Contains(wire(t, res), "someone") || strings.Contains(wire(t, res), "else") {
					t.Errorf("camera userinfo echoed: %s", wire(t, res))
				}
			}
		})
	}
	time.Sleep(100 * time.Millisecond)
	if n := foreign.conns.Load(); n != 0 {
		t.Errorf("foreign server saw %d connection(s), want 0", n)
	}
	if p.calls() != 0 {
		t.Errorf("fake prober called %d times", p.calls())
	}
}

func TestInspectTrustedForeignHostIsProbedWithoutCredentials(t *testing.T) {
	srv := startRTSP(t, "127.0.0.2", "", "")
	uri := "rtsp://" + canaryUser + ":" + "camera-supplied" + "@" + srv.addr + "/s"
	env := streamSession(t, uri, config.Camera{TrustAdvertisedHosts: true}, probe.NewRTSP())
	res := inspect(t, env.cs, nil)
	d := dataMap(t, res)
	if d["authenticated"] != false || d["describe_ok"] != true {
		t.Fatalf("authenticated=%v describe_ok=%v: %s", d["authenticated"], d["describe_ok"], wire(t, res))
	}
	if srv.conns.Load() == 0 {
		t.Error("trusted foreign host was never contacted")
	}
	if a := srv.authorizations(); len(a) != 0 {
		t.Errorf("foreign host received Authorization: %v", a)
	}
	assertNoLeak(t, "wire", wire(t, res))
	if strings.Contains(wire(t, res), "camera-supplied") {
		t.Errorf("camera-supplied password echoed: %s", wire(t, res))
	}
}

func TestInspectTrustedForeignHostWithCapturingProberSeesNoUserinfo(t *testing.T) {
	p := &captureProber{res: h264Result()}
	env := streamSession(t, "rtsp://u:camera-pw@198.51.100.9:8554/live?a=1", config.Camera{TrustAdvertisedHosts: true}, p)
	res := inspect(t, env.cs, nil)
	dataMap(t, res)
	if got := p.urls[0]; got != "rtsp://198.51.100.9:8554/live?a=1" {
		t.Errorf("probe url = %q", got)
	}
}

func TestInspectNeverProbesDangerousTargetsEvenWithTrust(t *testing.T) {
	p := &captureProber{res: h264Result()}
	for _, uri := range []string{
		"rtsp://169.254.169.254/latest/meta-data", "rtsp://0.0.0.0:554/s", "rtsp://[::]/s", "rtsp://224.0.0.251/s",
		"rtsp://2852039166/s", "rtsp://[fe80::1]/s",
	} {
		env := streamSession(t, uri, config.Camera{TrustAdvertisedHosts: true}, p)
		res := inspect(t, env.cs, nil)
		code, _ := errCode(t, res)
		if !res.IsError || code != "device_fault" {
			t.Errorf("%s: want device_fault, got %s", uri, wire(t, res))
		}
	}
	if p.calls() != 0 {
		t.Errorf("prober was called %d times for refused targets", p.calls())
	}
}

func TestInspectRefusesUnusableSchemesAndPorts(t *testing.T) {
	p := &captureProber{res: h264Result()}
	for _, uri := range []string{
		"http://127.0.0.1/s", "file:///etc/passwd", "rtsp://127.0.0.1:0/s", "rtsp://127.0.0.1:70000/s",
	} {
		env := streamSession(t, uri, config.Camera{TrustAdvertisedHosts: true}, p)
		res := inspect(t, env.cs, nil)
		if code, _ := errCode(t, res); code != "device_fault" {
			t.Errorf("%s: code %q: %s", uri, code, wire(t, res))
		}
	}
	if p.calls() != 0 {
		t.Errorf("prober called %d times", p.calls())
	}
}

func TestInspectStripsCameraUserinfoFromSameHostURI(t *testing.T) {
	const rightPass = "zqxv-right-pass" //nolint:gosec // fixed test secret, not a credential
	srv := startRTSP(t, "127.0.0.1", canaryUser, rightPass)
	uri := "rtsp://attacker:their-pass@127.0.0.1:" + portOf(srv.addr) + "/s"
	env := streamSession(t, uri, config.Camera{Password: rightPass}, probe.NewRTSP())
	res := inspect(t, env.cs, nil)
	d := dataMap(t, res)
	if d["authenticated"] != true {
		t.Errorf("configured credentials were not used: %s", wire(t, res))
	}
	if w := wire(t, res); strings.Contains(w, "attacker") || strings.Contains(w, "their-pass") {
		t.Errorf("camera-supplied userinfo echoed: %s", w)
	}
}

func TestInspectHungServerReturnsWithinTheTimeout(t *testing.T) {
	srv := startRaw(t, "127.0.0.1", "hang", "")
	env := streamSession(t, "rtsp://127.0.0.1:"+portOf(srv.addr())+"/s", config.Camera{}, probe.NewRTSP())
	start := time.Now()
	res := inspect(t, env.cs, map[string]any{"timeout_seconds": 1})
	if d := time.Since(start); d > 3500*time.Millisecond {
		t.Errorf("took %v for a 1s timeout", d)
	}
	if !res.IsError {
		t.Fatalf("expected an error: %s", wire(t, res))
	}
	if code, _ := errCode(t, res); code != "timeout" {
		t.Errorf("code = %q: %s", code, wire(t, res))
	}
	assertNoLeak(t, "wire", wire(t, res))
}

func TestInspectHostileSDPIsCapped(t *testing.T) {
	for _, n := range []int{1500, 10000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) { hostileSDP(t, n) })
	}
}

func hostileSDP(t *testing.T, n int) {
	srv := startRaw(t, "127.0.0.1", "sdp", sdpTracks(n))
	env := streamSession(t, "rtsp://127.0.0.1:"+portOf(srv.addr())+"/s", config.Camera{}, probe.NewRTSP())
	res := inspect(t, env.cs, map[string]any{"timeout_seconds": 5})
	if res.IsError {
		assertNoLeak(t, "wire", wire(t, res))
		t.Logf("library rejected the %d-track SDP outright (acceptable): %s", n, wire(t, res))
		return
	}
	d := dataMap(t, res)
	if n := len(d["tracks"].([]any)); n == 0 || n > probe.MaxTracks {
		t.Errorf("tracks = %d, want 1..%d", n, probe.MaxTracks)
	}
}

func TestInspectBoundsHostileProberOutput(t *testing.T) {
	long := strings.Repeat("A", 5000) + "\x00\u202e"
	r := &probe.Result{Reachable: true, DescribeOK: true, Protocol: long, LatencyMs: math.NaN()}
	for i := 0; i < 10000; i++ {
		r.Tracks = append(r.Tracks, probe.Track{Index: i, Type: long, Format: long, Width: -1, Height: math.MaxInt32})
	}
	env := streamSession(t, "rtsp://127.0.0.1:1/s", config.Camera{}, &captureProber{res: r})
	res := inspect(t, env.cs, nil)
	d := dataMap(t, res)
	if d["latency_ms"] != float64(0) {
		t.Errorf("latency = %v", d["latency_ms"])
	}
	tr := d["tracks"].([]any)
	if len(tr) != probe.MaxTracks {
		t.Errorf("tracks = %d", len(tr))
	}
	if len(wire(t, res)) > 64<<10 {
		t.Errorf("result is %d bytes", len(wire(t, res)))
	}
	if strings.ContainsAny(wire(t, res), "\x00\u202e") {
		t.Error("control characters survive")
	}
}

func TestInspectClosedPortIsUnreachable(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()
	env := streamSession(t, "rtsp://"+addr+"/s", config.Camera{}, probe.NewRTSP())
	res := inspect(t, env.cs, nil)
	if code, _ := errCode(t, res); code != "unreachable" {
		t.Errorf("code = %q: %s", code, wire(t, res))
	}
	assertNoLeak(t, "wire", wire(t, res))
}

func TestInspectTestcamStreamIsProbedWithItsCredentials(t *testing.T) {
	cam := testCamSession(t)
	p := &captureProber{res: h264Result()}
	cs := cam.session(t, p)
	res := call(t, cs, "stream.inspect", map[string]any{"camera": "cam-a", "profile": cam.profile})
	dataMap(t, res)
	if p.calls() != 1 {
		t.Fatalf("calls = %d", p.calls())
	}
	pu, err := url.Parse(p.urls[0])
	if err != nil {
		t.Fatal(err)
	}
	pw, _ := pu.User.Password()
	if pu.User.Username() != cam.user || pw != cam.pass || pu.Hostname() != "127.0.0.1" {
		t.Errorf("probe url did not carry the camera's credentials for its own host: %s", pu.Redacted())
	}
	if strings.Contains(wire(t, res), cam.pass) {
		t.Errorf("password in output: %s", wire(t, res))
	}
}

func TestInspectUnknownProfileAndCamera(t *testing.T) {
	cam := testCamSession(t)
	p := &captureProber{res: h264Result()}
	cs := cam.session(t, p)
	res := call(t, cs, "stream.inspect", map[string]any{"camera": "cam-a", "profile": "no-such-profile"})
	code, hint := errCode(t, res)
	if !res.IsError || code != "not_found" || !strings.Contains(hint, "media.profiles") {
		t.Errorf("unknown profile: code=%q hint=%q %s", code, hint, wire(t, res))
	}
	res = call(t, cs, "stream.inspect", map[string]any{"camera": "ghost", "profile": "p"})
	code, hint = errCode(t, res)
	if !res.IsError || code != "not_found" || !strings.Contains(hint, "camera.list") {
		t.Errorf("unknown camera: code=%q hint=%q %s", code, hint, wire(t, res))
	}
	if p.calls() != 0 {
		t.Errorf("prober called %d times", p.calls())
	}
}

func TestInspectTimeoutIsDefaultedAndClamped(t *testing.T) {
	for in, want := range map[int]time.Duration{0: 5 * time.Second, 1: time.Second, 7: 7 * time.Second, 10: 10 * time.Second, 11: 10 * time.Second, 1 << 30: 10 * time.Second} {
		p := &captureProber{res: h264Result()}
		env := streamSession(t, "rtsp://127.0.0.1:1/s", config.Camera{}, p)
		args := map[string]any{}
		if in != 0 {
			args["timeout_seconds"] = in
		}
		dataMap(t, inspect(t, env.cs, args))
		if p.timeouts[0] != want {
			t.Errorf("timeout_seconds %d -> %v, want %v", in, p.timeouts[0], want)
		}
	}
}

func TestInspectInputValidation(t *testing.T) {
	p := &captureProber{res: h264Result()}
	env := streamSession(t, "rtsp://127.0.0.1:1/s", config.Camera{}, p)
	for name, args := range map[string]map[string]any{
		"empty camera":     {"camera": "", "profile": "p"},
		"empty profile":    {"camera": "fx", "profile": ""},
		"negative timeout": {"camera": "fx", "profile": "p", "timeout_seconds": -3},
		"zero timeout":     {"camera": "fx", "profile": "p", "timeout_seconds": 0},
		"fractional":       {"camera": "fx", "profile": "p", "timeout_seconds": 2.5},
		"string timeout":   {"camera": "fx", "profile": "p", "timeout_seconds": "5"},
		"extra field":      {"camera": "fx", "profile": "p", "url": "rtsp://evil/"},
		"credentials":      {"camera": "fx", "profile": "p", "password": "x"},
	} {
		res, err := env.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "stream.inspect", Arguments: args})
		if err == nil && (res == nil || !res.IsError) {
			t.Errorf("%s: accepted", name)
		}
	}
	if p.calls() != 0 {
		t.Errorf("prober called %d times for invalid input", p.calls())
	}
}

func TestInspectDeclaresItsContract(t *testing.T) {
	env := streamSession(t, "rtsp://127.0.0.1:1/s", config.Camera{}, &captureProber{res: h264Result()})
	list, err := env.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var tool *mcp.Tool
	for _, x := range list.Tools {
		if x.Name == "stream.inspect" {
			tool = x
		}
	}
	if tool == nil {
		t.Fatal("not registered")
	}
	a := tool.Annotations
	if a == nil || !a.ReadOnlyHint || !a.IdempotentHint || a.DestructiveHint == nil || *a.DestructiveHint ||
		a.OpenWorldHint == nil || !*a.OpenWorldHint {
		t.Errorf("annotations = %+v", a)
	}
	for _, w := range []string{"Use this after media.profiles", "media.stream_uri", "best-effort", "parameter sets",
		"Does not fetch frames", "does not record", "trust_advertised_hosts", "clamped to 10", "defaults to 5", "open-world"} {
		if !strings.Contains(tool.Description, w) {
			t.Errorf("description lacks %q", w)
		}
	}
	b, _ := json.Marshal(tool.InputSchema)
	for _, w := range []string{`"minLength":1`, `"minimum":1`, `"additionalProperties":false`} {
		if !strings.Contains(string(b), w) {
			t.Errorf("input schema lacks %s: %s", w, b)
		}
	}
	if strings.Contains(string(b), "password") || strings.Contains(string(b), "url") {
		t.Errorf("input schema offers a credential or url field: %s", b)
	}
}

// Only stream.go may reach the credential accessors, so no other tool can
// obtain a camera's password however it is written.
func TestOnlyStreamInspectReachesTheCredentialAccessors(t *testing.T) {
	root := filepath.Join("..", "..")
	banned := map[string]bool{"PrepareStream": true, "CredentialedURL": true}
	allowed := map[string]bool{
		filepath.Join(root, "internal", "tools", "stream.go"):    true,
		filepath.Join(root, "internal", "registry", "stream.go"): true,
	}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if de.IsDir() {
			switch de.Name() {
			case ".git", "vendor", "docs":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || allowed[path] {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if banned[x.Sel.Name] {
					t.Errorf("%s: %s reaches a credential accessor", fset.Position(x.Pos()), x.Sel.Name)
				}
			case *ast.Ident:
				if banned[x.Name] {
					t.Errorf("%s: %s reaches a credential accessor", fset.Position(x.Pos()), x.Name)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Deps must not grow a way to fetch credentials.
func TestDepsHasNoCredentialFunc(t *testing.T) {
	root := filepath.Join(".", "tools.go")
	f, err := parser.ParseFile(token.NewFileSet(), root, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Deps" {
			return true
		}
		for _, fld := range ts.Type.(*ast.StructType).Fields.List {
			for _, nm := range fld.Names {
				if _, isFn := fld.Type.(*ast.FuncType); isFn && strings.Contains(strings.ToLower(nm.Name), "cred") {
					t.Errorf("Deps.%s is a credential accessor", nm.Name)
				}
				if strings.Contains(strings.ToLower(nm.Name), "cred") || strings.Contains(strings.ToLower(nm.Name), "password") {
					t.Errorf("Deps.%s looks like credential access", nm.Name)
				}
			}
		}
		return false
	})
}

// A probe that refuses a resolved address surfaces as the same message as a
// refused advertised address.
func TestInspectMapsProbeBlockedAddressToTheBlockedMessage(t *testing.T) {
	env := streamSession(t, "rtsp://127.0.0.1:1/s", config.Camera{}, &captureProber{err: func(string) error { return probe.ErrBlockedAddress }})
	res := inspect(t, env.cs, nil)
	if !res.IsError {
		t.Fatalf("expected an error: %s", wire(t, res))
	}
	if w := wire(t, res); !strings.Contains(w, "never probes") || !strings.Contains(w, "device_fault") {
		t.Errorf("wire = %s", w)
	}
}
