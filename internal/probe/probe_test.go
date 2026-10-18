package probe

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bluenviron/gortsplib/v5"
	"github.com/bluenviron/gortsplib/v5/pkg/base"
	"github.com/bluenviron/gortsplib/v5/pkg/description"
	"github.com/bluenviron/gortsplib/v5/pkg/format"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
)

const (
	testUser = "operator"
	testPass = "s3cretPassw0rd"
)

// rawRTSP is a minimal RTSP responder on a loopback TCP port. mode selects
// how it answers DESCRIBE; OPTIONS always succeeds.
type rawRTSP struct {
	ln    net.Listener
	mode  string // "401", "sdp", "hang", "silent"
	sdp   string
	wg    sync.WaitGroup
	mu    sync.Mutex
	conns []net.Conn
}

func startRaw(t *testing.T, mode, sdp string) *rawRTSP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &rawRTSP{ln: ln, mode: mode, sdp: sdp}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			r.mu.Lock()
			r.conns = append(r.conns, c)
			r.mu.Unlock()
			r.wg.Add(1)
			go func() { defer r.wg.Done(); r.serve(c) }()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		// rtspeek keeps its connection open until its read timeout after a
		// cancel, so close the server side rather than wait for it.
		r.mu.Lock()
		for _, c := range r.conns {
			_ = c.Close()
		}
		r.mu.Unlock()
		r.wg.Wait()
	})
	return r
}

func (r *rawRTSP) hostPort() string { return r.ln.Addr().String() }

func (r *rawRTSP) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	if r.mode == "silent" {
		// Accept and never answer; hold the connection until the client leaves.
		_, _ = io.Copy(io.Discard, c)
		return
	}
	br := bufio.NewReader(c)
	for {
		var method, cseq string
		var clen int
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
		_ = clen
		switch {
		case method == "OPTIONS":
			_, _ = fmt.Fprintf(c, "RTSP/1.0 200 OK\r\nCSeq: %s\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY\r\n\r\n", cseq)
		case method == "DESCRIBE" && r.mode == "401":
			_, _ = fmt.Fprintf(c, "RTSP/1.0 401 Unauthorized\r\nCSeq: %s\r\nWWW-Authenticate: Basic realm=\"cam\"\r\n\r\n", cseq)
		case method == "DESCRIBE" && r.mode == "hang":
			_, _ = io.Copy(io.Discard, c)
			return
		case method == "DESCRIBE":
			_, _ = fmt.Fprintf(c, "RTSP/1.0 200 OK\r\nCSeq: %s\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", cseq, len(r.sdp), r.sdp)
		default:
			_, _ = fmt.Fprintf(c, "RTSP/1.0 501 Not Implemented\r\nCSeq: %s\r\n\r\n", cseq)
		}
	}
}

func sdpWithVideoTracks(n int) string {
	var b strings.Builder
	b.WriteString("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=hostile\r\nt=0 0\r\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:track%d\r\n", i)
	}
	return b.String()
}

func probeWithCreds(hostPort string) string {
	return "rtsp://" + testUser + ":" + testPass + "@" + hostPort + "/stream"
}

func assertNoLeak(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, leak := range []string{testPass, testUser + ":", "rtsp://", "@127.0.0.1"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error leaks %q: %v", leak, err)
		}
	}
}

func TestFakeProberSatisfiesTheInterface(t *testing.T) {
	var p Prober = FakeProber{Result: &Result{
		Reachable: true, DescribeOK: true, Protocol: "rtsp",
		Tracks: []Track{{Index: 0, Type: "video", Format: "H264", Width: 1920, Height: 1080}},
	}}
	got, err := p.Describe(context.Background(), "rtsp://example/s", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Tracks) != 1 || got.Tracks[0].Width != 1920 {
		t.Errorf("fake did not round-trip: %+v", got)
	}
	boom := errors.New("boom")
	if _, err := (FakeProber{Err: boom}).Describe(context.Background(), "", 0); !errors.Is(err, boom) {
		t.Errorf("fake error not returned: %v", err)
	}
}

func TestRefusedConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	_, err = NewRTSP().Describe(context.Background(), probeWithCreds(addr), time.Second)
	assertNoLeak(t, err)
	te := mcperr.FromStreamError(err, "cam", "stream.inspect")
	if te.Code != mcperr.CodeUnreachable {
		t.Errorf("code = %s (%v), want unreachable", te.Code, err)
	}
}

func TestUnreachableHostWithinTimeout(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1: nothing answers.
	start := time.Now()
	_, err := NewRTSP().Describe(context.Background(), "rtsp://"+testUser+":"+testPass+"@192.0.2.1:554/s", 300*time.Millisecond)
	assertNoLeak(t, err)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %v", d)
	}
}

func TestAuthRequiredWithoutCredentials(t *testing.T) {
	srv := startRaw(t, "401", "")
	_, err := NewRTSP().Describe(context.Background(), "rtsp://"+srv.hostPort()+"/stream", 2*time.Second)
	assertNoLeak(t, err)
	te := mcperr.FromStreamError(err, "cam", "stream.inspect")
	if te.Code != mcperr.CodeAuthFailed {
		t.Errorf("code = %s (%v), want auth_failed", te.Code, err)
	}
}

func TestAuthRejectedWithCredentialsDoesNotLeak(t *testing.T) {
	srv := startRaw(t, "401", "")
	_, err := NewRTSP().Describe(context.Background(), probeWithCreds(srv.hostPort()), 2*time.Second)
	assertNoLeak(t, err)
	if te := mcperr.FromStreamError(err, "cam", "stream.inspect"); te.Code != mcperr.CodeAuthFailed {
		t.Errorf("code = %s (%v), want auth_failed", te.Code, err)
	}
}

func TestSilentServerHonoursTimeout(t *testing.T) {
	srv := startRaw(t, "silent", "")
	start := time.Now()
	_, err := NewRTSP().Describe(context.Background(), probeWithCreds(srv.hostPort()), 400*time.Millisecond)
	d := time.Since(start)
	assertNoLeak(t, err)
	if d > 400*time.Millisecond+time.Second {
		t.Errorf("returned after %v, want about 400ms", d)
	}
	if te := mcperr.FromStreamError(err, "cam", "stream.inspect"); te.Code != mcperr.CodeTimeout {
		t.Errorf("code = %s (%v), want timeout", te.Code, err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error does not wrap DeadlineExceeded: %v", err)
	}
}

func TestHangingDescribeHonoursTimeout(t *testing.T) {
	srv := startRaw(t, "hang", "")
	start := time.Now()
	_, err := NewRTSP().Describe(context.Background(), probeWithCreds(srv.hostPort()), 400*time.Millisecond)
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Errorf("returned after %v", d)
	}
	assertNoLeak(t, err)
}

func TestContextCancellationReturnsPromptly(t *testing.T) {
	srv := startRaw(t, "silent", "")
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(150*time.Millisecond, cancel)
	start := time.Now()
	_, err := NewRTSP().Describe(ctx, probeWithCreds(srv.hostPort()), 30*time.Second)
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Errorf("cancel took %v to honour", d)
	}
	assertNoLeak(t, err)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error does not wrap Canceled: %v", err)
	}
}

func TestAlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := NewRTSP().Describe(ctx, "rtsp://127.0.0.1:1/s", 5*time.Second)
	if err == nil || time.Since(start) > time.Second {
		t.Errorf("err=%v after %v", err, time.Since(start))
	}
}

func TestInvalidURLKeepsItsClassAndLeaksNothing(t *testing.T) {
	_, err := NewRTSP().Describe(context.Background(), "http://"+testUser+":"+testPass+"@host/x", time.Second)
	assertNoLeak(t, err)
	if te := mcperr.FromStreamError(err, "cam", "stream.inspect"); te.Code != mcperr.CodeInvalidArgument {
		t.Errorf("code = %s (%v), want invalid_argument", te.Code, err)
	}
	_, err = NewRTSP().Describe(context.Background(), "rtsp://"+testUser+":"+testPass+"@[bad/x", time.Second)
	assertNoLeak(t, err)
}

func TestSuccessWithVideoTrack(t *testing.T) {
	addr, stop := startGortsplib(t)
	defer stop()
	res, err := NewRTSP().Describe(context.Background(), "rtsp://"+addr+"/test", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reachable || !res.DescribeOK || res.Protocol != "rtsp" {
		t.Errorf("flags wrong: %+v", res)
	}
	if len(res.Tracks) != 1 || res.Tracks[0].Type != "video" || !strings.Contains(strings.ToUpper(res.Tracks[0].Format), "H264") {
		t.Errorf("tracks = %+v", res.Tracks)
	}
	if res.LatencyMs < 0 || math.IsNaN(res.LatencyMs) {
		t.Errorf("latency = %v", res.LatencyMs)
	}
}

type gortsplibHandler struct {
	stream atomic.Pointer[gortsplib.ServerStream]
}

func (h *gortsplibHandler) OnDescribe(*gortsplib.ServerHandlerOnDescribeCtx) (*base.Response, *gortsplib.ServerStream, error) {
	return &base.Response{StatusCode: base.StatusOK}, h.stream.Load(), nil
}

func startGortsplib(t *testing.T) (string, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	h := &gortsplibHandler{}
	s := &gortsplib.Server{RTSPAddress: addr, Handler: h}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	stream := &gortsplib.ServerStream{Server: s, Desc: &description.Session{Medias: []*description.Media{{
		Type: description.MediaTypeVideo,
		Formats: []format.Format{&format.H264{
			PayloadTyp: 96,
			SPS:        []byte{0x67, 0x42, 0x00, 0x1f},
			PPS:        []byte{0x68, 0xce, 0x06, 0xe2},
		}},
	}}}}
	if err := stream.Initialize(); err != nil {
		s.Close()
		t.Fatal(err)
	}
	h.stream.Store(stream)
	return addr, func() { stream.Close(); s.Close() }
}

func TestGarbageSDPYieldsNoPanicAndNoLeak(t *testing.T) {
	for name, sdp := range map[string]string{
		"binary":    "\x00\xff\xfe garbage \x01\x02" + strings.Repeat("\x80", 100),
		"empty":     "",
		"truncated": "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=x\r\nm=video",
	} {
		t.Run(name, func(t *testing.T) {
			srv := startRaw(t, "sdp", sdp)
			res, err := NewRTSP().Describe(context.Background(), probeWithCreds(srv.hostPort()), 2*time.Second)
			if err != nil {
				assertNoLeak(t, err)
				return
			}
			if res == nil || len(res.Tracks) > MaxTracks {
				t.Errorf("bad result %+v", res)
			}
		})
	}
}

func TestHostileSDPTrackCountIsCapped(t *testing.T) {
	srv := startRaw(t, "sdp", sdpWithVideoTracks(300))
	res, err := NewRTSP().Describe(context.Background(), probeWithCreds(srv.hostPort()), 3*time.Second)
	if err != nil {
		assertNoLeak(t, err)
		t.Skipf("rtspeek rejected the hostile SDP outright (acceptable): %v", err)
	}
	if len(res.Tracks) == 0 || len(res.Tracks) > MaxTracks {
		t.Errorf("tracks = %d, want 1..%d", len(res.Tracks), MaxTracks)
	}
}

func TestBoundResultClipsEverything(t *testing.T) {
	long := strings.Repeat("A", 10000) + "\x00\u202e"
	in := &Result{
		Reachable: true, DescribeOK: true, Protocol: long,
		LatencyMs: math.NaN(),
	}
	for i := 0; i < 500; i++ {
		in.Tracks = append(in.Tracks, Track{Index: i, Type: long, Format: long + "\n\x1b[31m", Width: -5, Height: math.MaxInt32})
	}
	out := Bound(in)
	if len(out.Tracks) != MaxTracks {
		t.Errorf("tracks = %d", len(out.Tracks))
	}
	if out.LatencyMs != 0 {
		t.Errorf("NaN latency = %v", out.LatencyMs)
	}
	for _, f := range []float64{math.Inf(1), math.Inf(-1), -3} {
		if got := Bound(&Result{LatencyMs: f}).LatencyMs; got != 0 {
			t.Errorf("latency %v -> %v", f, got)
		}
	}
	if len(out.Protocol) > MaxStringBytes {
		t.Errorf("protocol len %d", len(out.Protocol))
	}
	for _, tr := range out.Tracks {
		if len(tr.Type) > MaxStringBytes || len(tr.Format) > MaxStringBytes {
			t.Fatalf("unclipped string: %d/%d", len(tr.Type), len(tr.Format))
		}
		if strings.ContainsAny(tr.Format, "\x00\x1b\n\u202e") {
			t.Errorf("control chars survive: %q", tr.Format)
		}
		if tr.Width != 0 || tr.Height != MaxDimension {
			t.Errorf("dims = %dx%d", tr.Width, tr.Height)
		}
	}
	if Bound(nil) != nil {
		t.Error("Bound(nil) should be nil")
	}
}

func TestNothingIsWrittenToStdoutOrStderr(t *testing.T) {
	srv := startRaw(t, "401", "")
	addr, stop := startGortsplib(t)
	defer stop()

	origOut, origErr := os.Stdout, os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout, os.Stderr = wOut, wErr
	restore := func() { os.Stdout, os.Stderr = origOut, origErr }
	defer restore()

	p := NewRTSP()
	// A context that asks for rtspeek's debug trace must not enable logging.
	ctx := rtspeekDebugContext(context.Background())
	_, _ = p.Describe(ctx, probeWithCreds(srv.hostPort()), time.Second)
	_, _ = p.Describe(ctx, probeWithCreds(addr), time.Second)
	_, _ = p.Describe(ctx, probeWithCreds("127.0.0.1:1"), time.Second)

	restore()
	_ = wOut.Close()
	_ = wErr.Close()
	for name, r := range map[string]*os.File{"stdout": rOut, "stderr": rErr} {
		b, _ := io.ReadAll(r)
		if len(b) != 0 {
			t.Errorf("%s received %d bytes: %q", name, len(b), b)
		}
	}
}

func TestResolutionComesFromTheSPS(t *testing.T) {
	// A 1920x1080 High profile SPS.
	sps := []byte{0x67, 0x64, 0x00, 0x28, 0xac, 0xd9, 0x40, 0x78, 0x02, 0x27, 0xe5, 0xc0, 0x44, 0x00, 0x00, 0x03,
		0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xc8, 0x3c, 0x60, 0xc6, 0x58}
	tr := classify(0, &description.Media{Type: description.MediaTypeVideo, Formats: []format.Format{
		&format.H264{PayloadTyp: 96, SPS: sps, PPS: []byte{0x68, 0xe9, 0x3b, 0x2c, 0x8b}}}})
	if tr.Format != "H264" || tr.Width != 1920 || tr.Height != 1080 {
		t.Errorf("track = %+v, want H264 1920x1080", tr)
	}
	tr = classify(1, &description.Media{Type: description.MediaTypeVideo, Formats: []format.Format{
		&format.H264{PayloadTyp: 96, SPS: []byte{0x67, 0x01}}}})
	if tr.Width != 0 || tr.Height != 0 {
		t.Errorf("unparsable SPS gave %dx%d, want unknown", tr.Width, tr.Height)
	}
	h265sps, _ := hex.DecodeString("420101016000000300900000030000030078a003c08010e596566924cae010000003001000000301e080")
	tr = classify(4, &description.Media{Type: description.MediaTypeVideo, Formats: []format.Format{
		&format.H265{PayloadTyp: 96, SPS: h265sps}}})
	if tr.Format != "H265" || tr.Width != 1920 || tr.Height != 1080 {
		t.Errorf("track = %+v, want H265 1920x1080", tr)
	}
	au := classify(2, &description.Media{Type: description.MediaTypeAudio, Formats: []format.Format{&format.G711{MULaw: false}}})
	if au.Type != "audio" || au.Format == "" || au.Width != 0 {
		t.Errorf("audio track = %+v", au)
	}
	if got := classify(3, &description.Media{Type: description.MediaTypeApplication}); got.Type != "application" || got.Format != "" {
		t.Errorf("no-format track = %+v", got)
	}
}

func TestBoundStripsControlAndFormatCharacters(t *testing.T) {
	got := Bound(&Result{Protocol: "r\x00t\u202esp", Tracks: []Track{{Type: "vi\x1bdeo", Format: "H2\u200b64"}}})
	if got.Protocol != "rtsp" || got.Tracks[0].Type != "video" || got.Tracks[0].Format != "H264" {
		t.Errorf("%+v", got)
	}
}
