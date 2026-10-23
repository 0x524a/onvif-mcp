package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const soapEnv = `<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>%s</s:Body></s:Envelope>`

var soapOp = regexp.MustCompile(`Body[^>]*>\s*<(?:[A-Za-z0-9]+:)?([A-Za-z0-9]+)`)

// stopStub is a PTZ device whose Stop reply is held until release is closed.
type stopStub struct {
	srv       *httptest.Server
	release   chan struct{}
	once      sync.Once
	stopSeen  chan struct{}
	stops     atomic.Int32
	statusReq atomic.Int32
}

func newStopStub(t *testing.T) *stopStub {
	t.Helper()
	f := &stopStub{release: make(chan struct{}), stopSeen: make(chan struct{}, 8)}
	const ns = `xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema"`
	var url string
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		op := "?"
		if m := soapOp.FindStringSubmatch(string(raw)); m != nil {
			op = m[1]
		}
		w.Header().Set("Content-Type", "application/soap+xml")
		switch op {
		case "GetCapabilities":
			_, _ = fmt.Fprintf(w, soapEnv, `<tds:GetCapabilitiesResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:Capabilities>`+
				`<tt:PTZ xmlns:tt="http://www.onvif.org/ver10/schema"><tt:XAddr>`+url+`/ptz</tt:XAddr></tt:PTZ>`+
				`<tt:Media xmlns:tt="http://www.onvif.org/ver10/schema"><tt:XAddr>`+url+`/media</tt:XAddr></tt:Media>`+
				`</tds:Capabilities></tds:GetCapabilitiesResponse>`)
		case "GetProfiles":
			_, _ = fmt.Fprintf(w, soapEnv, `<trt:GetProfilesResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl" `+ns+`>`+
				`<trt:Profiles token="prof"><tt:Name>main</tt:Name><tt:PTZConfiguration token="c"><tt:Name>c</tt:Name></tt:PTZConfiguration></trt:Profiles></trt:GetProfilesResponse>`)
		case "Stop":
			f.stops.Add(1)
			f.stopSeen <- struct{}{}
			select {
			case <-f.release:
			case <-r.Context().Done():
				return
			}
			_, _ = fmt.Fprintf(w, soapEnv, `<tptz:StopResponse `+ns+`/>`)
		case "GetStatus":
			f.statusReq.Add(1)
			_, _ = fmt.Fprintf(w, soapEnv, `<tptz:GetStatusResponse `+ns+`><tptz:PTZStatus><tt:MoveStatus><tt:PanTilt>IDLE</tt:PanTilt></tt:MoveStatus></tptz:PTZStatus></tptz:GetStatusResponse>`)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	url = f.srv.URL
	t.Cleanup(f.srv.Close)
	t.Cleanup(f.releaseAll)
	return f
}

func (f *stopStub) releaseAll() { f.once.Do(func() { close(f.release) }) }

func (f *stopStub) config(t *testing.T) string {
	t.Helper()
	body := fmt.Sprintf(`{"cameras":{"cam1":{"endpoint":%q,"username":"u","password":"stub-pw-1","control":true,"timeout_seconds":30}}}`,
		f.srv.URL+"/device_service")
	p := filepath.Join(t.TempDir(), "cameras.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func alive(s *session) bool { return s.cmd.Process.Signal(syscall.Signal(0)) == nil }

func (s *session) startStop(id int) {
	s.send(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{
		"name": "ptz.stop", "arguments": map[string]any{"camera": "cam1", "profile": "prof"}}})
}

func waitFor(t *testing.T, ch <-chan struct{}, d time.Duration, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(d):
		t.Fatalf("%s: not within %v", what, d)
	}
}

// A second SIGTERM inside the grace period must not abort a ptz.stop that has
// been dispatched: the process stays up until the stop finishes, then exits.
func TestSecondSignalInsideGraceDoesNotAbortADispatchedStop(t *testing.T) {
	stub := newStopStub(t)
	s, se := startSession(t, stub.config(t), "-enable-control")
	s.initialize()
	s.startStop(2)
	waitFor(t, stub.stopSeen, 10*time.Second, "the Stop request reaching the camera")

	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond)
	if !alive(s) {
		t.Fatalf("the process died on a second signal while a stop was in flight:\n%s", se)
	}
	if stub.statusReq.Load() != 0 {
		t.Fatal("harness: the Stop reply was supposed to be held")
	}

	stub.releaseAll()
	code, ok := s.wait(15 * time.Second)
	if !ok || code != 0 {
		t.Fatalf("ok=%v code=%d stderr=%s", ok, code, se)
	}
	if stub.stops.Load() != 1 {
		t.Errorf("Stop requests = %d", stub.stops.Load())
	}
	if stub.statusReq.Load() == 0 {
		t.Error("the stop handler was aborted before it could confirm; it must run to completion")
	}
}

// After the grace period a further signal ends a shutdown that is stuck, even
// though a handler never returns.
func TestSecondSignalAfterGraceTerminatesAStuckShutdown(t *testing.T) {
	stub := newStopStub(t)
	s, se := startSession(t, stub.config(t), "-enable-control")
	s.initialize()
	s.startStop(2)
	waitFor(t, stub.stopSeen, 10*time.Second, "the Stop request reaching the camera")

	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	time.Sleep(shutdownGrace + 700*time.Millisecond)
	if !alive(s) {
		t.Fatalf("the process exited before the second signal although the stop is held:\n%s", se)
	}
	start := time.Now()
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.wait(2 * time.Second); !ok {
		t.Fatalf("the process did not exit within 2s of the second signal:\n%s", se)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("exit took %v", d)
	}
}
