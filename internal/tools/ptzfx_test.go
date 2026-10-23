package tools

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/registry"
)

// ptzFx is a recording, scriptable PTZ SOAP device for the motion tests. It
// answers GetCapabilities (media and PTZ at its own URL), GetProfiles, Stop,
// RelativeMove, ContinuousMove and GetStatus, records every request with its
// arrival time, and lets a test intercept any operation.
type ptzFx struct {
	srv     *httptest.Server
	release chan struct{} // closed at cleanup; held handlers return
	relOnce sync.Once

	mu  sync.Mutex
	ops []ptzOp

	// profiles are the tokens GetProfiles reports, all with a PTZConfiguration
	// except those in noPTZ.
	profiles []string
	noPTZ    map[string]bool
	// moveStatus is the inner XML of the GetStatus reply's MoveStatus element
	// ("" means the camera reports none).
	moveStatus string
	// behave intercepts an operation; n is the 1-based count of that operation.
	// It returns true when it has written the reply itself.
	behave map[string]func(n int, w http.ResponseWriter, r *http.Request, body string) bool
}

type ptzOp struct {
	name string
	at   time.Time
	body string
	n    int
}

var opName = regexp.MustCompile(`Body[^>]*>\s*<(?:[A-Za-z0-9]+:)?([A-Za-z0-9]+)`)

const idleStatus = `<tt:PanTilt>IDLE</tt:PanTilt><tt:Zoom>IDLE</tt:Zoom>`

func newPtzFx(t *testing.T, profiles ...string) *ptzFx {
	t.Helper()
	if len(profiles) == 0 {
		profiles = []string{"prof"}
	}
	f := &ptzFx{
		profiles: profiles, noPTZ: map[string]bool{}, moveStatus: idleStatus,
		release: make(chan struct{}),
		behave:  map[string]func(int, http.ResponseWriter, *http.Request, string) bool{},
	}
	var url string
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		name := "?"
		if m := opName.FindStringSubmatch(body); m != nil {
			name = m[1]
		}
		f.mu.Lock()
		n := 1
		for _, o := range f.ops {
			if o.name == name {
				n++
			}
		}
		f.ops = append(f.ops, ptzOp{name: name, at: time.Now(), body: body, n: n})
		hook := f.behave[name]
		f.mu.Unlock()

		w.Header().Set("Content-Type", "application/soap+xml")
		if hook != nil && hook(n, w, r, body) {
			return
		}
		switch name {
		case "GetCapabilities":
			_, _ = fmt.Fprintf(w, envelope, `<tds:GetCapabilitiesResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:Capabilities>`+
				`<tt:PTZ xmlns:tt="http://www.onvif.org/ver10/schema"><tt:XAddr>`+url+`/ptz</tt:XAddr></tt:PTZ>`+
				`<tt:Media xmlns:tt="http://www.onvif.org/ver10/schema"><tt:XAddr>`+url+`/media</tt:XAddr></tt:Media>`+
				`</tds:Capabilities></tds:GetCapabilitiesResponse>`)
		case "GetProfiles":
			var b strings.Builder
			b.WriteString(`<trt:GetProfilesResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl" ` + ptzNS + `>`)
			f.mu.Lock()
			for _, p := range f.profiles {
				cfg := `<tt:PTZConfiguration token="c-` + p + `"><tt:Name>c</tt:Name></tt:PTZConfiguration>`
				if f.noPTZ[p] {
					cfg = ""
				}
				b.WriteString(`<trt:Profiles token="` + p + `"><tt:Name>` + p + `</tt:Name>` + cfg + `</trt:Profiles>`)
			}
			f.mu.Unlock()
			b.WriteString(`</trt:GetProfilesResponse>`)
			_, _ = fmt.Fprintf(w, envelope, b.String())
		case "Stop":
			_, _ = fmt.Fprintf(w, envelope, `<tptz:StopResponse `+ptzNS+`/>`)
		case "RelativeMove":
			_, _ = fmt.Fprintf(w, envelope, `<tptz:RelativeMoveResponse `+ptzNS+`/>`)
		case "ContinuousMove":
			_, _ = fmt.Fprintf(w, envelope, `<tptz:ContinuousMoveResponse `+ptzNS+`/>`)
		case "GetStatus":
			f.mu.Lock()
			ms := ""
			if f.moveStatus != "" {
				ms = `<tt:MoveStatus>` + f.moveStatus + `</tt:MoveStatus>`
			}
			f.mu.Unlock()
			_, _ = fmt.Fprintf(w, envelope, `<tptz:GetStatusResponse `+ptzNS+`><tptz:PTZStatus>`+
				`<tt:Position><tt:PanTilt x="0.5" y="0.25"/><tt:Zoom x="0.1"/></tt:Position>`+ms+`</tptz:PTZStatus></tptz:GetStatusResponse>`)
		default:
			faultReply(w, "unexpected operation "+name)
		}
	}))
	url = f.srv.URL
	t.Cleanup(f.srv.Close)
	t.Cleanup(f.releaseAll) // runs before srv.Close: held handlers return
	return f
}

// releaseAll lets every held handler return. It is idempotent.
func (f *ptzFx) releaseAll() { f.relOnce.Do(func() { close(f.release) }) }

// bg runs fn on a goroutine that the test waits for at cleanup, after releasing
// every held handler. Register it after any global seam swap so the goroutine
// cannot outlive that swap.
func (f *ptzFx) bg(t *testing.T, fn func()) {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); fn() }()
	t.Cleanup(func() { f.releaseAll(); wg.Wait() })
}

// faultReply writes a SOAP fault with HTTP 500.
func faultReply(w http.ResponseWriter, reason string) {
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = fmt.Fprintf(w, envelope, `<s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code><s:Reason><s:Text xml:lang="en">`+reason+`</s:Text></s:Reason></s:Fault>`)
}

// dropConn closes the connection without a reply: a transport error.
func dropConn(w http.ResponseWriter) {
	if hj, ok := w.(http.Hijacker); ok {
		if c, _, err := hj.Hijack(); err == nil {
			_ = c.Close()
		}
	}
}

// hold blocks until the fixture is released or the request goes away.
func (f *ptzFx) hold(r *http.Request) {
	select {
	case <-f.release:
	case <-r.Context().Done():
	}
}

func (f *ptzFx) on(op string, h func(n int, w http.ResponseWriter, r *http.Request, body string) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.behave[op] = h
}

func (f *ptzFx) setStatus(ms string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.moveStatus = ms
}

func (f *ptzFx) named(op string) []ptzOp {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []ptzOp
	for _, o := range f.ops {
		if o.name == op {
			out = append(out, o)
		}
	}
	return out
}

func (f *ptzFx) count(op string) int { return len(f.named(op)) }

func (f *ptzFx) all() []ptzOp {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ptzOp(nil), f.ops...)
}

// waitCount waits until at least n requests named op have arrived.
func (f *ptzFx) waitCount(t *testing.T, op string, n int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for f.count(op) < n {
		if time.Now().After(deadline) {
			t.Fatalf("only %d %s request(s) arrived within %v, want %d", f.count(op), op, within, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// camera returns the camera config for the fixture, opted in to control.
func (f *ptzFx) camera(timeoutSeconds int) *config.Camera {
	return &config.Camera{ID: "fx", Endpoint: f.srv.URL + "/device_service", Username: "u", Password: "fixture-pw",
		Control: true, TimeoutSeconds: timeoutSeconds}
}

// deps returns Deps over the fixture as camera fx.
func (f *ptzFx) deps(timeoutSeconds int) Deps {
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{"fx": f.camera(timeoutSeconds)}})
	return Deps{Reg: reg, Log: quietLog()}
}
