package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	onvif "github.com/0x524a/onvif-go"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
	"github.com/0x524a/onvif-mcp/internal/testcam"
)

// motionRig serves the motion tools over a fixture as camera fx (opted in) and
// fx-fixed (same device, not opted in).
type motionRig struct {
	cs     *mcp.ClientSession
	fx     *ptzFx
	policy *safety.Policy
	audit  *auditBuf
	d      Deps
}

func newMotionRig(t *testing.T, fx *ptzFx, control, withLog bool, timeoutSeconds int) *motionRig {
	t.Helper()
	fastGates(t, time.Second, time.Millisecond)
	cam := fx.camera(timeoutSeconds)
	fixed := fx.camera(timeoutSeconds)
	fixed.ID, fixed.Control = "fx-fixed", false
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{"fx": cam, "fx-fixed": fixed}})
	r := &motionRig{fx: fx, audit: &auditBuf{}}
	opts := safety.PolicyOptions{ControlEnabled: control, Cameras: reg, Interval: time.Hour, Burst: 1}
	if withLog {
		opts.Log = slog.New(slog.NewJSONHandler(r.audit, nil))
	}
	r.policy = safety.NewPolicy(opts)
	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	r.d = Deps{Reg: reg, Log: quietLog(), Policy: r.policy}
	RegisterPTZMotion(srv, r.d)
	r.cs = connectTo(t, srv)
	return r
}

func (r *motionRig) stop(t *testing.T, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	m := map[string]any{"camera": "fx", "profile": "prof"}
	for k, v := range args {
		m[k] = v
	}
	return call(t, r.cs, "ptz.stop", m)
}

func TestPTZStopIsAbsentWithControlOffButNamedByThePolicy(t *testing.T) {
	r := newMotionRig(t, newPtzFx(t), false, true, 5)
	if toolNames(t, r.cs)["ptz.stop"] {
		t.Fatal("ptz.stop must not be listed while control is off")
	}
	found := false
	for _, g := range r.policy.GatedTools() {
		found = found || g == "ptz.stop"
	}
	if !found || len(r.policy.HaltTools()) != 1 {
		t.Errorf("gated=%v halt=%v", r.policy.GatedTools(), r.policy.HaltTools())
	}
	if _, err := r.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "ptz.stop",
		Arguments: map[string]any{"camera": "fx", "profile": "prof"}}); err == nil {
		t.Error("calling an unregistered tool must fail")
	}
	if r.fx.count("Stop") != 0 {
		t.Error("nothing may reach the camera")
	}
}

func TestPTZStopSchemaHasNoDryRunAndIsAgentLegible(t *testing.T) {
	r := newMotionRig(t, newPtzFx(t), true, true, 5)
	res, err := r.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range res.Tools {
		if x.Name != "ptz.stop" {
			continue
		}
		b := wireOf(t, x.InputSchema)
		if strings.Contains(b, "dry_run") {
			t.Errorf("ptz.stop must have no dry_run field: %s", b)
		}
		for _, want := range []string{"media.profiles", "has_ptz"} {
			if !strings.Contains(b, want) {
				t.Errorf("schema lacks %q: %s", want, b)
			}
		}
		for _, want := range []string{"no dry run", "not rate limited", "per profile", "confirmed_idle", "sent_unconfirmed", "ptz.status"} {
			if !strings.Contains(x.Description, want) {
				t.Errorf("description lacks %q: %s", want, x.Description)
			}
		}
		a := x.Annotations
		if a == nil || a.ReadOnlyHint || a.DestructiveHint == nil || *a.DestructiveHint || !a.IdempotentHint {
			t.Errorf("annotations = %+v", a)
		}
		return
	}
	t.Fatal("ptz.stop not listed with control on")
}

func TestPTZStopSendsOneStopForBothAxesAndNeverEchoesCredentials(t *testing.T) {
	fx := newPtzFx(t)
	r := newMotionRig(t, fx, true, true, 5)
	res := r.stop(t, nil)
	d := dataMap(t, res)
	if d["executed"] != true || d["stop_status"] != "confirmed_idle" || d["profile"] != "prof" {
		t.Errorf("data = %v", d)
	}
	ops := fx.named("Stop")
	if len(ops) != 1 || !strings.Contains(ops[0].body, "<tptz:PanTilt>true</tptz:PanTilt>") || !strings.Contains(ops[0].body, "<tptz:Zoom>true</tptz:Zoom>") {
		t.Fatalf("Stop requests = %+v", ops)
	}
	if n, _ := d["note"].(string); n == "" || len(n) > 256 || !strings.Contains(n, "per profile") {
		t.Errorf("note = %q", n)
	}
	if strings.Contains(wire(t, res), "fixture-pw") {
		t.Error("password in output")
	}
	a := r.audit.records(t)
	last := a[len(a)-1]
	if last["tool"] != "ptz.stop" || last["executed"] != true || last["dry_run"] != false || last["outcome"] != "ok" || last["target"] != "prof" {
		t.Errorf("audit = %v", last)
	}
}

func TestPTZStopWithNoLogAndTwentyCallsIsNeverRefused(t *testing.T) {
	r := newMotionRig(t, newPtzFx(t), true, false, 5)
	for i := 0; i < 20; i++ {
		if res := r.stop(t, nil); res.IsError {
			t.Fatalf("call %d refused: %s", i, wire(t, res))
		}
	}
}

func TestPTZStopRefusals(t *testing.T) {
	fx := newPtzFx(t)
	r := newMotionRig(t, fx, true, true, 5)
	if code, _ := errCode(t, r.stop(t, map[string]any{"camera": "nope"})); code != "not_found" {
		t.Errorf("unknown camera: %q", code)
	}
	res := r.stop(t, map[string]any{"camera": "fx-fixed"})
	if code, hint := errCode(t, res); code != "blocked_by_policy" || !strings.Contains(hint, "control") {
		t.Errorf("not granted: %q %q", code, hint)
	}
	if len(fx.all()) != 0 {
		t.Error("a refused call reached the camera")
	}
}

func TestPTZStopHugeProfileIsRefusedBeforeAnyCameraTraffic(t *testing.T) {
	fx := newPtzFx(t)
	r := newMotionRig(t, fx, true, true, 5)
	res := r.stop(t, map[string]any{"profile": strings.Repeat("A", 1<<20)})
	if code, _ := errCode(t, res); code != "invalid_argument" {
		t.Fatalf("code = %q: %.300s", code, wire(t, res))
	}
	if len(fx.all()) != 0 {
		t.Error("camera traffic for an oversized profile")
	}
	for _, rec := range r.audit.records(t) {
		if s, _ := json.Marshal(rec); len(s) > 1500 {
			t.Errorf("audit record of %d bytes: the hostile profile must be bounded", len(s))
		}
	}
}

func TestPTZStopSOAPFaultAfterDispatchIsFailedWithRetryNowHint(t *testing.T) {
	fx := newPtzFx(t)
	fx.on("Stop", func(_ int, w http.ResponseWriter, _ *http.Request, _ string) bool {
		faultReply(w, "motor busy")
		return true
	})
	r := newMotionRig(t, fx, true, true, 5)
	res := r.stop(t, nil)
	code, hint := errCode(t, res)
	if !res.IsError || code != "device_fault" || !strings.Contains(hint, "ptz.stop again") {
		t.Fatalf("code=%q hint=%q: %s", code, hint, wire(t, res))
	}
	if !strings.Contains(wire(t, res), "the stop was not delivered") {
		t.Errorf("message must say the stop was not delivered: %s", wire(t, res))
	}
	a := r.audit.records(t)
	if last := a[len(a)-1]; last["executed"] != true || last["outcome"] != "device_fault" {
		t.Errorf("audit = %v", last)
	}
}

func TestPTZStopInitializeFailureIsFailedAndAuditedAsNotExecuted(t *testing.T) {
	for name, hook := range map[string]func(int, http.ResponseWriter, *http.Request, string) bool{
		"unreachable": func(_ int, w http.ResponseWriter, _ *http.Request, _ string) bool { dropConn(w); return true },
		"soap fault": func(_ int, w http.ResponseWriter, _ *http.Request, _ string) bool {
			faultReply(w, "not ready")
			return true
		},
	} {
		t.Run(name, func(t *testing.T) {
			fx := newPtzFx(t)
			fx.on("GetCapabilities", hook)
			r := newMotionRig(t, fx, true, true, 4)
			res := r.stop(t, nil)
			_, hint := errCode(t, res)
			if !res.IsError || !strings.Contains(hint, "ptz.stop again") {
				t.Fatalf("%s", wire(t, res))
			}
			a := r.audit.records(t)
			if last := a[len(a)-1]; last["executed"] != false {
				t.Errorf("audit = %v", last)
			}
			if fx.count("Stop") != 0 {
				t.Error("no Stop can have been sent")
			}
		})
	}
}

func TestPTZStopUnknownProfileListsRealProfilesAndSendsNoStop(t *testing.T) {
	fx := newPtzFx(t, "main", "sub")
	r := newMotionRig(t, fx, true, true, 5)
	res := r.stop(t, map[string]any{"profile": "typo"})
	code, hint := errCode(t, res)
	if code != "invalid_argument" || !strings.Contains(hint, "main") || !strings.Contains(hint, "sub") || strings.Contains(hint, "ptz.stop again") {
		t.Fatalf("code=%q hint=%q", code, hint)
	}
	if fx.count("Stop") != 0 {
		t.Error("a Stop was sent for a profile that does not exist")
	}
}

func TestPTZStopConcurrentWithStatusUsesOneClientPerCallUnderRace(t *testing.T) {
	fx := newPtzFx(t)
	r := newMotionRig(t, fx, true, true, 5)
	var mu sync.Mutex
	seen := map[*onvif.Client]int{}
	r.d.clientHook = func(c *onvif.Client) {
		mu.Lock()
		seen[c]++
		mu.Unlock()
	}
	// A second server over the same registry, so the hook sees the rig's calls.
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterPTZMotion(srv, r.d)
	RegisterPTZReads(srv, r.d)
	cs := connectTo(t, srv)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			call(t, cs, "ptz.stop", map[string]any{"camera": "fx", "profile": "prof"})
		}()
		go func() {
			defer wg.Done()
			call(t, cs, "ptz.status", map[string]any{"camera": "fx", "profile": "prof"})
		}()
	}
	wg.Wait()
	for c, n := range seen {
		if n != 1 {
			t.Errorf("client %p handed out %d times", c, n)
		}
	}
	if len(seen) == 0 {
		t.Error("the hook saw no client")
	}
}

// ---- against the onvif-go virtual camera ----------------------------------

func TestPTZStopEndToEndStopsAMovingTestcam(t *testing.T) {
	cam := testcam.Start(t)
	fastGates(t, time.Second, 10*time.Millisecond)
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a": {ID: "cam-a", Endpoint: cam.Endpoint(), Username: cam.Username(), Password: cam.Password(), Control: true},
	}})
	policy := safety.NewPolicy(safety.PolicyOptions{ControlEnabled: true, Cameras: reg, Log: quietLog()})
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterPTZMotion(srv, Deps{Reg: reg, Log: quietLog(), Policy: policy})
	cs := connectTo(t, srv)

	// Put the virtual camera in MOVING with a raw ContinuousMove (it ignores the
	// timeout and stays MOVING until a Stop).
	c, err := onvif.NewClient(cam.Endpoint(), onvif.WithCredentials(cam.Username(), cam.Password()))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	timeout := "PT30S"
	if err := c.ContinuousMove(context.Background(), cam.ProfileToken(),
		&onvif.PTZSpeed{PanTilt: &onvif.Vector2D{X: 0.1, Y: 0}}, &timeout); err != nil {
		t.Fatal(err)
	}
	if pt, _ := cam.PTZMoveState(); pt != "MOVING" {
		t.Fatalf("harness: the camera should be MOVING, is %q", pt)
	}

	res := call(t, cs, "ptz.stop", map[string]any{"camera": "cam-a", "profile": cam.ProfileToken()})
	d := dataMap(t, res)
	if d["stop_status"] != "confirmed_idle" {
		t.Fatalf("data = %v", d)
	}
	if pt, _ := cam.PTZMoveState(); pt != "IDLE" {
		t.Errorf("after ptz.stop the camera is %q, want IDLE", pt)
	}
	_ = fmt.Sprint
}

func TestPTZStopNotesFitTheOutputClipForEveryOutcome(t *testing.T) {
	for name, status := range map[string]string{
		"idle":     idleStatus,
		"moving":   `<tt:PanTilt>MOVING</tt:PanTilt>`,
		"no state": "",
		"unknown":  `<tt:Zoom>UNKNOWN</tt:Zoom>`,
	} {
		t.Run(name, func(t *testing.T) {
			fx := newPtzFx(t)
			fx.setStatus(status)
			r := newMotionRig(t, fx, true, true, 5)
			d := dataMap(t, r.stop(t, nil))
			n, _ := d["note"].(string)
			if len(n) > 256 || strings.HasSuffix(n, "...") || !strings.Contains(n, "per profile") {
				t.Errorf("note (%d bytes) = %q", len(n), n)
			}
		})
	}
}
