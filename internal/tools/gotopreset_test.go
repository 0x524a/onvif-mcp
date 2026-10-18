package tools

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	onvif "github.com/0x524a/onvif-go"
	"github.com/0x524a/onvif-go/server"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
	"github.com/0x524a/onvif-mcp/internal/testcam"
)

const gotoTool = "ptz.goto_preset"

// presetRig is a server with the PTZ read and write tools over one testcam,
// reachable as cam-a (opted in) and cam-fixed (not opted in).
type presetRig struct {
	cs     *mcp.ClientSession
	cam    *testcam.Cam
	policy *safety.Policy
	audit  *auditBuf
}

func newPresetRig(t *testing.T, control bool) *presetRig {
	t.Helper()
	cam := testcam.Start(t)
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a":     {ID: "cam-a", Endpoint: cam.Endpoint(), Username: cam.Username(), Password: cam.Password(), Control: true},
		"cam-fixed": {ID: "cam-fixed", Endpoint: cam.Endpoint(), Username: cam.Username(), Password: cam.Password()},
	}})
	r := &presetRig{cam: cam, audit: &auditBuf{}}
	r.policy = safety.NewPolicy(safety.PolicyOptions{
		ControlEnabled: control, Cameras: reg, Interval: time.Hour, Burst: 1,
		Log: slog.New(slog.NewJSONHandler(r.audit, nil)),
	})
	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	d := Deps{Reg: reg, Log: quietLog(), Policy: r.policy}
	RegisterMedia(srv, d)
	RegisterPTZReads(srv, d)
	RegisterPTZWrites(srv, d)
	r.cs = connectTo(t, srv)
	return r
}

func (r *presetRig) args(extra map[string]any) map[string]any {
	m := map[string]any{"camera": "cam-a", "profile": r.cam.ProfileToken(), "preset": r.cam.PresetToken()}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func toolNames(t *testing.T, cs *mcp.ClientSession) map[string]bool {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]bool{}
	for _, x := range res.Tools {
		m[x.Name] = true
	}
	return m
}

// presetPosition reads the preset's stored position straight from the camera,
// not through the tool under test.
func presetPosition(t *testing.T, cam *testcam.Cam) server.PTZPosition {
	t.Helper()
	c, err := onvif.NewClient(cam.Endpoint(), onvif.WithCredentials(cam.Username(), cam.Password()))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	ps, err := c.GetPresets(context.Background(), cam.ProfileToken())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		if p.Token == cam.PresetToken() && p.PTZPosition != nil && p.PTZPosition.PanTilt != nil && p.PTZPosition.Zoom != nil {
			return server.PTZPosition{Pan: p.PTZPosition.PanTilt.X, Tilt: p.PTZPosition.PanTilt.Y, Zoom: p.PTZPosition.Zoom.X}
		}
	}
	t.Fatalf("preset %q has no position on the camera", cam.PresetToken())
	return server.PTZPosition{}
}

func TestGotoPresetIsAbsentWhenControlIsOffAndStillNamedByThePolicy(t *testing.T) {
	r := newPresetRig(t, false)
	if toolNames(t, r.cs)[gotoTool] {
		t.Fatal("the write tool must not be listed while control is off")
	}
	if got := r.policy.GatedTools(); len(got) != 1 || got[0] != gotoTool {
		t.Errorf("gated tools = %v, the policy must still name it", got)
	}
	if _, err := r.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: gotoTool, Arguments: r.args(map[string]any{"dry_run": false})}); err == nil {
		t.Error("calling an unregistered tool must fail")
	}
}

func TestGotoPresetIsListedWhenControlIsOnWithAgentFacingSchema(t *testing.T) {
	r := newPresetRig(t, true)
	res, err := r.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var tool *mcp.Tool
	for _, x := range res.Tools {
		if x.Name == gotoTool {
			tool = x
		}
	}
	if tool == nil {
		t.Fatal("write tool missing with control on")
	}
	for _, want := range []string{"media.profiles", "ptz.presets", "dry_run", "ptz.status"} {
		if !strings.Contains(tool.Description, want) {
			t.Errorf("description lacks %q: %s", want, tool.Description)
		}
	}
	b := wireOf(t, tool.InputSchema)
	for _, want := range []string{"media.profiles", "ptz.presets", "defaults to true"} {
		if !strings.Contains(b, want) {
			t.Errorf("input schema lacks %q: %s", want, b)
		}
	}
	if a := tool.Annotations; a == nil || a.ReadOnlyHint || a.DestructiveHint == nil || !*a.DestructiveHint {
		t.Errorf("annotations = %+v", a)
	}
}

func TestGotoPresetDryRunDoesRealWorkAndLeavesTheCameraUnmoved(t *testing.T) {
	r := newPresetRig(t, true)
	before := r.cam.PTZPosition()
	want := presetPosition(t, r.cam)
	if before == want {
		t.Fatal("harness: the preset must differ from the starting position")
	}

	res := call(t, r.cs, gotoTool, r.args(nil)) // dry_run omitted
	d := dataMap(t, res)
	if d["executed"] != false || d["dry_run"] != true {
		t.Errorf("a dry run must say nothing moved: %v", d)
	}
	if d["preset"] != r.cam.PresetToken() || d["profile"] != r.cam.ProfileToken() {
		t.Errorf("echo = %v", d)
	}
	for k, w := range map[string]float64{"target_pan": want.Pan, "target_tilt": want.Tilt, "target_zoom": want.Zoom} {
		if got, ok := d[k].(float64); !ok || math.Abs(got-w) > 1e-6 {
			t.Errorf("%s = %v, want %v", k, d[k], w)
		}
	}
	// The testcam reports no limits; a dry run must say so rather than invent any.
	if _, ok := d["reported_limits"]; ok || !strings.Contains(wire(t, res), "limits not reported") {
		t.Errorf("unreported limits must be absent and said to be unreported: %v", d)
	}
	note, _ := d["note"].(string)
	if !strings.Contains(note, "dry_run false") || strings.HasSuffix(note, "...") {
		t.Errorf("note must say exactly what to send: %q", note)
	}
	if after := r.cam.PTZPosition(); after != before {
		t.Errorf("dry run moved the camera: %+v -> %+v", before, after)
	}
	a := r.audit.records(t)
	last := a[len(a)-1]
	if last["dry_run"] != true || last["executed"] != false || last["outcome"] != "dry_run" || last["target"] != r.cam.PresetToken() {
		t.Errorf("audit = %v", last)
	}
	if strings.Contains(wire(t, res), "hunter") || strings.Contains(wire(t, res), r.cam.Password()) {
		t.Error("password in output")
	}
}

func TestGotoPresetRealRunMovesTheCameraToThePresetOnce(t *testing.T) {
	r := newPresetRig(t, true)
	before := r.cam.PTZPosition()
	want := presetPosition(t, r.cam)

	res := call(t, r.cs, gotoTool, r.args(map[string]any{"dry_run": false}))
	d := dataMap(t, res)
	if d["executed"] != true || d["dry_run"] != false {
		t.Errorf("data = %v", d)
	}
	if note, _ := d["note"].(string); !strings.Contains(note, "ptz.status") || !strings.Contains(note, "in progress") {
		t.Errorf("note must say motion may continue and point to ptz.status: %q", note)
	}
	after := r.cam.PTZPosition()
	if after == before {
		t.Fatal("a real move left the camera where it was; the write did not reach the device")
	}
	if math.Abs(after.Pan-want.Pan) > 1e-6 || math.Abs(after.Tilt-want.Tilt) > 1e-6 || math.Abs(after.Zoom-want.Zoom) > 1e-6 {
		t.Errorf("camera at %+v, preset is %+v", after, want)
	}
	a := r.audit.records(t)
	last := a[len(a)-1]
	if last["executed"] != true || last["dry_run"] != false || last["outcome"] != "ok" || last["target"] != r.cam.PresetToken() {
		t.Errorf("audit = %v", last)
	}
}

func TestGotoPresetUnknownPresetIsNotFoundAndDoesNotMove(t *testing.T) {
	r := newPresetRig(t, true)
	before := r.cam.PTZPosition()
	for _, dry := range []bool{true, false} {
		res := call(t, r.cs, gotoTool, r.args(map[string]any{"preset": "no-such-preset", "dry_run": dry}))
		code, hint := errCode(t, res)
		if !res.IsError || code != "not_found" || !strings.Contains(hint, "ptz.presets") {
			t.Fatalf("dry=%v: code=%q hint=%q: %s", dry, code, hint, wire(t, res))
		}
	}
	if r.cam.PTZPosition() != before {
		t.Error("a rejected call moved the camera")
	}
	a := r.audit.records(t)
	if last := a[len(a)-1]; last["outcome"] != "not_found" || last["target"] != "no-such-preset" {
		t.Errorf("audit = %v", last)
	}
}

func TestGotoPresetUnknownProfileIsNotFoundWithAHint(t *testing.T) {
	r := newPresetRig(t, true)
	before := r.cam.PTZPosition()
	res := call(t, r.cs, gotoTool, r.args(map[string]any{"profile": "no-such-profile", "dry_run": false}))
	code, hint := errCode(t, res)
	if code != "not_found" || !strings.Contains(hint, "media.profiles") {
		t.Fatalf("code=%q hint=%q", code, hint)
	}
	if r.cam.PTZPosition() != before {
		t.Error("moved")
	}
}

func TestGotoPresetCameraWithoutAGrantIsBlockedAndUnmoved(t *testing.T) {
	r := newPresetRig(t, true)
	before := r.cam.PTZPosition()
	for _, dry := range []bool{true, false} {
		res := call(t, r.cs, gotoTool, r.args(map[string]any{"camera": "cam-fixed", "dry_run": dry}))
		if code, _ := errCode(t, res); code != "blocked_by_policy" {
			t.Fatalf("dry=%v: %s", dry, wire(t, res))
		}
	}
	if r.cam.PTZPosition() != before {
		t.Error("a camera that did not opt in moved")
	}
}

func TestGotoPresetSecondRealMoveIsRateLimitedAndTheCameraMovedOnce(t *testing.T) {
	fx := newPresetFixture(t, presetFixtureOpts{})
	cs := fx.rig(t, true)
	args := map[string]any{"camera": "fx", "profile": "prof", "preset": "p1", "dry_run": false}
	dataMap(t, call(t, cs, gotoTool, args))

	res := call(t, cs, gotoTool, args)
	if code, _ := errCode(t, res); code != "blocked_by_policy" {
		t.Fatalf("second call: %s", wire(t, res))
	}
	e := res.StructuredContent.(map[string]any)["error"].(map[string]any)
	if e["retry_after_seconds"] == nil || e["retryable"] != true {
		t.Errorf("a rate limit must say how long to wait: %v", e)
	}
	if fx.gotoCalls.Load() != 1 {
		t.Errorf("GotoPreset sent %d times, want 1", fx.gotoCalls.Load())
	}
	// A dry run is still allowed and consumes nothing.
	dataMap(t, call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": "prof", "preset": "p1"}))
	if fx.gotoCalls.Load() != 1 {
		t.Error("the dry run sent GotoPreset")
	}
}

func TestGotoPresetSchemaInvalidDryRunIsRejectedAndDoesNotMove(t *testing.T) {
	r := newPresetRig(t, true)
	before := r.cam.PTZPosition()
	res := call(t, r.cs, gotoTool, r.args(map[string]any{"dry_run": "false"}))
	if !res.IsError {
		t.Fatalf("a string dry_run must be rejected: %s", wire(t, res))
	}
	if r.cam.PTZPosition() != before {
		t.Error("a schema-invalid call moved the camera")
	}
}

func TestGotoPresetConcurrentRealCallsMoveAtMostOnce(t *testing.T) {
	for _, n := range []int{20, 60} {
		fx := newPresetFixture(t, presetFixtureOpts{})
		r := fx.rig(t, true)
		var wg sync.WaitGroup
		var ok atomic.Int32
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := r.CallTool(context.Background(), &mcp.CallToolParams{Name: gotoTool,
					Arguments: map[string]any{"camera": "fx", "profile": "prof", "preset": "p1", "dry_run": false}})
				if err == nil && !res.IsError {
					ok.Add(1)
				}
			}()
		}
		wg.Wait()
		if fx.gotoCalls.Load() != 1 || ok.Load() != 1 {
			t.Fatalf("n=%d: GotoPreset sent %d times, %d calls succeeded; want exactly 1 and 1", n, fx.gotoCalls.Load(), ok.Load())
		}
	}
}

// presetFixture is a hand-written PTZ device: one PTZ profile, presets p1 and
// (optionally) a position-less p2, and a scriptable GotoPreset.
type presetFixture struct {
	srv       *httptest.Server
	gotoCalls atomic.Int32
	opts      presetFixtureOpts
	audit     *auditBuf
	// base, if set, becomes Deps.Base so a test can simulate shutdown.
	base context.Context
}

type presetFixtureOpts struct {
	noPTZConfig bool
	gotoHandler func(w http.ResponseWriter, r *http.Request)
	// override replaces the canned answer for one operation (GetProfiles,
	// GetPresets, GetConfiguration); it receives the request body.
	override map[string]func(w http.ResponseWriter, body string)
	// presets, if set, is the inner XML of GetPresetsResponse.
	presets string
}

func newPresetFixture(t *testing.T, o presetFixtureOpts) *presetFixture {
	t.Helper()
	f := &presetFixture{opts: o, audit: &auditBuf{}}
	ptzCfg := `<tt:PTZConfiguration token="c"><tt:Name>c</tt:Name></tt:PTZConfiguration>`
	if o.noPTZConfig {
		ptzCfg = ""
	}
	presetsXML := `<tptz:Preset token="p1"><tt:Name>Door</tt:Name></tptz:Preset>`
	if o.presets != "" {
		presetsXML = o.presets
	}
	bodies := map[string]string{
		"GetProfiles": `<trt:GetProfilesResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl" ` + ptzNS + `>` +
			`<trt:Profiles token="prof"><tt:Name>main</tt:Name>` + ptzCfg + `</trt:Profiles></trt:GetProfilesResponse>`,
		"GetPresets": `<tptz:GetPresetsResponse ` + ptzNS + `>` +
			presetsXML + `</tptz:GetPresetsResponse>`,
		"GetConfiguration": `<tptz:GetConfigurationResponse ` + ptzNS + `><tptz:PTZConfiguration token="c"><tt:Name>c</tt:Name>` +
			`<tt:PanTiltLimits><tt:Range><tt:URI>u</tt:URI><tt:XRange><tt:Min>-1</tt:Min><tt:Max>1</tt:Max></tt:XRange>` +
			`<tt:YRange><tt:Min>-1</tt:Min><tt:Max>1</tt:Max></tt:YRange></tt:Range></tt:PanTiltLimits>` +
			`</tptz:PTZConfiguration></tptz:GetConfigurationResponse>`,
	}
	var url string
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		raw, _ := io.ReadAll(req.Body)
		body := string(raw)
		w.Header().Set("Content-Type", "application/soap+xml")
		switch {
		case strings.Contains(body, "GetCapabilities"):
			_, _ = fmt.Fprintf(w, envelope, `<tds:GetCapabilitiesResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:Capabilities>`+
				`<tt:PTZ xmlns:tt="http://www.onvif.org/ver10/schema"><tt:XAddr>`+url+`/ptz</tt:XAddr></tt:PTZ>`+
				`<tt:Media xmlns:tt="http://www.onvif.org/ver10/schema"><tt:XAddr>`+url+`/media</tt:XAddr></tt:Media>`+
				`</tds:Capabilities></tds:GetCapabilitiesResponse>`)
		case strings.Contains(body, "GotoPreset"):
			f.gotoCalls.Add(1)
			if o.gotoHandler != nil {
				o.gotoHandler(w, req)
				return
			}
			_, _ = fmt.Fprintf(w, envelope, `<tptz:GotoPresetResponse `+ptzNS+`/>`)
		default:
			for op, h := range o.override {
				if strings.Contains(body, op) {
					h(w, body)
					return
				}
			}
			for op, b := range bodies {
				if strings.Contains(body, op) {
					_, _ = fmt.Fprintf(w, envelope, b)
					return
				}
			}
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	url = f.srv.URL
	t.Cleanup(f.srv.Close)
	return f
}

// rig serves the write tool over the fixture as camera fx (opted in, 1s timeout).
func (f *presetFixture) rig(t *testing.T, control bool) *mcp.ClientSession {
	t.Helper()
	cam := fixtureCamera(f.srv)
	cam.Control = true
	cam.TimeoutSeconds = 1
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{"fx": cam}})
	policy := safety.NewPolicy(safety.PolicyOptions{ControlEnabled: control, Cameras: reg, Interval: time.Hour, Burst: 1,
		Log: slog.New(slog.NewJSONHandler(f.audit, nil))})
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterPTZWrites(srv, Deps{Reg: reg, Log: quietLog(), Policy: policy, Base: f.base})
	return connectTo(t, srv)
}

func TestGotoPresetProfileWithoutPTZConfigurationIsNotSupported(t *testing.T) {
	fx := newPresetFixture(t, presetFixtureOpts{noPTZConfig: true})
	cs := fx.rig(t, true)
	for _, dry := range []bool{true, false} {
		res := call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": "prof", "preset": "p1", "dry_run": dry})
		code, hint := errCode(t, res)
		if code != "not_supported" || !strings.Contains(hint, "has_ptz") {
			t.Fatalf("dry=%v code=%q hint=%q", dry, code, hint)
		}
	}
	if fx.gotoCalls.Load() != 0 {
		t.Error("GotoPreset must not be sent for a profile without PTZ")
	}
}

func TestGotoPresetWithNoStoredPositionStillWorksForADryRun(t *testing.T) {
	fx := newPresetFixture(t, presetFixtureOpts{})
	cs := fx.rig(t, true)
	res := call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": "prof", "preset": "p1"})
	d := dataMap(t, res)
	for _, k := range []string{"target_pan", "target_tilt", "target_zoom"} {
		if _, ok := d[k]; ok {
			t.Errorf("an unreported position must not be invented as %q: %v", k, d)
		}
	}
	if !strings.Contains(wire(t, res), "not reported") {
		t.Errorf("the target must read as not reported: %s", wire(t, res))
	}
	if _, ok := d["reported_limits"].(map[string]any); !ok {
		t.Errorf("limits were reported by the fixture: %v", d)
	}
	if fx.gotoCalls.Load() != 0 {
		t.Error("a dry run sent GotoPreset")
	}
}

func TestGotoPresetFaultIsDeviceFaultWithSOAPAndSaysTheStateIsUnknown(t *testing.T) {
	fx := newPresetFixture(t, presetFixtureOpts{gotoHandler: func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, envelope, `<s:Fault><s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>ter:ActionNotSupported</s:Value></s:Subcode></s:Code>`+
			`<s:Reason><s:Text xml:lang="en">motor busy</s:Text></s:Reason></s:Fault>`)
	}})
	cs := fx.rig(t, true)
	res := call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": "prof", "preset": "p1", "dry_run": false})
	code, hint := errCode(t, res)
	if code != "device_fault" {
		t.Fatalf("code=%q: %s", code, wire(t, res))
	}
	e := res.StructuredContent.(map[string]any)["error"].(map[string]any)
	if e["soap"] == nil || e["operation"] != "GotoPreset" || e["retryable"] != false {
		t.Errorf("error = %v", e)
	}
	if !strings.Contains(hint, "may or may not") || !strings.Contains(hint, "ptz.status") {
		t.Errorf("hint = %q", hint)
	}
	if fx.gotoCalls.Load() != 1 {
		t.Errorf("GotoPreset sent %d times, want exactly 1 (no retry)", fx.gotoCalls.Load())
	}
}

func TestGotoPresetTimeoutAfterSendCarriesTheUnknownStateHintAndIsNotRetryable(t *testing.T) {
	fx := newPresetFixture(t, presetFixtureOpts{gotoHandler: func(_ http.ResponseWriter, r *http.Request) {
		select { // the camera received the command and never answers
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}})
	cs := fx.rig(t, true)
	res := call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": "prof", "preset": "p1", "dry_run": false})
	code, hint := errCode(t, res)
	if code != "timeout" {
		t.Fatalf("code=%q: %s", code, wire(t, res))
	}
	e := res.StructuredContent.(map[string]any)["error"].(map[string]any)
	if e["retryable"] != false || e["operation"] != "GotoPreset" {
		t.Errorf("a timeout after send must not be retryable blind: %v", e)
	}
	if !strings.Contains(hint, "may or may not") || !strings.Contains(hint, "ptz.status") {
		t.Errorf("hint = %q", hint)
	}
	if fx.gotoCalls.Load() != 1 {
		t.Errorf("GotoPreset sent %d times, want 1", fx.gotoCalls.Load())
	}
}

// A call that fails validation sent nothing, so it must not spend the camera's
// movement budget: with an hour-long refill and a burst of 1, a mistyped token
// followed by the right one still moves the camera.
func TestMistypedPresetDoesNotBurnTheRateBudget(t *testing.T) {
	fx := newPresetFixture(t, presetFixtureOpts{})
	cs := fx.rig(t, true)
	bad := call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": "prof", "preset": "nope", "dry_run": false})
	if code, _ := errCode(t, bad); code != "not_found" {
		t.Fatalf("code = %q", code)
	}
	good := call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": "prof", "preset": "p1", "dry_run": false})
	if good.IsError {
		t.Fatalf("a mistyped token cost the budget: %s", wire(t, good))
	}
	if fx.gotoCalls.Load() != 1 {
		t.Errorf("GotoPreset sent %d times", fx.gotoCalls.Load())
	}
	// A real send does spend it.
	again := call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": "prof", "preset": "p1", "dry_run": false})
	if code, _ := errCode(t, again); code != "blocked_by_policy" {
		t.Errorf("second real send: code = %q, want blocked_by_policy", code)
	}
}

// A failure after the send keeps the budget spent.
func TestFailureAfterTheSendKeepsTheBudgetSpent(t *testing.T) {
	fx := newPresetFixture(t, presetFixtureOpts{gotoHandler: plainReply(500, "boom")})
	cs := fx.rig(t, true)
	args := map[string]any{"camera": "fx", "profile": "prof", "preset": "p1", "dry_run": false}
	call(t, cs, gotoTool, args)
	res := call(t, cs, gotoTool, args)
	if code, _ := errCode(t, res); code != "blocked_by_policy" {
		t.Errorf("code = %q, want blocked_by_policy after a sent command", code)
	}
	if fx.gotoCalls.Load() != 1 {
		t.Errorf("GotoPreset sent %d times", fx.gotoCalls.Load())
	}
}

// Two ids for one device, hit concurrently with valid and mistyped presets,
// move it at most once: refunds only ever follow a call that sent nothing.
func TestTwoIDsOneDeviceMixedConcurrentCallsMoveAtMostOnce(t *testing.T) {
	for _, n := range []int{20, 60} {
		fx := newPresetFixture(t, presetFixtureOpts{})
		ca, cb := fixtureCamera(fx.srv), fixtureCamera(fx.srv)
		ca.ID, cb.ID = "a", "b"
		ca.Control, cb.Control = true, true
		reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{"a": ca, "b": cb}})
		policy := safety.NewPolicy(safety.PolicyOptions{ControlEnabled: true, Cameras: reg, Interval: time.Hour, Burst: 1,
			Log: slog.New(slog.NewJSONHandler(&auditBuf{}, nil))})
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		RegisterPTZWrites(srv, Deps{Reg: reg, Log: quietLog(), Policy: policy})
		cs := connectTo(t, srv)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				id, preset := "a", "p1"
				if i%2 == 1 {
					id = "b"
				}
				if i%3 == 0 {
					preset = "nope"
				}
				_, _ = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: gotoTool,
					Arguments: map[string]any{"camera": id, "profile": "prof", "preset": preset, "dry_run": false}})
			}(i)
		}
		wg.Wait()
		if got := fx.gotoCalls.Load(); got > 1 {
			t.Fatalf("n=%d: GotoPreset sent %d times for one device, want at most 1", n, got)
		}
	}
}
