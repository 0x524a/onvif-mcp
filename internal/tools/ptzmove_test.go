package tools

import (
	"context"
	"math"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
	"github.com/0x524a/onvif-mcp/internal/testcam"
)

const moveTool = "ptz.move_relative"

const (
	panTiltSpace = "http://www.onvif.org/ver10/tptz/PanTiltSpaces/TranslationGenericSpace"
	zoomSpace    = "http://www.onvif.org/ver10/tptz/ZoomSpaces/TranslationGenericSpace"
)

func (r *motionRig) move(t *testing.T, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	m := map[string]any{"camera": "fx", "profile": "prof"}
	for k, v := range args {
		m[k] = v
	}
	return call(t, r.cs, moveTool, m)
}

func TestMoveRelativeIsAbsentWithControlOffButNamedByThePolicy(t *testing.T) {
	r := newMotionRig(t, newPtzFx(t), false, true, 5)
	if toolNames(t, r.cs)[moveTool] {
		t.Fatal("must not be listed while control is off")
	}
	found := false
	for _, g := range r.policy.GatedTools() {
		found = found || g == moveTool
	}
	if !found {
		t.Errorf("gated = %v", r.policy.GatedTools())
	}
}

func TestMoveRelativeDryRunIsTheDefaultAndSendsNothing(t *testing.T) {
	fx := newPtzFx(t)
	r := newMotionRig(t, fx, true, true, 5)
	res := r.move(t, map[string]any{"pan": 0.1, "tilt": -0.2, "zoom": 0.05}) // dry_run omitted
	d := dataMap(t, res)
	if d["executed"] != false || d["dry_run"] != true || d["mode"] != "relative" || d["profile"] != "prof" {
		t.Errorf("data = %v", d)
	}
	req, _ := d["requested"].(map[string]any)
	if req["pan"] != 0.1 || req["tilt"] != -0.2 || req["zoom"] != 0.05 {
		t.Errorf("requested = %v", req)
	}
	space, _ := d["space_sent"].(string)
	if !strings.Contains(space, panTiltSpace) || !strings.Contains(space, zoomSpace) {
		t.Errorf("space_sent = %q", space)
	}
	if n := fx.count("RelativeMove"); n != 0 {
		t.Fatalf("a dry run sent %d RelativeMove requests", n)
	}
	if fx.count("GetProfiles") != 1 {
		t.Errorf("a dry run must validate the profile with a read: GetProfiles=%d", fx.count("GetProfiles"))
	}
	if note, _ := d["note"].(string); !strings.Contains(note, "dry_run false") {
		t.Errorf("note = %q", note)
	}
	a := r.audit.records(t)
	last := a[len(a)-1]
	if last["dry_run"] != true || last["executed"] != false || last["motion_mode"] != "relative" ||
		last["motion_pan"] != 0.1 || last["motion_tilt"] != -0.2 || last["motion_zoom"] != 0.05 || last["target"] != "prof" {
		t.Errorf("audit = %v", last)
	}
}

func TestMoveRelativeRealCallSendsOneTranslationWithExplicitSpaceAndNoSpeed(t *testing.T) {
	fx := newPtzFx(t)
	r := newMotionRig(t, fx, true, true, 5)
	res := r.move(t, map[string]any{"pan": 0.1, "zoom": -0.05, "dry_run": false})
	d := dataMap(t, res)
	if d["executed"] != true || d["dry_run"] != false {
		t.Errorf("data = %v", d)
	}
	ops := fx.named("RelativeMove")
	if len(ops) != 1 {
		t.Fatalf("RelativeMove requests = %d", len(ops))
	}
	b := ops[0].body
	for _, want := range []string{
		`<tptz:ProfileToken>prof</tptz:ProfileToken>`,
		`x="0.1"`, `y="0"`, `space="` + panTiltSpace + `"`,
		`x="-0.05"`, `space="` + zoomSpace + `"`,
	} {
		if !strings.Contains(b, want) {
			t.Errorf("body lacks %s:\n%s", want, b)
		}
	}
	if strings.Contains(b, "Speed") {
		t.Errorf("a Speed element was sent:\n%s", b)
	}
	if note, _ := d["note"].(string); !strings.Contains(note, "ptz.status") || len(note) > 256 {
		t.Errorf("note = %q", note)
	}
	a := r.audit.records(t)
	last := a[len(a)-1]
	if last["executed"] != true || last["outcome"] != "ok" || last["motion_pan"] != 0.1 {
		t.Errorf("audit = %v", last)
	}
	// Pan travels with tilt in one PanTilt vector, the omitted tilt as 0: the
	// audit records the exact numbers sent.
	if last["motion_tilt"] != 0.0 {
		t.Errorf("the audit must record the tilt 0 that was sent: %v", last)
	}
	if strings.Contains(wire(t, res), "fixture-pw") {
		t.Error("password in output")
	}
}

func TestMoveRelativeAZeroTiltAloneSendsOnlyPanTilt(t *testing.T) {
	fx := newPtzFx(t)
	r := newMotionRig(t, fx, true, true, 5)
	dataMap(t, r.move(t, map[string]any{"tilt": 0.2, "dry_run": false}))
	b := fx.named("RelativeMove")[0].body
	if !strings.Contains(b, `x="0"`) || !strings.Contains(b, `y="0.2"`) || strings.Contains(b, zoomSpace) {
		t.Errorf("body:\n%s", b)
	}
}

func TestMoveRelativeBoundaryIsInclusiveAndJustAboveIsRefused(t *testing.T) {
	fx := newPtzFx(t)
	r := newMotionRig(t, fx, true, true, 5)
	if res := r.move(t, map[string]any{"pan": 0.25, "tilt": -0.25, "zoom": 0.25}); res.IsError {
		t.Fatalf("0.25 must be accepted: %s", wire(t, res))
	}
	for _, v := range []float64{math.Nextafter(0.25, 1), -math.Nextafter(0.25, 1), 1, -1, 100} {
		res := r.move(t, map[string]any{"pan": v})
		code, hint := errCode(t, res)
		if code != "invalid_argument" {
			t.Fatalf("pan %v: code %q: %s", v, code, wire(t, res))
		}
		all := wire(t, res)
		for _, want := range []string{"pan", "-0.25", "0.25", "server cap"} {
			if !strings.Contains(all, want) {
				t.Errorf("pan %v: refusal lacks %q: %s", v, want, all)
			}
		}
		if !strings.Contains(hint, "ptz.move_relative") {
			t.Errorf("hint must give a corrected call: %q", hint)
		}
	}
}

func TestMoveRelativeRefusalsAreLegibleNotSentAndRefundTheToken(t *testing.T) {
	fx := newPtzFx(t)
	fx.noPTZ["noptz"] = true
	fx.profiles = append(fx.profiles, "noptz")
	r := newMotionRig(t, fx, true, true, 5)
	cases := map[string]map[string]any{
		"no axes":         {},
		"all zero":        {"pan": 0, "tilt": 0, "zoom": 0},
		"negative zero":   {"pan": math.Copysign(0, -1)},
		"pan over cap":    {"pan": 0.3},
		"tilt over cap":   {"tilt": -0.3},
		"zoom over cap":   {"zoom": 0.26},
		"unknown profile": {"pan": 0.1, "profile": "nope"},
		"no PTZ profile":  {"pan": 0.1, "profile": "noptz"},
		"profile too big": {"pan": 0.1, "profile": strings.Repeat("A", 129)},
	}
	for name, args := range cases {
		for _, dry := range []bool{true, false} {
			a := map[string]any{"dry_run": dry}
			for k, v := range args {
				a[k] = v
			}
			res := r.move(t, a)
			code, hint := errCode(t, res)
			if !res.IsError || (code != "invalid_argument" && code != "not_supported") || hint == "" {
				t.Errorf("%s dry=%v: code=%q hint=%q: %.300s", name, dry, code, hint, wire(t, res))
			}
		}
	}
	if n := fx.count("RelativeMove"); n != 0 {
		t.Fatalf("%d RelativeMove requests for refused calls", n)
	}
	// Every refused real call was NotSent, so the single token is still there.
	if res := r.move(t, map[string]any{"pan": 0.1, "dry_run": false}); res.IsError {
		t.Fatalf("the rate token was not refunded: %s", wire(t, res))
	}
	for _, rec := range r.audit.records(t) {
		if rec["blocked"] == false && rec["dry_run"] == false && rec["outcome"] != "ok" && rec["executed"] != false {
			t.Errorf("a refusal was audited as executed: %v", rec)
		}
	}
}

func TestMoveRelativeUnknownProfileNamesTheRealOnes(t *testing.T) {
	fx := newPtzFx(t, "main", "sub")
	r := newMotionRig(t, fx, true, true, 5)
	res := r.move(t, map[string]any{"pan": 0.1, "profile": "typo"})
	_, hint := errCode(t, res)
	if !strings.Contains(hint, "main") || !strings.Contains(hint, "sub") {
		t.Errorf("hint = %q", hint)
	}
}

func TestValidateRelativeRefusesNonFiniteNumbers(t *testing.T) {
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		in := MoveRelativeIn{Profile: "p", Pan: &v}
		if _, te := validateRelative(in); te == nil || te.Code != mcperr.CodeInvalidArgument || !te.NotSent || !strings.Contains(te.Message, "pan") {
			t.Errorf("%v: %+v", v, te)
		}
	}
	z := math.Copysign(0, -1)
	one := 0.1
	ax, te := validateRelative(MoveRelativeIn{Profile: "p", Pan: &z, Tilt: &one})
	if te != nil || math.Signbit(*ax.axes().Pan) {
		t.Errorf("-0 must be normalised to 0: %+v %+v", ax, te)
	}
}

func TestMoveRelativeFaultAfterSendCarriesTheUnknownStateHint(t *testing.T) {
	fx := newPtzFx(t)
	fx.on("RelativeMove", func(_ int, w http.ResponseWriter, _ *http.Request, _ string) bool {
		faultReply(w, "limit reached")
		return true
	})
	r := newMotionRig(t, fx, true, true, 5)
	res := r.move(t, map[string]any{"pan": 0.1, "dry_run": false})
	_, hint := errCode(t, res)
	if !res.IsError || !strings.Contains(hint, "may or may not have been executed") || errField(res, "retryable") != false {
		t.Fatalf("hint=%q retryable=%v: %s", hint, errField(res, "retryable"), wire(t, res))
	}
	if fx.count("RelativeMove") != 1 {
		t.Errorf("a failed move must never be retried: %d requests", fx.count("RelativeMove"))
	}
	a := r.audit.records(t)
	if last := a[len(a)-1]; last["executed"] != true || last["outcome"] != "device_fault" {
		t.Errorf("audit = %v", last)
	}
}

func TestMoveRelativeSecondRealCallInsideTheIntervalIsRateLimited(t *testing.T) {
	fx := newPtzFx(t)
	r := newMotionRig(t, fx, true, true, 5)
	dataMap(t, r.move(t, map[string]any{"pan": 0.1, "dry_run": false}))
	res := r.move(t, map[string]any{"pan": 0.1, "dry_run": false})
	code, _ := errCode(t, res)
	if code != "blocked_by_policy" || !strings.Contains(wire(t, res), "retry_after_seconds") {
		t.Fatalf("code=%q: %s", code, wire(t, res))
	}
	if fx.count("RelativeMove") != 1 {
		t.Errorf("RelativeMove requests = %d", fx.count("RelativeMove"))
	}
}

func TestMoveRelativeIsDestructiveAndNotIdempotent(t *testing.T) {
	r := newMotionRig(t, newPtzFx(t), true, true, 5)
	res, err := r.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range res.Tools {
		if x.Name != moveTool {
			continue
		}
		a := x.Annotations
		if a == nil || a.IdempotentHint || a.ReadOnlyHint || a.DestructiveHint == nil || !*a.DestructiveHint ||
			a.OpenWorldHint == nil || *a.OpenWorldHint {
			t.Errorf("annotations = %+v", a)
		}
		return
	}
	t.Fatal("not listed")
}

func TestMoveRelativeNeverReadsConfigurationEvenFromACameraThatFaultsOnIt(t *testing.T) {
	fx := newPtzFx(t)
	fx.on("GetConfiguration", func(_ int, w http.ResponseWriter, _ *http.Request, _ string) bool {
		faultReply(w, "no configuration")
		return true
	})
	r := newMotionRig(t, fx, true, true, 5)
	for _, dry := range []bool{true, false} {
		if res := r.move(t, map[string]any{"pan": 0.1, "dry_run": dry}); res.IsError {
			t.Fatalf("dry=%v: %s", dry, wire(t, res))
		}
		time.Sleep(0)
	}
	if n := fx.count("GetConfiguration") + fx.count("GetConfigurations") + fx.count("GetNode"); n != 0 {
		t.Errorf("%d configuration reads", n)
	}
}

func TestMoveRelativeSchemaAndDescriptionsMakeNoUnverifiedClaims(t *testing.T) {
	r := newMotionRig(t, newPtzFx(t), true, true, 5)
	res, err := r.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	banned := regexp.MustCompile(`(?i)\b(left|right|up|down|degrees?|radians?|clockwise|counter-?clockwise|fraction|zoom in|zoom out|towards?)\b`)
	for _, x := range res.Tools {
		if x.Name != moveTool {
			continue
		}
		schema := wireOf(t, x.InputSchema)
		if m := banned.FindString(x.Description + schema); m != "" {
			t.Errorf("unverified claim %q in the tool text/schema", m)
		}
		if strings.Contains(schema, `"minimum"`) || strings.Contains(schema, `"maximum"`) ||
			strings.Contains(schema, "exclusiveM") {
			t.Errorf("the range refusal must belong to the handler, not the SDK schema: %s", schema)
		}
		if strings.Count(schema, `"minLength":1`) < 1 {
			t.Errorf("profile must have minLength 1: %s", schema)
		}
		for _, want := range []string{"0.25", "dry_run", "ptz.stop", "ptz.status", "media.profiles", "defined by the camera"} {
			if !strings.Contains(x.Description+schema, want) {
				t.Errorf("text lacks %q", want)
			}
		}
		// Required: camera, profile. Axes optional.
		if !strings.Contains(schema, `"required":["camera","profile"]`) {
			t.Errorf("required = ? %s", schema)
		}
		return
	}
	t.Fatal("not listed")
}

// ---- against the onvif-go virtual camera ----------------------------------

func TestMoveRelativeEndToEndMovesTheTestcamByTheRequestedDelta(t *testing.T) {
	cam := testcam.Start(t)
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a": {ID: "cam-a", Endpoint: cam.Endpoint(), Username: cam.Username(), Password: cam.Password(), Control: true},
	}})
	policy := safety.NewPolicy(safety.PolicyOptions{ControlEnabled: true, Cameras: reg, Interval: time.Hour, Burst: 1, Log: quietLog()})
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterPTZMotion(srv, Deps{Reg: reg, Log: quietLog(), Policy: policy})
	cs := connectTo(t, srv)

	before := cam.PTZPosition()
	res := call(t, cs, moveTool, map[string]any{"camera": "cam-a", "profile": cam.ProfileToken(),
		"pan": 0.1, "tilt": -0.05, "zoom": 0.2, "dry_run": false})
	if d := dataMap(t, res); d["executed"] != true {
		t.Fatalf("data = %v", d)
	}
	after := cam.PTZPosition()
	near := func(a, b float64) bool { return math.Abs(a-b) < 1e-6 }
	if !near(after.Pan-before.Pan, 0.1) || !near(after.Tilt-before.Tilt, -0.05) || !near(after.Zoom-before.Zoom, 0.2) {
		t.Errorf("moved from %+v to %+v, want a delta of (0.1, -0.05, 0.2)", before, after)
	}
}
