package tools

import (
	"context"
	"log/slog"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
)

const contTool = "ptz.move_continuous"

const (
	panTiltVelSpace = "http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace"
	zoomVelSpace    = "http://www.onvif.org/ver10/tptz/ZoomSpaces/VelocityGenericSpace"
)

// contRig serves the motion tools and ptz.goto_preset over a fixture as:
//
//	fx          control, attested (unless attest is false), username u
//	fx-plain    control, not attested, same endpoint
//	fx-stopper  control, same device (trailing slash), username stopper, so the
//	            fixture can tell a ptz.stop round's Stop from the move's own
//	fx-fixed    no control
type contRig struct {
	cs     *mcp.ClientSession
	fx     *ptzFx
	policy *safety.Policy
	audit  *auditBuf
	cancel context.CancelFunc // cancels Deps.Base: a shutdown
}

type contOpts struct {
	attest      bool
	burst       int
	motionBurst int
	noLog       bool
}

func newContRig(t *testing.T, fx *ptzFx, o contOpts) *contRig {
	t.Helper()
	fastGates(t, time.Second, time.Millisecond)
	fastMotion(t)
	cam := func(id, user, suffix string, control, attest bool) *config.Camera {
		return &config.Camera{ID: id, Endpoint: fx.srv.URL + "/device_service" + suffix, Username: user, Password: "fixture-pw",
			Control: control, PTZHonoursTimeout: attest, TimeoutSeconds: 5}
	}
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"fx":         cam("fx", "u", "", true, o.attest),
		"fx-plain":   cam("fx-plain", "u", "", true, false),
		"fx-stopper": cam("fx-stopper", "stopper", "/", true, false),
		"fx-fixed":   cam("fx-fixed", "u", "", false, false),
	}})
	if o.burst == 0 {
		o.burst = 50
	}
	r := &contRig{fx: fx, audit: &auditBuf{}}
	opts := safety.PolicyOptions{ControlEnabled: true, Cameras: reg, Interval: time.Millisecond, Burst: o.burst,
		MotionBurstSeconds: o.motionBurst}
	if !o.noLog {
		opts.Log = slog.New(slog.NewJSONHandler(r.audit, nil))
	}
	r.policy = safety.NewPolicy(opts)
	base, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	t.Cleanup(cancel)
	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	d := Deps{Reg: reg, Log: quietLog(), Policy: r.policy, Base: base}
	RegisterPTZMotion(srv, d)
	RegisterPTZWrites(srv, d)
	r.cs = connectTo(t, srv)
	return r
}

// fastMotion shortens the stop-section seams for the test.
func fastMotion(t *testing.T) {
	t.Helper()
	gap, att, budget, timer, hook := motionStopGap, motionStopAttempt, motionStopBudget, motionTimer, afterContinuousSend
	motionStopGap, motionStopAttempt, motionStopBudget = time.Millisecond, 2*time.Second, 8*time.Second
	t.Cleanup(func() {
		motionStopGap, motionStopAttempt, motionStopBudget, motionTimer, afterContinuousSend = gap, att, budget, timer, hook
	})
}

// instantTimer makes the motion deadline fire at once and records the waits the
// handler asked for.
func instantTimer(t *testing.T) *[]time.Duration {
	t.Helper()
	var mu sync.Mutex
	asked := &[]time.Duration{}
	motionTimer = func(d time.Duration) (<-chan time.Time, func() bool) {
		mu.Lock()
		*asked = append(*asked, d)
		mu.Unlock()
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch, func() bool { return true }
	}
	return asked
}

// heldTimer makes the motion deadline never fire, so only a cancel, a shutdown
// or an interrupt ends the wait.
func heldTimer(t *testing.T) {
	t.Helper()
	motionTimer = func(time.Duration) (<-chan time.Time, func() bool) {
		return make(chan time.Time), func() bool { return true }
	}
}

func (r *contRig) move(t *testing.T, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	m := map[string]any{"camera": "fx", "profile": "prof", "duration_seconds": 1.5, "pan": 0.2}
	for k, v := range args {
		if v == nil {
			delete(m, k)
			continue
		}
		m[k] = v
	}
	return call(t, r.cs, contTool, m)
}

func (r *contRig) records(t *testing.T, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, rec := range r.audit.records(t) {
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

// waitAudit waits for an audit record with msg.
func (r *contRig) waitAudit(t *testing.T, msg string, within time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if recs := r.records(t, msg); len(recs) > 0 {
			return recs[len(recs)-1]
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %q audit record within %v", msg, within)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func stopsBy(fx *ptzFx, user string) []ptzOp {
	var out []ptzOp
	for _, o := range fx.named("Stop") {
		if strings.Contains(o.body, ">"+user+"</") {
			out = append(out, o)
		}
	}
	return out
}

// ---- registration and gating -----------------------------------------------

func TestContinuousIsHiddenUnlessACameraAttests(t *testing.T) {
	r := newContRig(t, newPtzFx(t), contOpts{attest: false})
	if toolNames(t, r.cs)[contTool] {
		t.Fatal("ptz.move_continuous must not be listed when no camera sets ptz_honours_timeout")
	}
	gated, timed := r.policy.GatedTools(), r.policy.TimedTools()
	if !strings.Contains(strings.Join(gated, ","), contTool) || len(timed) != 1 || timed[0] != contTool {
		t.Errorf("gated=%v timed=%v: the policy must still name it", gated, timed)
	}
	if !toolNames(t, newContRig(t, newPtzFx(t), contOpts{attest: true}).cs)[contTool] {
		t.Fatal("listed once a camera attests")
	}
}

func TestContinuousIsAbsentWithControlOff(t *testing.T) {
	fx := newPtzFx(t)
	cam := fx.camera(5)
	cam.PTZHonoursTimeout = true
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{"fx": cam}})
	p := safety.NewPolicy(safety.PolicyOptions{Cameras: reg, Log: quietLog()})
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterPTZMotion(srv, Deps{Reg: reg, Log: quietLog(), Policy: p})
	if toolNames(t, connectTo(t, srv))[contTool] {
		t.Fatal("listed with control off")
	}
	if RegisteredCount(srv) != 0 || ClaimedCount(srv) != 3 {
		t.Errorf("registered=%d claimed=%d", RegisteredCount(srv), ClaimedCount(srv))
	}
}

func TestContinuousRefusesAnUnattestedOrUngrantedCameraBeforeAnyTraffic(t *testing.T) {
	fx := newPtzFx(t)
	r := newContRig(t, fx, contOpts{attest: true})
	for _, cam := range []string{"fx-plain", "fx-fixed"} {
		for _, dry := range []bool{true, false} {
			res := r.move(t, map[string]any{"camera": cam, "dry_run": dry})
			code, hint := errCode(t, res)
			if code != "blocked_by_policy" || hint == "" {
				t.Errorf("%s dry=%v: %s", cam, dry, wire(t, res))
			}
		}
	}
	res := r.move(t, map[string]any{"camera": "fx-plain", "dry_run": false})
	if !strings.Contains(wire(t, res), "ptz_honours_timeout") {
		t.Errorf("an unattested refusal must name the setting: %s", wire(t, res))
	}
	if n := len(fx.all()); n != 0 {
		t.Fatalf("%d requests reached the camera", n)
	}
}

func TestContinuousSchemaAndDescriptionsAreLegibleAndClaimNothingUnverified(t *testing.T) {
	r := newContRig(t, newPtzFx(t), contOpts{attest: true})
	res, err := r.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	banned := regexp.MustCompile(`(?i)\b(left|right|up|down|degrees?|radians?|clockwise|counter-?clockwise|fraction|zoom in|zoom out|towards?)\b`)
	for _, x := range res.Tools {
		if x.Name != contTool {
			continue
		}
		schema := wireOf(t, x.InputSchema)
		if m := banned.FindString(x.Description + schema); m != "" {
			t.Errorf("unverified claim %q", m)
		}
		if strings.Contains(schema, `"minimum"`) || strings.Contains(schema, `"maximum"`) || strings.Contains(schema, "exclusiveM") {
			t.Errorf("range refusals belong to the handler: %s", schema)
		}
		if !strings.Contains(schema, `"required":["camera","profile","duration_seconds"]`) {
			t.Errorf("duration_seconds must be required, with no default: %s", schema)
		}
		for _, want := range []string{"0.5", "duration_seconds", "dry_run", "ptz.stop", "ptz.status", "media.profiles",
			"ptz_honours_timeout", "blocks", "defined by the camera", "Timeout"} {
			if !strings.Contains(x.Description+schema, want) {
				t.Errorf("text lacks %q", want)
			}
		}
		a := x.Annotations
		if a == nil || a.IdempotentHint || a.ReadOnlyHint || a.DestructiveHint == nil || !*a.DestructiveHint {
			t.Errorf("annotations = %+v", a)
		}
		return
	}
	t.Fatal("not listed")
}

// ---- validation -------------------------------------------------------------

func TestContinuousDryRunIsTheDefaultSendsNothingAndPredictsTheCall(t *testing.T) {
	fx := newPtzFx(t)
	r := newContRig(t, fx, contOpts{attest: true})
	res := r.move(t, map[string]any{"pan": 0.2, "tilt": -0.1, "zoom": 0.05, "duration_seconds": 1.5})
	d := dataMap(t, res)
	if d["dry_run"] != true || d["executed"] != false || d["mode"] != "continuous" || d["duration_seconds"] != 1.5 ||
		d["camera_timeout"] != "PT1.5S" || d["stopped_by"] != nil {
		t.Errorf("data = %v", d)
	}
	req, _ := d["requested"].(map[string]any)
	if req["pan"] != 0.2 || req["tilt"] != -0.1 || req["zoom"] != 0.05 {
		t.Errorf("requested = %v", req)
	}
	if s, _ := d["space_sent"].(string); !strings.Contains(s, panTiltVelSpace) || !strings.Contains(s, zoomVelSpace) {
		t.Errorf("space_sent = %q", s)
	}
	if fx.count("ContinuousMove")+fx.count("Stop") != 0 || fx.count("GetProfiles") != 1 {
		t.Fatalf("ops = %+v", fx.all())
	}
	if len(r.records(t, "motion started")) != 0 {
		t.Error("a dry run started no motion")
	}
}

func TestContinuousRefusalsAreLegibleNotSentAndCostNothing(t *testing.T) {
	fx := newPtzFx(t)
	fx.noPTZ["noptz"] = true
	fx.profiles = append(fx.profiles, "noptz")
	r := newContRig(t, fx, contOpts{attest: true, burst: 1})
	cases := map[string]map[string]any{
		"no axes":         {"pan": nil},
		"all zero":        {"pan": 0, "tilt": 0, "zoom": 0},
		"negative zero":   {"pan": math.Copysign(0, -1)},
		"pan over cap":    {"pan": math.Nextafter(0.5, 1)},
		"tilt over cap":   {"tilt": -0.6},
		"zoom over cap":   {"zoom": 1},
		"duration zero":   {"duration_seconds": 0},
		"duration short":  {"duration_seconds": math.Nextafter(0.5, 0)},
		"duration long":   {"duration_seconds": math.Nextafter(5, 6)},
		"duration neg":    {"duration_seconds": -1},
		"unknown profile": {"profile": "nope"},
		"no PTZ profile":  {"profile": "noptz"},
		"profile too big": {"profile": strings.Repeat("A", 129)},
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
	res := r.move(t, map[string]any{"pan": 0, "dry_run": false})
	if _, hint := errCode(t, res); !strings.Contains(hint, "ptz.stop") {
		t.Errorf("all-zero must point at ptz.stop: %q", hint)
	}
	res = r.move(t, map[string]any{"pan": 0.9, "dry_run": false})
	for _, want := range []string{"pan", "-0.5", "0.5", "server cap", "refused, not clamped"} {
		if !strings.Contains(wire(t, res), want) {
			t.Errorf("over-cap refusal lacks %q: %s", want, wire(t, res))
		}
	}
	if fx.count("ContinuousMove")+fx.count("Stop") != 0 {
		t.Fatal("a refused call sent a command")
	}
	// Burst 1 and every refusal NotSent: the token and the motion budget are intact.
	instantTimer(t)
	if res := r.move(t, map[string]any{"dry_run": false, "duration_seconds": 5}); res.IsError {
		t.Fatalf("token or budget was spent by a refusal: %s", wire(t, res))
	}
}

func TestContinuousDurationIsRequiredBySchema(t *testing.T) {
	fx := newPtzFx(t)
	r := newContRig(t, fx, contOpts{attest: true})
	res := r.move(t, map[string]any{"duration_seconds": nil, "dry_run": false})
	if !res.IsError || fx.count("ContinuousMove") != 0 {
		t.Fatalf("no duration: %s", wire(t, res))
	}
}

func TestValidateContinuousRefusesNonFiniteNumbers(t *testing.T) {
	ok := 0.1
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		v := v
		for name, in := range map[string]MoveContinuousIn{
			"pan":      {Profile: "p", Pan: &v, DurationSeconds: 1},
			"duration": {Profile: "p", Pan: &ok, DurationSeconds: v},
		} {
			if _, _, te := validateContinuous(in); te == nil || te.Code != "invalid_argument" || !te.NotSent {
				t.Errorf("%s %v: %+v", name, v, te)
			}
		}
	}
}

// The ONVIF Timeout is an xs:duration: never an exponent, never absent, rounded
// up to whole milliseconds so the camera never stops before the server would.
func TestONVIFTimeoutFormatting(t *testing.T) {
	for in, want := range map[float64]string{
		0.5: "PT0.5S", 1: "PT1S", 1.5: "PT1.5S", 2.3: "PT2.3S", 5: "PT5S",
		1.0001: "PT1.001S", 4.9999: "PT5S", 0.500001: "PT0.501S", 3.14159: "PT3.142S",
		// Below a microsecond is float noise, not a request: it is not rounded up.
		0.5000001: "PT0.5S",
	} {
		if got := onvifTimeout(in); got != want {
			t.Errorf("onvifTimeout(%v) = %q, want %q", in, got, want)
		}
	}
	re := regexp.MustCompile(`^PT[0-9]+(\.[0-9]{1,3})?S$`)
	for i := 0; i <= 45000; i++ {
		d := 0.5 + float64(i)*0.0001
		got := onvifTimeout(d)
		if !re.MatchString(got) {
			t.Fatalf("onvifTimeout(%v) = %q", d, got)
		}
		secs, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimPrefix(got, "PT"), "S"), 64)
		if err != nil || secs < d-1e-9 || secs > d+0.001+1e-9 {
			t.Fatalf("onvifTimeout(%v) = %q: not d rounded up to the millisecond", d, got)
		}
	}
}

// ---- a real move -------------------------------------------------------------

func TestContinuousRealMoveSendsOneMoveThenItsOwnStopAtTheDeadline(t *testing.T) {
	fx := newPtzFx(t)
	r := newContRig(t, fx, contOpts{attest: true})
	start := time.Now()
	res := r.move(t, map[string]any{"pan": 0.2, "zoom": -0.1, "duration_seconds": 0.5, "dry_run": false})
	elapsed := time.Since(start)
	d := dataMap(t, res)
	if d["executed"] != true || d["stopped_by"] != "deadline" || d["stop_status"] != "confirmed_idle" || d["camera_timeout"] != "PT0.5S" {
		t.Fatalf("data = %v", d)
	}
	moves, stops := fx.named("ContinuousMove"), fx.named("Stop")
	if len(moves) != 1 || len(stops) != 1 {
		t.Fatalf("ContinuousMove=%d Stop=%d", len(moves), len(stops))
	}
	b := moves[0].body
	for _, want := range []string{`<tptz:ProfileToken>prof</tptz:ProfileToken>`, `<tptz:Timeout>PT0.5S</tptz:Timeout>`,
		`x="0.2"`, `y="0"`, `space="` + panTiltVelSpace + `"`, `x="-0.1"`, `space="` + zoomVelSpace + `"`} {
		if !strings.Contains(b, want) {
			t.Errorf("ContinuousMove body lacks %s:\n%s", want, b)
		}
	}
	if !strings.Contains(stops[0].body, "<tptz:PanTilt>true</tptz:PanTilt>") || !strings.Contains(stops[0].body, "<tptz:Zoom>true</tptz:Zoom>") {
		t.Errorf("Stop body:\n%s", stops[0].body)
	}
	gap := stops[0].at.Sub(moves[0].at)
	if gap < 450*time.Millisecond || gap > 1500*time.Millisecond {
		t.Errorf("Stop came %v after ContinuousMove, want about the 0.5s duration", gap)
	}
	if elapsed > 5*time.Second {
		t.Errorf("call took %v", elapsed)
	}
	// The move's stop owns its client: no second Initialize for it.
	if n := fx.count("GetCapabilities"); n != 1 {
		t.Errorf("GetCapabilities = %d, want 1 (plan and stop share the call's client)", n)
	}
	started, stopped := r.records(t, "motion started"), r.records(t, "motion stopped")
	if len(started) != 1 || len(stopped) != 1 || started[0]["motion_id"] == nil || started[0]["motion_id"] != stopped[0]["motion_id"] ||
		started[0]["duration_ms"] != 500.0 || started[0]["motion_pan"] != 0.2 || stopped[0]["stopped_by"] != "deadline" {
		t.Errorf("started=%v stopped=%v", started, stopped)
	}
}
