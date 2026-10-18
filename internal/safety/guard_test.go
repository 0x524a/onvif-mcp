package safety

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/registry"
)

const tool = "ptz.goto_preset"

func testRegistry() *registry.Registry {
	return registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a":     {ID: "cam-a", Endpoint: "http://192.0.2.1/onvif/device_service", Control: true},
		"cam-b":     {ID: "cam-b", Endpoint: "http://192.0.2.2/onvif/device_service", Control: true},
		"cam-fixed": {ID: "cam-fixed", Endpoint: "http://192.0.2.3/onvif/device_service", Control: false},
	}})
}

// syncBuf is a goroutine-safe buffer for the audit logger.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) records(t *testing.T) []map[string]any {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(s.b.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("audit line is not JSON: %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func newPolicy(controlEnabled bool) (*Policy, *syncBuf, *fakeClock) {
	buf := &syncBuf{}
	clk := newFakeClock()
	p := NewPolicy(PolicyOptions{
		ControlEnabled: controlEnabled,
		Cameras:        testRegistry(),
		Interval:       time.Hour, // no refill unless the test advances the clock
		Burst:          1,
		Clock:          clk.Now,
		Log:            slog.New(slog.NewJSONHandler(buf, nil)),
	})
	return p, buf, clk
}

func TestUnknownCameraIsRefusedBeforeTheLimiter(t *testing.T) {
	p, _, _ := newPolicy(true)
	for i := 0; i < 200; i++ {
		d := p.Evaluate(fmt.Sprintf("attacker-%d", i), tool, false)
		if d.Blocked == nil || d.Blocked.Code != mcperr.CodeNotFound {
			t.Fatalf("unknown camera must be not_found, got %+v", d.Blocked)
		}
	}
	if got := p.Limiter.size(); got != 0 {
		t.Errorf("limiter tracks %d keys after only unknown cameras; it must see none", got)
	}
}

func TestLimiterOnlyEverSeesConfiguredCameras(t *testing.T) {
	p, _, _ := newPolicy(true)
	p.Evaluate("cam-a", tool, false)
	p.Evaluate("nope", tool, false)
	p.Evaluate("cam-fixed", tool, false) // known but not granted: also never reaches the limiter
	if got := p.Limiter.size(); got != 1 {
		t.Errorf("limiter tracks %d keys, want 1 (cam-a only)", got)
	}
}

func TestCameraWithoutGrantIsBlocked(t *testing.T) {
	p, _, _ := newPolicy(true)
	d := p.Evaluate("cam-fixed", tool, false)
	if d.Blocked == nil {
		t.Fatal("a camera that did not opt in must be blocked")
	}
	if d.Blocked.Code != mcperr.CodeBlockedByPolicy {
		t.Errorf("got %s", d.Blocked.Code)
	}
	if d.Blocked.Retryable {
		t.Error("a missing grant is not retryable; it needs a config change")
	}
}

func TestGrantComesFromTheRegistryNotTheCaller(t *testing.T) {
	// Evaluate has no controlAllowed parameter: a tool cannot assert a grant.
	p, _, _ := newPolicy(true)
	if d := p.Evaluate("cam-a", tool, false); d.Blocked != nil {
		t.Fatalf("granted camera was blocked: %+v", d.Blocked)
	}
}

func TestGrantBeatsDryRunOrdering(t *testing.T) {
	// Even a dry run must not reveal anything for a camera that did not opt in.
	p, _, _ := newPolicy(true)
	if d := p.Evaluate("cam-fixed", tool, true); d.Blocked == nil {
		t.Error("a dry run against a non-granted camera must still be blocked")
	}
}

func TestControlDisabledBlocksEverythingDefenceInDepth(t *testing.T) {
	p, _, _ := newPolicy(false)
	for _, dry := range []bool{true, false} {
		d := p.Evaluate("cam-a", tool, dry)
		if d.Blocked == nil || d.Blocked.Code != mcperr.CodeBlockedByPolicy {
			t.Errorf("dry=%v: control disabled must block, got %+v", dry, d.Blocked)
		}
	}
}

func TestDryRunSkipsTheRateLimiter(t *testing.T) {
	// A dry run touches no motor, so it must not consume a token.
	p, _, _ := newPolicy(true)
	for i := 0; i < 5; i++ {
		d := p.Evaluate("cam-a", tool, true)
		if d.Blocked != nil {
			t.Fatalf("dry run %d was blocked: %+v", i, d.Blocked)
		}
		if !d.DryRun {
			t.Error("decision must carry DryRun")
		}
	}
	if d := p.Evaluate("cam-a", tool, false); d.Blocked != nil {
		t.Error("dry runs must not have exhausted the real budget")
	}
}

func TestRateLimitBlocksWithRetryAfter(t *testing.T) {
	p, _, _ := newPolicy(true)
	if d := p.Evaluate("cam-a", tool, false); d.Blocked != nil || d.DryRun {
		t.Fatalf("first real move must proceed: %+v", d)
	}
	d := p.Evaluate("cam-a", tool, false)
	if d.Blocked == nil {
		t.Fatal("second real move must be rate limited")
	}
	if !d.Blocked.Retryable || d.Blocked.RetryAfterSeconds == nil || *d.Blocked.RetryAfterSeconds < 1 {
		t.Errorf("rate limit must be retryable with a delay: %+v", d.Blocked)
	}
	if d.Blocked.Code != mcperr.CodeBlockedByPolicy {
		t.Errorf("code = %s", d.Blocked.Code)
	}
}

func TestRateLimitRecoversAfterInterval(t *testing.T) {
	p, _, clk := newPolicy(true)
	p.Evaluate("cam-a", tool, false)
	clk.Advance(time.Hour)
	if d := p.Evaluate("cam-a", tool, false); d.Blocked != nil {
		t.Errorf("must proceed after the interval: %+v", d.Blocked)
	}
}

func TestRateLimitIsPerCameraThroughPolicy(t *testing.T) {
	p, _, _ := newPolicy(true)
	p.Evaluate("cam-a", tool, false)
	if d := p.Evaluate("cam-b", tool, false); d.Blocked != nil {
		t.Errorf("cam-b throttled by cam-a: %+v", d.Blocked)
	}
}

func TestDefaultsAreTwoSecondsBurstOne(t *testing.T) {
	clk := newFakeClock()
	p := NewPolicy(PolicyOptions{ControlEnabled: true, Cameras: testRegistry(), Clock: clk.Now,
		Log: slog.New(slog.NewJSONHandler(io.Discard, nil))})
	if d := p.Evaluate("cam-a", tool, false); d.Blocked != nil {
		t.Fatal("first move must proceed")
	}
	d := p.Evaluate("cam-a", tool, false)
	if d.Blocked == nil || *d.Blocked.RetryAfterSeconds != 2 {
		t.Fatalf("want a 2s retry-after by default, got %+v", d.Blocked)
	}
	clk.Advance(2 * time.Second)
	if d := p.Evaluate("cam-a", tool, false); d.Blocked != nil {
		t.Errorf("one movement per 2s: must proceed after 2s: %+v", d.Blocked)
	}
}

func TestConfiguredIntervalAndBurst(t *testing.T) {
	clk := newFakeClock()
	p := NewPolicy(PolicyOptions{ControlEnabled: true, Cameras: testRegistry(), Clock: clk.Now,
		Interval: 10 * time.Second, Burst: 3, Log: slog.New(slog.NewJSONHandler(io.Discard, nil))})
	for i := 0; i < 3; i++ {
		if d := p.Evaluate("cam-a", tool, false); d.Blocked != nil {
			t.Fatalf("move %d within burst blocked", i)
		}
	}
	d := p.Evaluate("cam-a", tool, false)
	if d.Blocked == nil || *d.Blocked.RetryAfterSeconds != 10 {
		t.Errorf("want 10s retry-after, got %+v", d.Blocked)
	}
}

func TestConcurrentRealMovesGrantExactlyOne(t *testing.T) {
	p, _, _ := newPolicy(true)
	var ok atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if p.Evaluate("cam-a", tool, false).Blocked == nil {
				ok.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if ok.Load() != 1 {
		t.Errorf("%d concurrent moves proceeded, want 1", ok.Load())
	}
}

func TestNilLimiterFailsClosedForRealMovesOnly(t *testing.T) {
	p, _, _ := newPolicy(true)
	p.Limiter = nil
	if d := p.Evaluate("cam-a", tool, false); d.Blocked == nil || d.Blocked.Code != mcperr.CodeBlockedByPolicy {
		t.Errorf("nil limiter must refuse real moves, got %+v", d.Blocked)
	}
	if d := p.Evaluate("cam-a", tool, true); d.Blocked != nil {
		t.Errorf("nil limiter must not break dry runs: %+v", d.Blocked)
	}
}

func TestNilLogFailsClosedForRealMovesAndDoesNotPanic(t *testing.T) {
	p, _, _ := newPolicy(true)
	p.Log = nil
	if d := p.Evaluate("cam-a", tool, false); d.Blocked == nil {
		t.Error("with no audit log a real move must be refused")
	}
	p.Evaluate("nope", tool, true)
	p.Audit(tool, "cam-a", false, true, "ok")
}

func TestZeroValuePolicyFailsClosedWithoutPanic(t *testing.T) {
	var p Policy
	for _, dry := range []bool{true, false} {
		if d := p.Evaluate("cam-a", tool, dry); d.Blocked == nil {
			t.Errorf("zero Policy must block (dry=%v)", dry)
		}
	}
	if p.WriteRegistered() {
		t.Error("zero Policy must not register write tools")
	}
	p.Audit(tool, "cam-a", true, false, "x")
}

func TestNilPolicyFailsClosedWithoutPanic(t *testing.T) {
	var p *Policy
	if d := p.Evaluate("cam-a", tool, true); d.Blocked == nil {
		t.Error("nil Policy must block")
	}
	if p.WriteRegistered() {
		t.Error("nil Policy must not register write tools")
	}
	p.Audit(tool, "cam-a", true, false, "x")
}

func TestNilCamerasBlocksEverything(t *testing.T) {
	p, _, _ := newPolicy(true)
	p.Cameras = nil
	if d := p.Evaluate("cam-a", tool, true); d.Blocked == nil {
		t.Error("no camera source means no camera is known")
	}
}

func TestWriteRegisteredFollowsControlFlag(t *testing.T) {
	if p, _, _ := newPolicy(false); p.WriteRegistered() {
		t.Error("write tools must not be registered when control is disabled")
	}
	if p, _, _ := newPolicy(true); !p.WriteRegistered() {
		t.Error("write tools must be registered when control is enabled")
	}
}

func TestBlockedAttemptsAreAuditedByTheGuard(t *testing.T) {
	cases := []struct {
		name   string
		cam    string
		enable bool
		dry    bool
		reason string
	}{
		{"unknown", "nope", true, false, ReasonUnknownCamera},
		{"no grant", "cam-fixed", true, false, ReasonCameraNotGranted},
		{"control off", "cam-a", false, true, ReasonControlDisabled},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, buf, _ := newPolicy(c.enable)
			p.Evaluate(c.cam, tool, c.dry)
			recs := buf.records(t)
			if len(recs) != 1 {
				t.Fatalf("want exactly 1 audit line, got %d", len(recs))
			}
			r := recs[0]
			if r["blocked"] != true || r["reason"] != c.reason || r["executed"] != false {
				t.Errorf("bad blocked audit: %v", r)
			}
			if r["tool"] != tool || r["dry_run"] != c.dry || r["control_enabled"] != c.enable {
				t.Errorf("audit missing fields: %v", r)
			}
		})
	}
}

func TestRateLimitedAttemptIsAudited(t *testing.T) {
	p, buf, _ := newPolicy(true)
	p.Evaluate("cam-a", tool, false)
	p.Evaluate("cam-a", tool, false)
	recs := buf.records(t)
	if len(recs) != 1 { // the allowed call is audited by the tool, not the guard
		t.Fatalf("want 1 line (the blocked one), got %d: %v", len(recs), recs)
	}
	if recs[0]["blocked"] != true || recs[0]["reason"] != ReasonRateLimited {
		t.Errorf("bad audit: %v", recs[0])
	}
}

func TestAuditRecordsOutcomeFields(t *testing.T) {
	p, buf, _ := newPolicy(true)
	p.Audit(tool, "cam-a", false, true, "ok")
	r := buf.records(t)[0]
	want := map[string]any{"tool": tool, "camera": "cam-a", "dry_run": false, "executed": true,
		"outcome": "ok", "blocked": false, "control_enabled": true}
	for k, v := range want {
		if r[k] != v {
			t.Errorf("%s = %v, want %v", k, r[k], v)
		}
	}
}

func TestAuditHasNoArgumentOrSecretFields(t *testing.T) {
	p, buf, _ := newPolicy(true)
	p.Audit(tool, "cam-a", false, true, "ok")
	p.Evaluate("nope", tool, false)
	allowed := map[string]bool{"time": true, "level": true, "msg": true, "tool": true, "camera": true,
		"control_enabled": true, "dry_run": true, "executed": true, "outcome": true, "blocked": true, "reason": true,
		"camera_granted": true, "target": true}
	for _, r := range buf.records(t) {
		for k := range r {
			if !allowed[k] {
				t.Errorf("unexpected audit field %q (arguments and secrets must never be logged)", k)
			}
		}
	}
}

func TestAuditScrubsAndBoundsAgentControlledText(t *testing.T) {
	p, buf, _ := newPolicy(true)
	p.Evaluate("http://admin:hunter2@evil/"+strings.Repeat("x", 5000), tool, false)
	p.Audit(tool, "cam-a", false, false, "failed: http://admin:hunter2@192.0.2.1/x "+strings.Repeat("y", 5000))
	for _, r := range buf.records(t) {
		for k, v := range r {
			s, _ := v.(string)
			if strings.Contains(s, "hunter2") {
				t.Errorf("%s leaks userinfo: %q", k, s)
			}
			if len(s) > 400 {
				t.Errorf("%s is %d bytes; agent-controlled text must be bounded", k, len(s))
			}
		}
	}
}

func TestAuditNeutralisesLogInjection(t *testing.T) {
	p, buf, _ := newPolicy(true)
	p.Evaluate("cam\n{\"msg\":\"forged\"}", tool, false)
	if n := len(buf.records(t)); n != 1 {
		t.Errorf("a newline in the camera id forged %d log lines, want 1", n)
	}
}

func TestPolicyDoesNotFormatCredentials(t *testing.T) {
	// The Policy holds a registry; formatting a Policy must stay credential free.
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a": {ID: "cam-a", Endpoint: "http://192.0.2.1/", Password: "hunter2", Control: true},
	}})
	p := NewPolicy(PolicyOptions{ControlEnabled: true, Cameras: reg})
	if s := fmt.Sprintf("%v %+v", p, p); strings.Contains(s, "hunter2") {
		t.Errorf("policy formatting leaks a credential: %s", s)
	}
}

// The camera id is agent input and reaches the scrubber on every refusal, so
// an enormous one must not cost seconds of CPU.
func TestHugeCameraIDIsBoundedBeforeScrubbing(t *testing.T) {
	big := strings.Repeat("a:b@", 2_500_000) // 10 MB
	p, buf, _ := newPolicy(true)
	for name, pol := range map[string]*Policy{"unknown camera": p, "nil policy": nil} {
		t0 := time.Now()
		d := pol.Evaluate(big, tool, false)
		if el := time.Since(t0); el > 500*time.Millisecond {
			t.Errorf("%s: Evaluate took %v", name, el)
		}
		if d.Blocked == nil || len(d.Blocked.Camera) > 300 {
			t.Errorf("%s: blocked camera not bounded: %d bytes", name, len(d.Blocked.Camera))
		}
	}
	for _, r := range buf.records(t) {
		if c, _ := r["camera"].(string); len(c) > 64 || !strings.HasSuffix(c, "...") {
			t.Errorf("audit camera = %q", c)
		}
	}
}

func TestAuditCleanMarksEveryCutAndKeepsShortText(t *testing.T) {
	if got := clean("cam-a", 64); got != "cam-a" {
		t.Errorf("short text changed: %q", got)
	}
	if got := clean(strings.Repeat("x", 100), 64); len(got) != 64 || !strings.HasSuffix(got, "...") {
		t.Errorf("clean = %q", got)
	}
}

func TestAuditRecordsWhetherTheCameraWasGranted(t *testing.T) {
	p, buf, _ := newPolicy(true)
	p.Audit(tool, "cam-a", false, true, "ok")
	p.Audit(tool, "cam-fixed", true, false, "dry_run")
	p.Audit(tool, "nope", true, false, "dry_run")
	p.Evaluate("cam-fixed", tool, false) // refused: not granted
	recs := buf.records(t)
	want := []bool{true, false, false, false}
	for i, r := range recs {
		if r["camera_granted"] != want[i] {
			t.Errorf("record %d camera_granted = %v, want %v: %v", i, r["camera_granted"], want[i], r)
		}
	}
	if len(recs) != len(want) {
		t.Fatalf("records = %d", len(recs))
	}
}

func TestAuditTargetIsOptionalScrubbedAndBounded(t *testing.T) {
	p, buf, _ := newPolicy(true)
	p.Audit(tool, "cam-a", false, true, "ok")
	p.Audit(tool, "cam-a", false, true, "ok", WithTarget("preset-3"))
	p.Audit(tool, "cam-a", false, true, "ok", WithTarget("http://admin:s3cretpw@h/"+strings.Repeat("x", 500)))
	recs := buf.records(t)
	if _, has := recs[0]["target"]; has {
		t.Errorf("no target given, none expected: %v", recs[0])
	}
	if recs[1]["target"] != "preset-3" {
		t.Errorf("target = %v", recs[1]["target"])
	}
	long, _ := recs[2]["target"].(string)
	if strings.Contains(long, "s3cretpw") || len(long) > 64 || !strings.HasSuffix(long, "...") {
		t.Errorf("target not scrubbed and bounded: %q", long)
	}
}

func TestAuditRejectedLogsAWarnWithoutArguments(t *testing.T) {
	p, buf, _ := newPolicy(true)
	p.AuditRejected(tool)
	r := buf.records(t)
	if len(r) != 1 {
		t.Fatalf("records = %v", r)
	}
	a := r[0]
	if a["level"] != "WARN" || a["tool"] != tool || a["blocked"] != true || a["executed"] != false ||
		a["reason"] != ReasonInvalidArguments || a["outcome"] != "blocked" {
		t.Errorf("record = %v", a)
	}
	if _, has := a["camera"]; has {
		t.Errorf("a rejected call's camera is unvalidated and must not be logged: %v", a)
	}
	var nilPolicy *Policy
	nilPolicy.AuditRejected(tool) // must not panic
}

func TestAuditRejectedWithControlOffSaysControlDisabled(t *testing.T) {
	p, buf, _ := newPolicy(false)
	p.AuditRejected(tool)
	r := buf.records(t)
	if len(r) != 1 || r[0]["reason"] != ReasonControlDisabled {
		t.Errorf("records = %v", r)
	}
}

func TestAttemptTrackerSeesHandlerReach(t *testing.T) {
	ctx, tr := TrackAttempt(context.Background())
	if tr.Reached() {
		t.Fatal("not reached yet")
	}
	NoteReached(context.Background()) // no tracker: must not panic
	NoteReached(ctx)
	if !tr.Reached() {
		t.Fatal("reach not recorded")
	}
}

func TestFailClosedRefusalsTellTheAgentItIsAServerProblem(t *testing.T) {
	p, _, _ := newPolicy(true)
	p.Log = nil
	d := p.Evaluate("cam-a", tool, false)
	check := func(name string, d Decision) {
		t.Helper()
		if d.Blocked == nil || d.Blocked.Code != mcperr.CodeBlockedByPolicy || d.Blocked.Retryable {
			t.Fatalf("%s: %+v", name, d.Blocked)
		}
		for _, w := range []string{"misconfiguration", "operator", "do not retry"} {
			if !strings.Contains(d.Blocked.Hint, w) {
				t.Errorf("%s: hint = %q, want %q", name, d.Blocked.Hint, w)
			}
		}
	}
	check("no audit log", d)
	p, _, _ = newPolicy(true)
	p.Limiter = nil
	check("no limiter", p.Evaluate("cam-a", tool, false))
}

func sharedEndpointPolicy() *Policy {
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"a": {ID: "a", Endpoint: "http://192.0.2.9/onvif/device_service", Control: true},
		"b": {ID: "b", Endpoint: "HTTP://192.0.2.9:80/onvif/device_service/", Control: true},
		"c": {ID: "c", Endpoint: "http://192.0.2.10/onvif/device_service", Control: true},
	}})
	return NewPolicy(PolicyOptions{ControlEnabled: true, Cameras: reg, Interval: time.Hour, Burst: 1,
		Log: slog.New(slog.NewJSONHandler(&syncBuf{}, nil))})
}

// Two ids that address one device share one rate budget.
func TestTwoIDsOnOneDeviceShareOneBudget(t *testing.T) {
	p := sharedEndpointPolicy()
	if d := p.Evaluate("a", tool, false); d.Blocked != nil {
		t.Fatalf("first call blocked: %+v", d.Blocked)
	}
	d := p.Evaluate("b", tool, false)
	if d.Blocked == nil || d.Blocked.RetryAfterSeconds == nil {
		t.Fatalf("second id on the same device was not rate limited: %+v", d)
	}
	if d := p.Evaluate("c", tool, false); d.Blocked != nil {
		t.Errorf("a different device was throttled: %+v", d.Blocked)
	}
}

// A refund returns the budget, so a call that sent nothing costs nothing, and
// the other id sees it.
func TestRefundReturnsTheDevicesBudget(t *testing.T) {
	p := sharedEndpointPolicy()
	d := p.Evaluate("a", tool, false)
	if d.Blocked != nil || d.Refund == nil {
		t.Fatalf("decision = %+v, want an allowed real call with a Refund", d)
	}
	d.Refund()
	if d2 := p.Evaluate("b", tool, false); d2.Blocked != nil {
		t.Errorf("budget not returned: %+v", d2.Blocked)
	}
}

func TestDryRunAndRefusalCarryNoRefund(t *testing.T) {
	p := sharedEndpointPolicy()
	if d := p.Evaluate("a", tool, true); d.Refund != nil {
		t.Error("a dry run consumed nothing, so it has nothing to refund")
	}
	p.Evaluate("a", tool, false)
	if d := p.Evaluate("a", tool, false); d.Blocked == nil || d.Refund != nil {
		t.Errorf("refusal = %+v", d)
	}
}
