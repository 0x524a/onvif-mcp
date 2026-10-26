package safety

import (
	"log/slog"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/registry"
)

const contTool = "ptz.move_continuous"

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

// ---- Limiter.TakeCost ------------------------------------------------------

func TestTakeCostChargesTheWholeCostAndReportsTheWaitForTheRest(t *testing.T) {
	clk := newFakeClock()
	l := NewLimiter(4*time.Second, 5, WithClock(clk.Now)) // 5 s of motion, 1 s back per 4 s
	if ok, _ := l.TakeCost("k", 3); !ok {
		t.Fatal("3 of 5 must be granted")
	}
	ok, wait := l.TakeCost("k", 3) // 2 left, 1 missing
	if ok || wait != 4*time.Second {
		t.Fatalf("ok=%v wait=%v, want refused with 4s", ok, wait)
	}
	clk.Advance(4 * time.Second)
	if ok, _ := l.TakeCost("k", 3); !ok {
		t.Fatal("after one refill second the cost fits")
	}
	if ok, wait := l.TakeCost("k", 0.5); ok || wait != 2*time.Second {
		t.Errorf("empty bucket, cost 0.5: ok=%v wait=%v", ok, wait)
	}
}

func TestTakeCostRefusesCostsItCanNeverGrant(t *testing.T) {
	l := NewLimiter(time.Second, 5)
	for _, c := range []float64{0, -1, math.NaN(), math.Inf(1), 5.0001, 100} {
		if ok, wait := l.TakeCost("k", c); ok || wait <= 0 {
			t.Errorf("cost %v: ok=%v wait=%v", c, ok, wait)
		}
	}
	if ok, _ := l.TakeCost("k", 5); !ok {
		t.Error("a cost equal to the burst is grantable and must not have been charged by the refusals")
	}
}

func TestTakeCostFailsClosedWhenTheKeyTableIsFull(t *testing.T) {
	l := NewLimiter(time.Hour, 5, WithMaxKeys(1))
	if ok, _ := l.TakeCost("a", 1); !ok {
		t.Fatal("first key")
	}
	if ok, _ := l.TakeCost("b", 1); ok {
		t.Error("a full table must refuse a new key, never grant untracked motion")
	}
}

func TestAllowGrantStillTakesExactlyOneToken(t *testing.T) {
	l := NewLimiter(time.Hour, 2)
	ok1, _, g1 := l.AllowGrant("k")
	ok2, _, g2 := l.AllowGrant("k")
	ok3, _, _ := l.AllowGrant("k")
	if !ok1 || !ok2 || ok3 || g1 == g2 {
		t.Errorf("ok=%v %v %v grants=%d %d", ok1, ok2, ok3, g1, g2)
	}
}

// ---- the device lease inside Evaluate --------------------------------------

func TestRealWriteHoldsTheDeviceLeaseAndABusyRefusalSpendsNoToken(t *testing.T) {
	buf := &syncBuf{}
	p := NewPolicy(PolicyOptions{ControlEnabled: true, Cameras: testRegistry(), Interval: time.Hour, Burst: 2,
		Log: slog.New(slog.NewJSONHandler(buf, nil))})
	first := p.Evaluate(opCtx(), "cam-a", tool, false)
	if first.Blocked != nil || first.Lease == nil {
		t.Fatalf("first real write: %+v", first)
	}
	busy := p.Evaluate(opCtx(), "cam-a", tool, false)
	if busy.Blocked == nil || busy.Blocked.Code != mcperr.CodeBlockedByPolicy || busy.Blocked.RetryAfterSeconds == nil ||
		!strings.Contains(busy.Blocked.Message, "busy") || busy.Lease != nil || busy.Refund != nil {
		t.Fatalf("second real write while the first holds the device: %+v", busy)
	}
	recs := buf.records(t)
	if last := recs[len(recs)-1]; last["reason"] != ReasonDeviceBusy {
		t.Errorf("audit = %v", last)
	}
	// A dry run takes no lease and is never busy.
	if d := p.Evaluate(opCtx(), "cam-a", tool, true); d.Blocked != nil || d.Lease != nil {
		t.Errorf("dry run while busy: %+v", d)
	}
	first.Lease.Release()
	// Burst 2: the busy refusal must not have spent the second token.
	third := p.Evaluate(opCtx(), "cam-a", tool, false)
	if third.Blocked != nil {
		t.Fatalf("the busy refusal spent a token: %+v", third.Blocked)
	}
	third.Lease.Release()
}

func TestTwoIDsForOneDeviceShareOneLease(t *testing.T) {
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"a": {ID: "a", Endpoint: "http://192.0.2.9/onvif/device_service", Control: true},
		"b": {ID: "b", Endpoint: "HTTP://192.0.2.9:80/onvif/device_service/", Control: true},
	}})
	p := NewPolicy(PolicyOptions{ControlEnabled: true, Cameras: reg, Interval: time.Millisecond, Burst: 5, Log: quiet()})
	d := p.Evaluate(opCtx(), "a", tool, false)
	if d.Blocked != nil {
		t.Fatal(d.Blocked)
	}
	defer d.Lease.Release()
	if b := p.Evaluate(opCtx(), "b", tool, false); b.Blocked == nil {
		t.Fatal("a second id for the same endpoint must see the device busy")
	}
}

func TestATokenRefusalReleasesTheLease(t *testing.T) {
	p, _, _ := newPolicy(true) // burst 1, no refill
	d := p.Evaluate(opCtx(), "cam-a", tool, false)
	d.Lease.Release()
	if r := p.Evaluate(opCtx(), "cam-a", tool, false); r.Blocked == nil || r.Lease != nil {
		t.Fatalf("second call inside the interval: %+v", r)
	}
	if n := p.Leases.heldCount(); n != 0 {
		t.Fatalf("a rate-limit refusal leaked the device lease (%d held)", n)
	}
}

func TestNilLeasesRefusesRealWritesButNotDryRuns(t *testing.T) {
	p, _, _ := newPolicy(true)
	p.Leases = nil
	if d := p.Evaluate(opCtx(), "cam-a", tool, false); d.Blocked == nil || d.Blocked.Code != mcperr.CodeBlockedByPolicy {
		t.Fatalf("real write with no lease table: %+v", d)
	}
	if d := p.Evaluate(opCtx(), "cam-a", tool, true); d.Blocked != nil {
		t.Errorf("dry run: %+v", d.Blocked)
	}
	// Fail closed spent nothing: restoring the table lets the one token through.
	p.Leases = NewLeases(nil)
	if d := p.Evaluate(opCtx(), "cam-a", tool, false); d.Blocked != nil {
		t.Errorf("token was spent by the fail-closed refusal: %+v", d.Blocked)
	}
}

func TestHaltIsNeverBlockedByAHeldLease(t *testing.T) {
	p, _, _ := newPolicy(true)
	d := p.Evaluate(opCtx(), "cam-a", tool, false)
	defer d.Lease.Release()
	if h := p.EvaluateHalt(opCtx(), "cam-a", haltTool); h.Blocked != nil || h.Lease != nil {
		t.Fatalf("halt while a write holds the device: %+v", h)
	}
}

func TestConcurrentRealWritesOnOneDeviceGrantExactlyOne(t *testing.T) {
	p := NewPolicy(PolicyOptions{ControlEnabled: true, Cameras: testRegistry(), Interval: time.Millisecond, Burst: 50, Log: quiet()})
	var granted atomic.Int32
	var wg sync.WaitGroup
	hold := make(chan struct{})
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if d := p.Evaluate(opCtx(), "cam-a", tool, false); d.Blocked == nil {
				granted.Add(1)
				<-hold
				d.Lease.Release()
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(hold)
	wg.Wait()
	if granted.Load() != 1 {
		t.Fatalf("%d concurrent real writes were granted, want 1", granted.Load())
	}
}

// ---- timeout attestation ---------------------------------------------------

func attestRegistry() *registry.Registry {
	return registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-t": {ID: "cam-t", Endpoint: "http://192.0.2.7/onvif/device_service", Control: true, PTZHonoursTimeout: true},
		"cam-a": {ID: "cam-a", Endpoint: "http://192.0.2.1/onvif/device_service", Control: true},
	}})
}

func TestTimeoutAttestationIsRequiredOnlyWhenAsked(t *testing.T) {
	buf := &syncBuf{}
	p := NewPolicy(PolicyOptions{ControlEnabled: true, Cameras: attestRegistry(), Interval: time.Millisecond, Burst: 5,
		Log: slog.New(slog.NewJSONHandler(buf, nil))})
	for _, dry := range []bool{true, false} {
		d := p.Evaluate(opCtx(), "cam-a", contTool, dry, RequireTimeoutAttestation())
		if d.Blocked == nil || d.Blocked.Code != mcperr.CodeBlockedByPolicy || d.Lease != nil ||
			!strings.Contains(d.Blocked.Hint, "ptz_honours_timeout") || d.Blocked.Retryable {
			t.Fatalf("dry=%v unattested: %+v", dry, d)
		}
		recs := buf.records(t)
		if last := recs[len(recs)-1]; last["reason"] != ReasonTimeoutNotAttested {
			t.Errorf("audit = %v", last)
		}
	}
	if p.Leases.heldCount() != 0 {
		t.Error("an attestation refusal took a lease")
	}
	ok := p.Evaluate(opCtx(), "cam-t", contTool, false, RequireTimeoutAttestation())
	if ok.Blocked != nil {
		t.Fatalf("attested camera: %+v", ok.Blocked)
	}
	ok.Lease.Release()
	if d := p.Evaluate(opCtx(), "cam-a", tool, false); d.Blocked != nil {
		t.Errorf("without the option an unattested camera is not refused: %+v", d.Blocked)
	} else {
		d.Lease.Release()
	}
}

// ---- motion budget ---------------------------------------------------------

func TestChargeMotionDrawsSecondsFromThePerDeviceBudget(t *testing.T) {
	buf := &syncBuf{}
	clk := newFakeClock()
	p := NewPolicy(PolicyOptions{ControlEnabled: true, Cameras: attestRegistry(), Clock: clk.Now,
		Log: slog.New(slog.NewJSONHandler(buf, nil))})
	if p.MotionBudget.Burst() != DefaultMotionBurstSeconds || p.MotionBudget.Interval() != DefaultMotionRefill {
		t.Fatalf("defaults: burst %d interval %v", p.MotionBudget.Burst(), p.MotionBudget.Interval())
	}
	if te := p.ChargeMotion("cam-t", contTool, 4.5); te != nil {
		t.Fatal(te)
	}
	te := p.ChargeMotion("cam-t", contTool, 1)
	if te == nil || te.Code != mcperr.CodeBlockedByPolicy || te.RetryAfterSeconds == nil || *te.RetryAfterSeconds != 2 || !te.NotSent {
		t.Fatalf("exhausted: %+v", te)
	}
	recs := buf.records(t)
	if last := recs[len(recs)-1]; last["reason"] != ReasonMotionBudget || last["blocked"] != true {
		t.Errorf("audit = %v", last)
	}
	clk.Advance(2 * time.Second)
	if te := p.ChargeMotion("cam-t", contTool, 1); te != nil {
		t.Errorf("after the wait: %+v", te)
	}
}

func TestChargeMotionFailsClosed(t *testing.T) {
	var nilP *Policy
	if te := nilP.ChargeMotion("cam-t", contTool, 1); te == nil {
		t.Error("nil policy")
	}
	p := NewPolicy(PolicyOptions{ControlEnabled: true, Cameras: attestRegistry(), Log: quiet()})
	if te := p.ChargeMotion("nope", contTool, 1); te == nil || te.Code != mcperr.CodeNotFound {
		t.Errorf("unknown camera: %+v", te)
	}
	p.MotionBudget = nil
	if te := p.ChargeMotion("cam-t", contTool, 1); te == nil || te.Code != mcperr.CodeBlockedByPolicy {
		t.Errorf("no budget: %+v", te)
	}
}

func TestInterruptMotionWakesTheDevicesTimedLease(t *testing.T) {
	p := NewPolicy(PolicyOptions{ControlEnabled: true, Cameras: attestRegistry(), Log: quiet()})
	if p.InterruptMotion("cam-t") {
		t.Error("nothing moving")
	}
	d := p.Evaluate(opCtx(), "cam-t", contTool, false, RequireTimeoutAttestation())
	if !d.Lease.SetUntil(time.Now().Add(time.Minute)) {
		t.Fatal("SetUntil")
	}
	if p.InterruptMotion("nope") {
		t.Error("an unknown camera interrupts nothing")
	}
	if !p.InterruptMotion("cam-t") {
		t.Fatal("timed motion not interrupted")
	}
	select {
	case <-d.Lease.Interrupted():
	default:
		t.Fatal("lease not woken")
	}
	d.Lease.Release()
	var nilP *Policy
	if nilP.InterruptMotion("cam-t") {
		t.Error("nil policy")
	}
}

// ---- motion audit ----------------------------------------------------------

func TestAuditMotionRecordsStartAndStopWithTypedFieldsOnly(t *testing.T) {
	buf := &syncBuf{}
	p := NewPolicy(PolicyOptions{ControlEnabled: true, Cameras: attestRegistry(), Log: slog.New(slog.NewJSONHandler(buf, nil))})
	pan := 0.2
	p.AuditMotionStarted(contTool, "cam-t", "m-1", MotionAudit{Mode: "continuous", Pan: &pan}, 1500)
	p.AuditMotionStopped(contTool, "cam-t", "m-1", "deadline", "confirmed_idle", true)
	p.AuditMotionStopped(contTool, "cam-t\nforged=1", "m-1", "shutdown", "failed", false)
	recs := buf.records(t)
	if len(recs) != 3 {
		t.Fatalf("records = %v", recs)
	}
	s := recs[0]
	if s["msg"] != "motion started" || s["motion_id"] != "m-1" || s["motion_mode"] != "continuous" ||
		s["motion_pan"] != 0.2 || s["duration_ms"] != 1500.0 || s["level"] != "INFO" {
		t.Errorf("start = %v", s)
	}
	if e := recs[1]; e["msg"] != "motion stopped" || e["stopped_by"] != "deadline" || e["stop_status"] != "confirmed_idle" || e["level"] != "INFO" {
		t.Errorf("stop = %v", e)
	}
	if f := recs[2]; f["level"] != "ERROR" || f["stop_status"] != "failed" || f["motion_may_continue"] != true || f["forged"] != nil {
		t.Errorf("a failed stop must be audited at error level: %v", f)
	}
}

// ---- policy resource -------------------------------------------------------

func TestPolicyResourceReportsAttestationAndTheMotionBudget(t *testing.T) {
	p := NewPolicy(PolicyOptions{ControlEnabled: true, Cameras: attestRegistry(), Log: quiet()})
	p.NoteGated(contTool)
	p.NoteTimed(contTool)
	body, raw := readPolicyWith(t, p, []CameraGrant{
		{ID: "cam-a", ControlAllowed: true},
		{ID: "cam-t", ControlAllowed: true, PTZHonoursTimeout: true},
	})
	_ = body
	for _, want := range []string{`"ptz_honours_timeout": true`, `"ptz_honours_timeout": false`,
		"5 seconds of motion", "ptz.move_continuous", "ptz_honours_timeout"} {
		if !strings.Contains(raw, want) {
			t.Errorf("policy lacks %q:\n%s", want, raw)
		}
	}
	if !strings.Contains(raw, "only remaining protection") {
		t.Errorf("the policy must say what is left after a crash:\n%s", raw)
	}
}

func TestReadOnlyTransportPolicyHidesAttestation(t *testing.T) {
	p := NewPolicy(PolicyOptions{Cameras: attestRegistry(), Log: quiet(), WritesUnavailable: "not here"})
	_, raw := readPolicyWith(t, p, []CameraGrant{{ID: "cam-t", ControlAllowed: true, PTZHonoursTimeout: true}})
	if strings.Contains(raw, `"ptz_honours_timeout": true`) {
		t.Errorf("an operator attestation leaked to a read-only transport:\n%s", raw)
	}
}
