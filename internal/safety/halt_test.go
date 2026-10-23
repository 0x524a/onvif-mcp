package safety

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
)

const haltTool = "ptz.stop"

func TestRiskHaltHasAName(t *testing.T) {
	if RiskHalt.String() != "halt" {
		t.Errorf("RiskHalt = %q", RiskHalt.String())
	}
	if RiskHalt == RiskRead || RiskHalt == RiskWrite {
		t.Error("RiskHalt must be a class of its own")
	}
}

func TestHaltAnnotationsAreNotDestructiveAndIdempotent(t *testing.T) {
	a := HaltAnnotations("Stop PTZ")
	if a.Title != "Stop PTZ" || a.ReadOnlyHint {
		t.Errorf("annotations = %+v", a)
	}
	if a.DestructiveHint == nil || *a.DestructiveHint {
		t.Error("destructiveHint must be false")
	}
	if !a.IdempotentHint {
		t.Error("idempotentHint must be true")
	}
	if a.OpenWorldHint == nil || *a.OpenWorldHint {
		t.Error("openWorldHint must be false")
	}
}

func TestWriteAnnotationsNonIdempotentDiffersOnlyInIdempotentHint(t *testing.T) {
	w, n := WriteAnnotations("x"), WriteAnnotationsNonIdempotent("x")
	if n.IdempotentHint || !w.IdempotentHint {
		t.Errorf("idempotent: write=%v non=%v", w.IdempotentHint, n.IdempotentHint)
	}
	if n.DestructiveHint == nil || !*n.DestructiveHint || n.ReadOnlyHint || *n.OpenWorldHint {
		t.Errorf("non-idempotent write must stay destructive: %+v", n)
	}
}

func TestEvaluateHaltAllowsWithoutLogLimiterOrBudget(t *testing.T) {
	p, _, _ := newPolicy(true)
	p.Log = nil
	p.Limiter = nil
	for i := 0; i < 50; i++ {
		d := p.EvaluateHalt(opCtx(), "cam-a", haltTool)
		if d.Blocked != nil {
			t.Fatalf("call %d refused: %+v", i, d.Blocked)
		}
		if d.Refund != nil || d.DryRun {
			t.Errorf("a halt has no dry run and spends no budget: %+v", d)
		}
	}
}

func TestEvaluateHaltIsNotRateLimitedWhenTheBucketIsExhausted(t *testing.T) {
	p, _, _ := newPolicy(true)
	if d := p.Evaluate(opCtx(), "cam-a", tool, false); d.Blocked != nil {
		t.Fatal(d.Blocked)
	}
	if d := p.Evaluate(opCtx(), "cam-a", tool, false); d.Blocked == nil {
		t.Fatal("harness: the bucket should be exhausted")
	}
	for i := 0; i < 50; i++ {
		if d := p.EvaluateHalt(opCtx(), "cam-a", haltTool); d.Blocked != nil {
			t.Fatalf("halt refused after the bucket emptied: %+v", d.Blocked)
		}
	}
}

func TestEvaluateHaltRefusesAndAuditsEveryApplicableGate(t *testing.T) {
	cases := []struct {
		name    string
		control bool
		camera  string
		code    mcperr.Code
		reason  string
	}{
		{"unknown camera", true, "no-such", mcperr.CodeNotFound, ReasonUnknownCamera},
		{"control off", false, "cam-a", mcperr.CodeBlockedByPolicy, ReasonControlDisabled},
		{"not granted", true, "cam-fixed", mcperr.CodeBlockedByPolicy, ReasonCameraNotGranted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, buf, _ := newPolicy(c.control)
			d := p.EvaluateHalt(opCtx(), c.camera, haltTool)
			if d.Blocked == nil || d.Blocked.Code != c.code {
				t.Fatalf("got %+v, want %s", d.Blocked, c.code)
			}
			recs := buf.records(t)
			if len(recs) != 1 || recs[0]["reason"] != c.reason || recs[0]["blocked"] != true || recs[0]["executed"] != false {
				t.Errorf("audit = %v", recs)
			}
		})
	}
}

func TestEvaluateHaltOnNilPolicyRefuses(t *testing.T) {
	var p *Policy
	if d := p.EvaluateHalt(opCtx(), "cam-a", haltTool); d.Blocked == nil {
		t.Fatal("a nil policy must refuse")
	}
}

func TestEvaluateHaltUnknownCamerasNeverReachTheLimiter(t *testing.T) {
	p, _, _ := newPolicy(true)
	for i := 0; i < 100; i++ {
		p.EvaluateHalt(opCtx(), fmt.Sprintf("attacker-%d", i), haltTool)
	}
	if p.Limiter.size() != 0 {
		t.Error("a halt must not touch the limiter")
	}
}

func TestNoteHaltIsGatedAndListedAsHalt(t *testing.T) {
	p, _, _ := newPolicy(true)
	p.NoteGated("ptz.goto_preset")
	p.NoteHalt(haltTool)
	if got := strings.Join(p.GatedTools(), ","); got != "ptz.goto_preset,ptz.stop" {
		t.Errorf("gated = %s", got)
	}
	if got := p.HaltTools(); len(got) != 1 || got[0] != haltTool {
		t.Errorf("halt tools = %v", got)
	}
	var nilP *Policy
	nilP.NoteHalt("x") // must not panic
	if len(nilP.HaltTools()) != 0 {
		t.Error("nil policy has no halt tools")
	}
}

func TestAuditWithMotionRecordsTypedNumbersOnly(t *testing.T) {
	buf := &syncBuf{}
	p := NewPolicy(PolicyOptions{ControlEnabled: true, Cameras: testRegistry(), Interval: time.Hour,
		Log: slog.New(slog.NewJSONHandler(buf, nil))})
	pan, zoom := 0.25, -0.1
	p.Audit("ptz.move_relative", "cam-a", false, true, "ok",
		WithMotion(MotionAudit{Mode: "relative", Pan: &pan, Zoom: &zoom}))
	r := buf.records(t)[0]
	if r["motion_mode"] != "relative" || r["motion_pan"] != 0.25 || r["motion_zoom"] != -0.1 {
		t.Errorf("record = %v", r)
	}
	if _, ok := r["motion_tilt"]; ok {
		t.Error("an absent axis must not be logged as 0")
	}
}

func TestAuditWithMotionModeIsBoundedAndScrubbed(t *testing.T) {
	buf := &syncBuf{}
	p := NewPolicy(PolicyOptions{ControlEnabled: true, Cameras: testRegistry(), Interval: time.Hour,
		Log: slog.New(slog.NewJSONHandler(buf, nil))})
	p.Audit("t", "cam-a", false, true, "ok", WithMotion(MotionAudit{Mode: "password=hunter2-secret " + strings.Repeat("x", 500)}))
	raw := fmt.Sprint(buf.records(t)[0])
	if strings.Contains(raw, "hunter2-secret") || len(raw) > 1200 {
		t.Errorf("mode not scrubbed/bounded: %d bytes", len(raw))
	}
}

func TestAuditHostileTargetNeverAppearsVerbatim(t *testing.T) {
	buf := &syncBuf{}
	p := NewPolicy(PolicyOptions{ControlEnabled: true, Cameras: testRegistry(), Interval: time.Hour,
		Log: slog.New(slog.NewJSONHandler(buf, nil))})
	hostile := "tok\nFAKE RECORD password=hunter2-secret " + strings.Repeat("A", 300)
	p.Audit(haltTool, "cam-a", false, true, "ok", WithTarget(hostile))
	recs := buf.records(t)
	if len(recs) != 1 {
		t.Fatalf("a newline in the target forged a record: %d lines", len(recs))
	}
	tgt, _ := recs[0]["target"].(string)
	if strings.Contains(tgt, "hunter2-secret") || len(tgt) > maxAuditTarget {
		t.Errorf("target = %q", tgt)
	}
}
