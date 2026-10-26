package tools

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
	"github.com/0x524a/onvif-mcp/internal/testcam"
)

// ---- the stop section --------------------------------------------------------

func TestContinuousStopIsRetriedUntilItIsDelivered(t *testing.T) {
	fx := newPtzFx(t)
	fx.on("Stop", func(n int, w http.ResponseWriter, _ *http.Request, _ string) bool {
		switch n {
		case 1:
			dropConn(w)
			return true
		case 2:
			faultReply(w, "busy")
			return true
		}
		return false
	})
	r := newContRig(t, fx, contOpts{attest: true})
	instantTimer(t)
	d := dataMap(t, r.move(t, map[string]any{"dry_run": false}))
	if d["stop_status"] != "confirmed_idle" || fx.count("Stop") != 3 {
		t.Fatalf("data=%v stops=%d", d, fx.count("Stop"))
	}
}

func TestContinuousStopThatNeverLandsSaysMotionMayContinue(t *testing.T) {
	fx := newPtzFx(t)
	fx.on("Stop", func(_ int, w http.ResponseWriter, _ *http.Request, _ string) bool {
		faultReply(w, "motor fault")
		return true
	})
	r := newContRig(t, fx, contOpts{attest: true})
	instantTimer(t)
	res := r.move(t, map[string]any{"dry_run": false})
	all := wire(t, res)
	if !res.IsError || !strings.Contains(all, "MOTION MAY CONTINUE on camera fx") || errField(res, "retryable") != false {
		t.Fatalf("%s", all)
	}
	if _, hint := errCode(t, res); !strings.Contains(hint, "ptz.stop") || !strings.Contains(hint, "PT1.5S") {
		t.Errorf("hint = %q", hint)
	}
	if fx.count("Stop") != 3 {
		t.Errorf("Stop attempts = %d, want 3", fx.count("Stop"))
	}
	stopped := r.records(t, "motion stopped")
	if len(stopped) != 1 || stopped[0]["level"] != "ERROR" || stopped[0]["stop_status"] != "failed" || stopped[0]["motion_may_continue"] != true {
		t.Errorf("audit = %v", stopped)
	}
	if strings.Contains(all, "fixture-pw") || strings.Contains(strings.ToLower(all), "<s:envelope") {
		t.Error("credential or raw SOAP in the result")
	}
}

func TestContinuousSendFailureIsTreatedAsSentAndStoppedAtOnce(t *testing.T) {
	for name, hook := range map[string]func(int, http.ResponseWriter, *http.Request, string) bool{
		"fault":   func(_ int, w http.ResponseWriter, _ *http.Request, _ string) bool { faultReply(w, "no"); return true },
		"dropped": func(_ int, w http.ResponseWriter, _ *http.Request, _ string) bool { dropConn(w); return true },
		"empty 200": func(_ int, w http.ResponseWriter, _ *http.Request, _ string) bool {
			w.WriteHeader(http.StatusOK)
			return true
		},
	} {
		t.Run(name, func(t *testing.T) {
			fx := newPtzFx(t)
			fx.on("ContinuousMove", hook)
			r := newContRig(t, fx, contOpts{attest: true})
			asked := instantTimer(t)
			res := r.move(t, map[string]any{"dry_run": false, "duration_seconds": 5})
			if !res.IsError || errField(res, "retryable") != false {
				t.Fatalf("%s", wire(t, res))
			}
			if _, hint := errCode(t, res); !strings.Contains(hint, "may or may not have been executed") {
				t.Errorf("hint = %q", hint)
			}
			if !strings.Contains(wire(t, res), "stop") {
				t.Errorf("the error must carry the stop outcome: %s", wire(t, res))
			}
			if fx.count("Stop") != 1 || len(*asked) != 0 {
				t.Errorf("Stop=%d waits=%v: a failed send must be stopped at once, with no wait", fx.count("Stop"), *asked)
			}
			if s := r.records(t, "motion stopped"); len(s) != 1 || s[0]["stopped_by"] != "send_failed" {
				t.Errorf("audit = %v", s)
			}
		})
	}
}

func TestContinuousWaitIsTheDurationLessTheTimeTheSendTook(t *testing.T) {
	fx := newPtzFx(t)
	fx.on("ContinuousMove", func(_ int, _ http.ResponseWriter, _ *http.Request, _ string) bool {
		time.Sleep(200 * time.Millisecond)
		return false
	})
	r := newContRig(t, fx, contOpts{attest: true})
	asked := instantTimer(t)
	dataMap(t, r.move(t, map[string]any{"dry_run": false, "duration_seconds": 2}))
	if len(*asked) != 1 || (*asked)[0] > 1810*time.Millisecond || (*asked)[0] < 1500*time.Millisecond {
		t.Fatalf("waits = %v, want about 2s minus the 200ms send", *asked)
	}
}

func TestContinuousCancelMidWaitSendsTheStopAtOnceOnADetachedContext(t *testing.T) {
	fx := newPtzFx(t)
	r := newContRig(t, fx, contOpts{attest: true})
	heldTimer(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = r.cs.CallTool(ctx, &mcp.CallToolParams{Name: contTool, Arguments: map[string]any{
			"camera": "fx", "profile": "prof", "pan": 0.2, "duration_seconds": 5, "dry_run": false}})
	}()
	fx.waitCount(t, "ContinuousMove", 1, 5*time.Second)
	at := time.Now()
	cancel()
	<-done
	fx.waitCount(t, "Stop", 1, 5*time.Second)
	if lag := fx.named("Stop")[0].at.Sub(at); lag > 100*time.Millisecond {
		t.Errorf("Stop reached the camera %v after the cancel, want under 100ms", lag)
	}
	rec := r.waitAudit(t, "motion stopped", 5*time.Second)
	if rec["stopped_by"] != "cancelled" || rec["stop_status"] != "confirmed_idle" {
		t.Errorf("audit = %v (the stop must complete although the call was cancelled)", rec)
	}
}

func TestContinuousShutdownStopsTheCameraAndSaysSo(t *testing.T) {
	fx := newPtzFx(t)
	r := newContRig(t, fx, contOpts{attest: true})
	heldTimer(t)
	var res *mcp.CallToolResult
	done := make(chan struct{})
	go func() { defer close(done); res = r.move(t, map[string]any{"dry_run": false, "duration_seconds": 5}) }()
	fx.waitCount(t, "ContinuousMove", 1, 5*time.Second)
	r.cancel()
	<-done
	d := dataMap(t, res)
	if d["stopped_by"] != "shutdown" || d["stop_status"] != "confirmed_idle" || fx.count("Stop") != 1 {
		t.Fatalf("data=%v stops=%d", d, fx.count("Stop"))
	}
}

func TestContinuousPanicAfterTheSendStillStopsAndReleasesTheDevice(t *testing.T) {
	fx := newPtzFx(t)
	r := newContRig(t, fx, contOpts{attest: true})
	instantTimer(t)
	afterContinuousSend = func() { panic("boom password=hunter2-secret") }
	res := r.move(t, map[string]any{"dry_run": false})
	if code, _ := errCode(t, res); code != "internal" || strings.Contains(wire(t, res), "hunter2") {
		t.Fatalf("%s", wire(t, res))
	}
	if fx.count("Stop") != 1 {
		t.Fatalf("Stop = %d after a panic past the send", fx.count("Stop"))
	}
	if s := r.records(t, "motion stopped"); len(s) != 1 || s[0]["stopped_by"] != "panic" {
		t.Errorf("audit = %v", s)
	}
	afterContinuousSend = nil
	if res := r.move(t, map[string]any{"dry_run": false}); res.IsError {
		t.Fatalf("the device lease leaked through the panic: %s", wire(t, res))
	}
}

// ---- ptz.stop and the lease ---------------------------------------------------

// startHeldMove starts a real continuous move that only an interrupt, cancel or
// shutdown ends, and waits for its ContinuousMove to reach the fixture.
func startHeldMove(t *testing.T, r *contRig) (result func() *mcp.CallToolResult) {
	t.Helper()
	heldTimer(t)
	var res *mcp.CallToolResult
	done := make(chan struct{})
	r.fx.bg(t, func() {
		defer close(done)
		res = r.move(t, map[string]any{"dry_run": false, "duration_seconds": 5})
	})
	// Runs before bg's cleanup waits for the move: if a test fails before
	// ending the move, a shutdown ends it instead of hanging the run.
	t.Cleanup(r.cancel)
	r.fx.waitCount(t, "ContinuousMove", 1, 5*time.Second)
	return func() *mcp.CallToolResult {
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Fatal("the continuous move did not return")
		}
		return res
	}
}

func TestPTZStopInterruptsAContinuousMoveWhichSendsItsOwnStopToo(t *testing.T) {
	fx := newPtzFx(t)
	r := newContRig(t, fx, contOpts{attest: true})
	result := startHeldMove(t, r)
	at := time.Now()
	sd := dataMap(t, call(t, r.cs, "ptz.stop", map[string]any{"camera": "fx-stopper", "profile": "prof"}))
	if sd["interrupted_motion"] != true {
		t.Errorf("ptz.stop data = %v", sd)
	}
	d := dataMap(t, result())
	if d["stopped_by"] != "ptz.stop" || d["stop_status"] != "confirmed_idle" {
		t.Errorf("move data = %v", d)
	}
	own := stopsBy(fx, "u")
	if len(own) != 1 || own[0].at.Before(at) || len(stopsBy(fx, "stopper")) != 1 {
		t.Fatalf("the move must send its own Stop after the interrupt: own=%d stopper=%d", len(own), len(stopsBy(fx, "stopper")))
	}
}

func TestPTZStopFailingStillLeavesTheMovesOwnStop(t *testing.T) {
	fx := newPtzFx(t)
	fx.on("Stop", func(_ int, w http.ResponseWriter, _ *http.Request, body string) bool {
		if strings.Contains(body, ">stopper</") {
			faultReply(w, "stopper refused")
			return true
		}
		return false
	})
	r := newContRig(t, fx, contOpts{attest: true})
	result := startHeldMove(t, r)
	if res := call(t, r.cs, "ptz.stop", map[string]any{"camera": "fx-stopper", "profile": "prof"}); !res.IsError {
		t.Fatalf("ptz.stop should have failed here: %s", wire(t, res))
	}
	if d := dataMap(t, result()); d["stop_status"] != "confirmed_idle" || d["stopped_by"] != "ptz.stop" {
		t.Fatalf("the move's own stop must still land: %v", d)
	}
}

func TestTheMovesOwnStopFailingIsReportedEvenWhenPTZStopSucceeded(t *testing.T) {
	fx := newPtzFx(t)
	fx.on("Stop", func(_ int, w http.ResponseWriter, _ *http.Request, body string) bool {
		if strings.Contains(body, ">u</") {
			faultReply(w, "own stop refused")
			return true
		}
		return false
	})
	r := newContRig(t, fx, contOpts{attest: true})
	result := startHeldMove(t, r)
	if sd := dataMap(t, call(t, r.cs, "ptz.stop", map[string]any{"camera": "fx-stopper", "profile": "prof"})); sd["interrupted_motion"] != true {
		t.Errorf("ptz.stop = %v", sd)
	}
	res := result()
	if !res.IsError || !strings.Contains(wire(t, res), "MOTION MAY CONTINUE") {
		t.Fatalf("the move must report its own failed stop: %s", wire(t, res))
	}
	if len(stopsBy(fx, "u")) != 3 {
		t.Errorf("own Stop attempts = %d", len(stopsBy(fx, "u")))
	}
}

func TestPTZStopReportsNoInterruptWhenNothingIsMoving(t *testing.T) {
	r := newContRig(t, newPtzFx(t), contOpts{attest: true})
	if sd := dataMap(t, call(t, r.cs, "ptz.stop", map[string]any{"camera": "fx", "profile": "prof"})); sd["interrupted_motion"] != false {
		t.Errorf("ptz.stop = %v", sd)
	}
}

func TestEveryRealMoveIsBusyWhileAContinuousMoveHoldsTheDevice(t *testing.T) {
	fx := newPtzFx(t)
	r := newContRig(t, fx, contOpts{attest: true})
	result := startHeldMove(t, r)
	var wg sync.WaitGroup
	calls := []struct {
		tool string
		args map[string]any
	}{
		{contTool, map[string]any{"camera": "fx", "profile": "prof", "pan": 0.1, "duration_seconds": 1, "dry_run": false}},
		{"ptz.move_relative", map[string]any{"camera": "fx", "profile": "prof", "pan": 0.1, "dry_run": false}},
		{"ptz.move_relative", map[string]any{"camera": "fx-stopper", "profile": "prof", "pan": 0.1, "dry_run": false}},
		{"ptz.goto_preset", map[string]any{"camera": "fx-plain", "profile": "prof", "preset": "p1", "dry_run": false}},
	}
	for i := 0; i < 3; i++ {
		for _, c := range calls {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res := call(t, r.cs, c.tool, c.args)
				if code, _ := errCode(t, res); code != "blocked_by_policy" || !strings.Contains(wire(t, res), "busy") {
					t.Errorf("%s while busy: %s", c.tool, wire(t, res))
				}
			}()
		}
	}
	wg.Wait()
	if fx.count("ContinuousMove") != 1 || fx.count("RelativeMove")+fx.count("GotoPreset") != 0 {
		t.Fatalf("a second move reached the camera: %+v", fx.all())
	}
	call(t, r.cs, "ptz.stop", map[string]any{"camera": "fx", "profile": "prof"})
	result()
	if res := call(t, r.cs, "ptz.move_relative", map[string]any{"camera": "fx", "profile": "prof", "pan": 0.1, "dry_run": false}); res.IsError {
		t.Fatalf("after the continuous move ended: %s", wire(t, res))
	}
}

func TestContinuousMotionBudgetIsChargedUpFrontAndNeverRefunded(t *testing.T) {
	fx := newPtzFx(t)
	r := newContRig(t, fx, contOpts{attest: true, burst: 2})
	instantTimer(t)
	dataMap(t, r.move(t, map[string]any{"dry_run": false, "duration_seconds": 4.5}))
	res := r.move(t, map[string]any{"dry_run": false, "duration_seconds": 1})
	code, _ := errCode(t, res)
	ra, _ := errField(res, "retry_after_seconds").(float64)
	if code != "blocked_by_policy" || ra < 1 || ra > 3 || !strings.Contains(wire(t, res), "seconds of motion") {
		t.Fatalf("budget: %s", wire(t, res))
	}
	if fx.count("ContinuousMove") != 1 {
		t.Fatal("the refused move was sent")
	}
	// The refusal was NotSent: the second rate token (burst 2) is back, so a
	// relative move still goes through.
	if res := call(t, r.cs, "ptz.move_relative", map[string]any{"camera": "fx", "profile": "prof", "pan": 0.1, "dry_run": false}); res.IsError {
		t.Fatalf("the budget refusal kept the rate token: %s", wire(t, res))
	}
	if b := r.records(t, "write attempt blocked"); len(b) == 0 || b[len(b)-1]["reason"] != safety.ReasonMotionBudget {
		t.Errorf("audit = %v", b)
	}
}

func TestContinuousWorksWithoutLogButIsThenRefused(t *testing.T) {
	r := newContRig(t, newPtzFx(t), contOpts{attest: true, noLog: true})
	if code, _ := errCode(t, r.move(t, map[string]any{"dry_run": false})); code != "blocked_by_policy" {
		t.Fatalf("no audit trail must refuse a real continuous move: %q", code)
	}
}

// ---- against the onvif-go virtual camera ----------------------------------
//
// The virtual camera ignores the ONVIF Timeout and reports MOVING until a Stop,
// so these prove the server's own stop, not the camera's.

func testcamContRig(t *testing.T) (*mcp.ClientSession, *testcam.Cam) {
	t.Helper()
	cam := testcam.Start(t)
	fastGates(t, time.Second, 10*time.Millisecond)
	fastMotion(t)
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a": {ID: "cam-a", Endpoint: cam.Endpoint(), Username: cam.Username(), Password: cam.Password(), Control: true, PTZHonoursTimeout: true},
	}})
	policy := safety.NewPolicy(safety.PolicyOptions{ControlEnabled: true, Cameras: reg, Log: quietLog()})
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterPTZMotion(srv, Deps{Reg: reg, Log: quietLog(), Policy: policy})
	return connectTo(t, srv), cam
}

func TestContinuousEndToEndTheServerStopsATestcamThatIgnoresTimeout(t *testing.T) {
	cs, cam := testcamContRig(t)
	start := time.Now()
	res := call(t, cs, contTool, map[string]any{"camera": "cam-a", "profile": cam.ProfileToken(), "pan": 0.1,
		"duration_seconds": 1, "dry_run": false})
	d := dataMap(t, res)
	if d["stopped_by"] != "deadline" || d["stop_status"] != "confirmed_idle" {
		t.Fatalf("data = %v", d)
	}
	if el := time.Since(start); el < 900*time.Millisecond {
		t.Errorf("returned after %v, before the 1s duration", el)
	}
	if pt, _ := cam.PTZMoveState(); pt != "IDLE" {
		t.Errorf("after the move the camera is %q", pt)
	}
}

func TestContinuousEndToEndCancelAt300msLeavesTheTestcamIdle(t *testing.T) {
	cs, cam := testcamContRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_, _ = cs.CallTool(ctx, &mcp.CallToolParams{Name: contTool, Arguments: map[string]any{
			"camera": "cam-a", "profile": cam.ProfileToken(), "pan": 0.1, "duration_seconds": 5, "dry_run": false}})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if pt, _ := cam.PTZMoveState(); pt == "MOVING" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the testcam never started moving")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	cancel()
	deadline = time.Now().Add(time.Second)
	for {
		if pt, _ := cam.PTZMoveState(); pt == "IDLE" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the testcam was not IDLE within 1s of the cancel")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
