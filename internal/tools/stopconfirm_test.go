package tools

import (
	"net/http"
	"testing"
	"time"
)

func TestConfirmedIdleNeedsStopSuccessAndAnIdleStateField(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, time.Second, time.Millisecond)
	fx.setStatus(`<tt:PanTilt>IDLE</tt:PanTilt>`) // only one field reported, and it is idle
	rep := stopAndConfirm(stopCtx(), fx.deps(5), "fx", "prof")
	if rep.Status != stopConfirmedIdle {
		t.Fatalf("report = %+v", rep)
	}
}

func TestNoMoveStatusAtAllIsSentUnconfirmedAndStopsPollingEarly(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, time.Second, time.Millisecond)
	fx.setStatus("")
	rep := stopAndConfirm(stopCtx(), fx.deps(5), "fx", "prof")
	if rep.Status != stopSentUnconfirmed || rep.Err != nil || !rep.Sent {
		t.Fatalf("report = %+v", rep)
	}
	if n := fx.count("GetStatus"); n != 1 {
		t.Errorf("polled %d times for a camera that reports no state; one read is enough", n)
	}
	if rep.Final == nil || rep.Final.Pan == nil {
		t.Errorf("the position the camera did report must still be returned: %+v", rep.Final)
	}
}

func TestMovingOnAllThreePollsIsSentUnconfirmed(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, time.Second, time.Millisecond)
	fx.setStatus(`<tt:PanTilt>MOVING</tt:PanTilt><tt:Zoom>IDLE</tt:Zoom>`)
	rep := stopAndConfirm(stopCtx(), fx.deps(5), "fx", "prof")
	if rep.Status != stopSentUnconfirmed {
		t.Fatalf("report = %+v", rep)
	}
	if n := fx.count("GetStatus"); n != 3 {
		t.Errorf("polls = %d, want 3", n)
	}
	if rep.Final == nil || rep.Final.PanTiltState != "MOVING" {
		t.Errorf("final = %+v", rep.Final)
	}
}

func TestUnknownStateIsNeverConfirmedIdle(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, time.Second, time.Millisecond)
	fx.setStatus(`<tt:PanTilt>UNKNOWN</tt:PanTilt>`)
	if rep := stopAndConfirm(stopCtx(), fx.deps(5), "fx", "prof"); rep.Status != stopSentUnconfirmed {
		t.Fatalf("report = %+v", rep)
	}
}

func TestSettlingAfterTheFirstPollIsConfirmed(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, time.Second, time.Millisecond)
	fx.on("GetStatus", func(n int, _ http.ResponseWriter, _ *http.Request, _ string) bool {
		if n == 1 {
			fx.setStatus(`<tt:PanTilt>MOVING</tt:PanTilt>`)
		} else {
			fx.setStatus(idleStatus)
		}
		return false
	})
	rep := stopAndConfirm(stopCtx(), fx.deps(5), "fx", "prof")
	if rep.Status != stopConfirmedIdle {
		t.Fatalf("report = %+v", rep)
	}
	if n := fx.count("GetStatus"); n != 2 {
		t.Errorf("polls = %d, want 2", n)
	}
}

func TestStopFaultIsFailedAndConfirmationNeverRuns(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, time.Second, time.Millisecond)
	fx.on("Stop", func(_ int, w http.ResponseWriter, _ *http.Request, _ string) bool {
		faultReply(w, "motor busy")
		return true
	})
	rep := stopAndConfirm(stopCtx(), fx.deps(5), "fx", "prof")
	if rep.Status != stopFailed || rep.Err == nil || !rep.Sent {
		t.Fatalf("report = %+v", rep)
	}
	if fx.count("GetStatus") != 0 {
		t.Error("confirmation must not run after a failed stop")
	}
	if !contains(rep.Err.Message, "stop was not delivered") || !contains(rep.Err.Hint, "ptz.stop again") {
		t.Errorf("err = %+v", rep.Err)
	}
}

func TestEmptyStopReplyCanOnlyBeSentUnconfirmed(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, time.Second, time.Millisecond)
	fx.on("Stop", func(_ int, w http.ResponseWriter, _ *http.Request, _ string) bool {
		w.WriteHeader(http.StatusOK) // 200, empty body
		return true
	})
	rep := stopAndConfirm(stopCtx(), fx.deps(5), "fx", "prof")
	if rep.Status != stopSentUnconfirmed || rep.Err != nil {
		t.Fatalf("report = %+v", rep)
	}
}

func TestStatusReadFailureAfterAGoodStopIsSentUnconfirmed(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, time.Second, time.Millisecond)
	fx.on("GetStatus", func(_ int, w http.ResponseWriter, _ *http.Request, _ string) bool {
		faultReply(w, "no status")
		return true
	})
	rep := stopAndConfirm(stopCtx(), fx.deps(5), "fx", "prof")
	if rep.Status != stopSentUnconfirmed || rep.Err != nil {
		t.Fatalf("a delivered stop must not turn into a failure because the read failed: %+v", rep)
	}
}

func TestAbsentPositionIsNeverRenderedAsZero(t *testing.T) {
	st := statusOf(nil)
	if st.Pan != nil || st.Tilt != nil || st.Zoom != nil {
		t.Errorf("nil status = %+v", st)
	}
}

func TestOverlongOrEmptyProfileIsRefusedBeforeAnyCameraTraffic(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, time.Second, time.Millisecond)
	for _, p := range []string{"", string(make([]byte, 129)), string(make([]byte, 1<<20))} {
		rep := stopAndConfirm(stopCtx(), fx.deps(5), "fx", p)
		if rep.Err == nil || rep.Err.Code != "invalid_argument" || !rep.Err.NotSent || rep.Sent {
			t.Errorf("len %d: %+v", len(p), rep)
		}
	}
	if n := len(fx.all()); n != 0 {
		t.Errorf("%d requests reached the camera", n)
	}
}
