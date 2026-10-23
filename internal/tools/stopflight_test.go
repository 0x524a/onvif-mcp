package tools

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	onvif "github.com/0x524a/onvif-go"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
)

// fastGates swaps in gates with short timings for one test and restores the
// real ones afterwards.
func fastGates(t *testing.T, stall, confirmGap time.Duration) {
	t.Helper()
	oldGates, oldDelay := gates, confirmDelay
	gates = newGates(stall)
	confirmDelay = confirmGap
	t.Cleanup(func() { gates, confirmDelay = oldGates, oldDelay })
}

// ---- the generic flight, on a fake clock ------------------------------------

type fakeTimers struct {
	mu sync.Mutex
	fs []func()
}

func (f *fakeTimers) after(_ time.Duration, fn func()) func() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fs = append(f.fs, fn)
	return func() bool { return true }
}

func (f *fakeTimers) fireAll() {
	f.mu.Lock()
	fs := f.fs
	f.fs = nil
	f.mu.Unlock()
	for _, fn := range fs {
		fn()
	}
}

func TestFlightNeverHandsACallerAResultFromBeforeItArrived(t *testing.T) {
	ft := &fakeTimers{}
	f := newFlight[int](time.Second, ft.after)
	var round atomic.Int32
	hold := make(chan struct{})
	run := func(tokens []string) map[string]int {
		n := int(round.Add(1))
		if n == 1 {
			<-hold
		}
		out := map[string]int{}
		for _, tk := range tokens {
			out[tk] = n
		}
		return out
	}
	aDone := make(chan int, 1)
	go func() { r, _ := f.do(context.Background(), "k", "a", run); aDone <- r }()
	for round.Load() < 1 {
		time.Sleep(time.Millisecond)
	}
	// B arrives while round 1 (A's) is still running: it must get its own round.
	b, err := f.do(context.Background(), "k", "b", run)
	if err != nil || b != 2 {
		t.Fatalf("B got round %d (err %v), want its own round 2", b, err)
	}
	select {
	case <-aDone:
		t.Fatal("A returned before its round did")
	default:
	}
	close(hold)
	if a := <-aDone; a != 1 {
		t.Errorf("A = %d", a)
	}
}

func TestFlightAtMostTwoRoundsInFlightAndStallFreesASlot(t *testing.T) {
	ft := &fakeTimers{}
	f := newFlight[int](time.Second, ft.after)
	var inflight, maxIn, started atomic.Int32
	hold := make(chan struct{})
	run := func(tokens []string) map[string]int {
		n := inflight.Add(1)
		started.Add(1)
		for {
			m := maxIn.Load()
			if n <= m || maxIn.CompareAndSwap(m, n) {
				break
			}
		}
		<-hold
		inflight.Add(-1)
		out := map[string]int{}
		for _, tk := range tokens {
			out[tk] = 1
		}
		return out
	}
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = f.do(context.Background(), "k", fmt.Sprintf("t%d", i), run)
		}(i)
	}
	deadline := time.Now().Add(3 * time.Second)
	for started.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if started.Load() != 2 {
		t.Fatalf("started %d rounds with two held; the rest must wait for a slot", started.Load())
	}
	// Both held rounds stall: a slot frees for scheduling, so the pending round starts
	// although neither held round has returned.
	ft.fireAll()
	for started.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if started.Load() < 3 {
		t.Fatal("a stalled round must stop occupying a slot")
	}
	close(hold)
	wg.Wait()
	if f.keyCount() != 0 {
		t.Errorf("idle key not deleted: %d", f.keyCount())
	}
}

func TestFlightCallerCancelReturnsWithoutWaiting(t *testing.T) {
	f := newFlight[int](time.Second, (&fakeTimers{}).after)
	hold := make(chan struct{})
	defer close(hold)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := f.do(ctx, "k", "a", func([]string) map[string]int { <-hold; return nil })
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a cancelled wait must report an error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("do did not return after cancel")
	}
}

func TestFlightPanicInARoundDoesNotHangCallers(t *testing.T) {
	f := newFlight[int](time.Second, (&fakeTimers{}).after)
	_, err := f.do(context.Background(), "k", "a", func([]string) map[string]int { panic("boom") })
	if err == nil {
		t.Error("a round with no result must report an error")
	}
	if f.keyCount() != 0 {
		t.Error("key leaked after a panicking round")
	}
}

func TestFlightTokenSetIsBounded(t *testing.T) {
	f := newFlight[int](time.Hour, (&fakeTimers{}).after)
	hold := make(chan struct{})
	defer close(hold)
	run := func([]string) map[string]int { <-hold; return nil }
	for i := 0; i < 2; i++ { // fill both slots
		go func(i int) { _, _ = f.do(context.Background(), "k", fmt.Sprintf("s%d", i), run) }(i)
	}
	time.Sleep(50 * time.Millisecond)
	var full atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < maxRoundTokens+20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			if _, err := f.do(ctx, "k", fmt.Sprintf("p%d", i), run); err == errFlightFull {
				full.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if full.Load() != 20 {
		t.Errorf("%d callers refused as full, want exactly 20 over the cap of %d", full.Load(), maxRoundTokens)
	}
}

// ---- the stop gate against a real fixture ----------------------------------

func stopCtx() context.Context { return context.Background() }

func TestStopDeliversStopTrueTrueAndConfirms(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, time.Second, time.Millisecond)
	rep := stopAndConfirm(stopCtx(), fx.deps(5), "fx", "prof")
	if rep.Status != stopConfirmedIdle || rep.Err != nil || !rep.Sent {
		t.Fatalf("report = %+v", rep)
	}
	ops := fx.named("Stop")
	if len(ops) != 1 || !contains(ops[0].body, "<tptz:PanTilt>true</tptz:PanTilt>") || !contains(ops[0].body, "<tptz:Zoom>true</tptz:Zoom>") ||
		!contains(ops[0].body, "<tptz:ProfileToken>prof</tptz:ProfileToken>") {
		t.Fatalf("Stop requests = %+v", ops)
	}
	if rep.Final == nil || rep.Final.PanTiltState != "IDLE" {
		t.Errorf("final = %+v", rep.Final)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// The reviewer's scenario: stop A is in flight (reply held), a move is sent,
// stop B arrives. B's Stop must reach the camera after the move, and B must not
// be handed A's result.
func TestStopArrivingAfterAMoveIsNeverSwallowedByAnEarlierStop(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, 5*time.Second, time.Millisecond)
	fx.on("Stop", func(n int, w http.ResponseWriter, r *http.Request, _ string) bool {
		if n == 1 {
			fx.hold(r)
		}
		return false
	})
	d := fx.deps(5)
	aDone := make(chan stopReport, 1)
	fx.bg(t, func() { aDone <- stopAndConfirm(stopCtx(), d, "fx", "prof") })
	fx.waitCount(t, "Stop", 1, 5*time.Second)

	e, _ := d.Reg.Get("fx")
	c, err := e.Client(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.RelativeMove(context.Background(), "prof", &onvif.PTZVector{PanTilt: &onvif.Vector2D{X: 0.1}}, nil); err != nil {
		t.Fatal(err)
	}

	bRep := stopAndConfirm(stopCtx(), d, "fx", "prof")
	if bRep.Status != stopConfirmedIdle {
		t.Fatalf("B = %+v", bRep)
	}
	select {
	case <-aDone:
		t.Fatal("A returned although its Stop reply is held: B was answered with... or A was not held")
	default:
	}
	stops, moves := fx.named("Stop"), fx.named("RelativeMove")
	if len(stops) != 2 || len(moves) != 1 {
		t.Fatalf("stops=%d moves=%d", len(stops), len(moves))
	}
	if !stops[1].at.After(moves[0].at) {
		t.Errorf("B's Stop (%v) did not follow the move (%v)", stops[1].at, moves[0].at)
	}
}

func TestSecondStopReachesTheCameraWhileTheFirstReplyIsHeld(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, 200*time.Millisecond, time.Millisecond)
	fx.on("Stop", func(n int, w http.ResponseWriter, r *http.Request, _ string) bool {
		if n == 1 {
			fx.hold(r)
		}
		return false
	})
	d := fx.deps(10)
	fx.bg(t, func() { stopAndConfirm(stopCtx(), d, "fx", "prof") })
	fx.waitCount(t, "Stop", 1, 5*time.Second)
	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	rep := stopAndConfirm(stopCtx(), d, "fx", "prof")
	if rep.Status != stopConfirmedIdle {
		t.Fatalf("second = %+v", rep)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("the second stop waited %v behind a held reply", took)
	}
	if fx.count("Stop") != 2 {
		t.Errorf("Stop requests = %d", fx.count("Stop"))
	}
}

func TestThirdStopBehindTwoHeldRoundsWaitsAboutStallAfterNotTwoTimeouts(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, 300*time.Millisecond, time.Millisecond)
	fx.on("Stop", func(n int, w http.ResponseWriter, r *http.Request, _ string) bool {
		if n <= 2 {
			fx.hold(r)
		}
		return false
	})
	d := fx.deps(10)
	fx.bg(t, func() { stopAndConfirm(stopCtx(), d, "fx", "prof") })
	fx.bg(t, func() { stopAndConfirm(stopCtx(), d, "fx", "prof") })
	fx.waitCount(t, "Stop", 2, 5*time.Second)

	start := time.Now()
	rep := stopAndConfirm(stopCtx(), d, "fx", "prof")
	if rep.Status != stopConfirmedIdle {
		t.Fatalf("third = %+v", rep)
	}
	if took := time.Since(start); took > 300*time.Millisecond+time.Second {
		t.Errorf("third stop took %v; want about stallAfter (300ms) plus a margin", took)
	}
}

func TestFiftyRotatingProfileTokensCostAboutOneRoundAndSendNoStop(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, time.Second, time.Millisecond)
	arrived := make(chan struct{})
	var once sync.Once
	fx.on("GetProfiles", func(n int, w http.ResponseWriter, r *http.Request, _ string) bool {
		if n <= 2 {
			once.Do(func() { close(arrived) })
			select { // hold the first rounds until every caller has arrived
			case <-time.After(400 * time.Millisecond):
			case <-r.Context().Done():
			}
		}
		return false
	})
	d := fx.deps(10)
	var wg sync.WaitGroup
	var bad atomic.Int32
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rep := stopAndConfirm(stopCtx(), d, "fx", fmt.Sprintf("random-%d", i))
			if rep.Err == nil || rep.Err.Code != mcperr.CodeInvalidArgument || !rep.Err.NotSent || rep.Sent {
				bad.Add(1)
			}
		}(i)
	}
	<-arrived
	time.Sleep(100 * time.Millisecond)
	if n := gates.stop.keyCount(); n != 1 {
		t.Errorf("flight map has %d keys, want 1", n)
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Errorf("%d callers did not get invalid_argument/NotSent", bad.Load())
	}
	if n := fx.count("Stop"); n != 0 {
		t.Errorf("%d Stop requests were sent for profiles that do not exist", n)
	}
	if n := fx.count("GetProfiles"); n > 4 {
		t.Errorf("%d GetProfiles requests for 50 callers; rounds must be bounded", n)
	}
	if gates.stop.keyCount() != 0 {
		t.Error("idle key leaked")
	}
}

func TestInvalidProfileNamesTheRealProfilesAndNotTheRetryHint(t *testing.T) {
	fx := newPtzFx(t, "main", "sub")
	fastGates(t, time.Second, time.Millisecond)
	rep := stopAndConfirm(stopCtx(), fx.deps(5), "fx", "nope")
	if rep.Err == nil || rep.Err.Code != mcperr.CodeInvalidArgument || !rep.Err.NotSent {
		t.Fatalf("report = %+v", rep)
	}
	if !contains(rep.Err.Message+rep.Err.Hint, "main") || !contains(rep.Err.Message+rep.Err.Hint, "sub") {
		t.Errorf("the real profiles must be named: %q / %q", rep.Err.Message, rep.Err.Hint)
	}
	if contains(rep.Err.Hint, "ptz.stop again") {
		t.Errorf("a typo must not be told to call stop again: %q", rep.Err.Hint)
	}
}

func TestWhenGetProfilesFaultsAtMostFourTokensPerRoundGetAStop(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, time.Second, time.Millisecond)
	fx.on("GetProfiles", func(n int, w http.ResponseWriter, r *http.Request, _ string) bool {
		select {
		case <-time.After(300 * time.Millisecond):
		case <-r.Context().Done():
		}
		faultReply(w, "no media")
		return true
	})
	d := fx.deps(10)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			stopAndConfirm(stopCtx(), d, "fx", fmt.Sprintf("t%d", i))
		}(i)
	}
	wg.Wait()
	rounds := fx.count("GetProfiles")
	if rounds == 0 || fx.count("Stop") > 4*rounds {
		t.Errorf("rounds=%d stops=%d; each round may send at most 4", rounds, fx.count("Stop"))
	}
}

func TestTenConcurrentStopsOfOneProfileShareFewRoundsAndEachGetsAFreshStop(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, time.Second, time.Millisecond)
	var cur, maxCur atomic.Int32
	fx.on("Stop", func(n int, w http.ResponseWriter, r *http.Request, _ string) bool {
		c := cur.Add(1)
		for {
			m := maxCur.Load()
			if c <= m || maxCur.CompareAndSwap(m, c) {
				break
			}
		}
		time.Sleep(150 * time.Millisecond)
		cur.Add(-1)
		return false
	})
	d := fx.deps(10)
	var wg sync.WaitGroup
	arrivals := make([]time.Time, 10)
	reps := make([]stopReport, 10)
	for i := range reps {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			arrivals[i] = time.Now()
			reps[i] = stopAndConfirm(stopCtx(), d, "fx", "prof")
		}(i)
	}
	wg.Wait()
	if n := fx.count("Stop"); n < 1 || n > 3 {
		t.Errorf("Stop requests = %d, want 1 to 3 for 10 simultaneous callers", n)
	}
	if maxCur.Load() > 2 {
		t.Errorf("%d Stop rounds overlapped; at most 2", maxCur.Load())
	}
	stops := fx.named("Stop")
	for i, rep := range reps {
		if rep.Err != nil || rep.Status == stopFailed {
			t.Errorf("caller %d: %+v", i, rep)
		}
		fresh := false
		for _, s := range stops {
			if !s.at.Before(arrivals[i]) {
				fresh = true
			}
		}
		if !fresh {
			t.Errorf("caller %d was answered by a Stop that predates it", i)
		}
	}
}

func TestStopRoundsAreStopOnlyAndConfirmationRunsAfterThem(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, time.Second, time.Millisecond)
	d := fx.deps(5)
	e, _ := d.Reg.Get("fx")
	res := stopRoundFor(d, e)([]string{"prof"})
	if r := res["prof"]; r.te != nil || !r.sent {
		t.Fatalf("round result = %+v", r)
	}
	if n := fx.count("GetStatus"); n != 0 {
		t.Errorf("a stop round sent %d GetStatus requests; confirmation is outside the gate", n)
	}
	rep := stopAndConfirm(stopCtx(), d, "fx", "prof")
	if rep.Status != stopConfirmedIdle || fx.count("GetStatus") != 1 {
		t.Errorf("rep=%+v GetStatus=%d", rep, fx.count("GetStatus"))
	}
	ops := fx.all()
	lastStop, firstStatus := -1, -1
	for i, o := range ops {
		if o.name == "Stop" {
			lastStop = i
		}
		if o.name == "GetStatus" && firstStatus < 0 {
			firstStatus = i
		}
	}
	if firstStatus < lastStop {
		t.Errorf("a confirmation read preceded the last Stop: stop@%d status@%d", lastStop, firstStatus)
	}
}

func TestTransportErrorIsRetriedOnceAndSucceeds(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, time.Second, time.Millisecond)
	fx.on("GetCapabilities", func(n int, w http.ResponseWriter, _ *http.Request, _ string) bool {
		if n == 1 {
			dropConn(w)
			return true
		}
		return false
	})
	rep := stopAndConfirm(stopCtx(), fx.deps(8), "fx", "prof")
	if rep.Status != stopConfirmedIdle || rep.Err != nil {
		t.Fatalf("report = %+v", rep)
	}
	if fx.count("GetCapabilities") < 2 || fx.count("Stop") != 1 {
		t.Errorf("caps=%d stops=%d", fx.count("GetCapabilities"), fx.count("Stop"))
	}
}

func TestSOAPFaultNamingTheProfileIsNotRetried(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, time.Second, time.Millisecond)
	fx.on("Stop", func(n int, w http.ResponseWriter, _ *http.Request, _ string) bool {
		faultReply(w, "no such profile token")
		return true
	})
	rep := stopAndConfirm(stopCtx(), fx.deps(8), "fx", "prof")
	if rep.Status != stopFailed || rep.Err == nil || !rep.Sent {
		t.Fatalf("report = %+v", rep)
	}
	if fx.count("Stop") != 1 {
		t.Errorf("a SOAP fault was retried: %d Stop requests", fx.count("Stop"))
	}
}

func TestSlowInitializeStillLeavesTheRetryItsOwnTime(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, time.Second, time.Millisecond)
	fx.on("GetCapabilities", func(n int, w http.ResponseWriter, r *http.Request, _ string) bool {
		if n == 1 {
			time.Sleep(1500 * time.Millisecond) // just under attemptTimeout (2s)
			dropConn(w)
			return true
		}
		return false
	})
	// Camera timeout 4s: overall budget 4s, each attempt 2s.
	rep := stopAndConfirm(stopCtx(), fx.deps(4), "fx", "prof")
	if rep.Status != stopConfirmedIdle || rep.Err != nil {
		t.Fatalf("the retry must succeed within the budget: %+v", rep)
	}
}

func TestInitializeFailureIsFailedWithRetryNowHintAndNotSent(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, time.Second, time.Millisecond)
	fx.on("GetCapabilities", func(n int, w http.ResponseWriter, _ *http.Request, _ string) bool {
		faultReply(w, "initialising")
		return true
	})
	rep := stopAndConfirm(stopCtx(), fx.deps(4), "fx", "prof")
	if rep.Status != stopFailed || rep.Err == nil || rep.Sent {
		t.Fatalf("report = %+v", rep)
	}
	if !contains(rep.Err.Hint, "ptz.stop again") {
		t.Errorf("hint = %q", rep.Err.Hint)
	}
	if !rep.Err.NotSent {
		t.Error("an Initialize failure sent nothing; NotSent must be set so the audit says executed:false")
	}
}

func TestIdleKeysAreDeleted(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, time.Second, time.Millisecond)
	stopAndConfirm(stopCtx(), fx.deps(5), "fx", "prof")
	if gates.stop.keyCount() != 0 || gates.status.keyCount() != 0 {
		t.Errorf("leaked keys: stop=%d status=%d", gates.stop.keyCount(), gates.status.keyCount())
	}
}

func TestEveryStopCallBuildsItsOwnClient(t *testing.T) {
	fx := newPtzFx(t)
	fastGates(t, time.Second, time.Millisecond)
	d := fx.deps(5)
	var mu sync.Mutex
	seen := map[*onvif.Client]int{}
	d.clientHook = func(c *onvif.Client) {
		mu.Lock()
		seen[c]++
		mu.Unlock()
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stopAndConfirm(stopCtx(), d, "fx", "prof")
		}()
	}
	wg.Wait()
	if len(seen) == 0 {
		t.Fatal("the client hook was never called")
	}
	for c, n := range seen {
		if n != 1 {
			t.Errorf("client %p was handed out %d times", c, n)
		}
	}
}
