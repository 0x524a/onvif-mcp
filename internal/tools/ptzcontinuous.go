package tools

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	onvif "github.com/0x524a/onvif-go"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/redact"
	"github.com/0x524a/onvif-mcp/internal/safety"
)

// ptz.move_continuous is the one command whose end depends on something staying
// alive: the camera keeps moving until it is told to stop. The layers that end
// it, outermost first:
//
//  1. The camera's own ONVIF Timeout, sent with every move (onvifTimeout). It is
//     the only layer that survives this process being killed, running out of
//     memory or losing power, and onvif-go cannot read whether a camera honours
//     it (it exposes no PTZ GetNode or GetConfigurationOptions). That is why the
//     tool exists only for cameras whose operator attests ptz_honours_timeout.
//  2. The handler's own Stop at the deadline, on the client it built, from a
//     defer, on a context detached from the call: it also runs after a send
//     failure, a cancel, a shutdown (Deps.Base, and Server.Run waits for
//     handlers) and a panic.
//  3. ptz.stop, which interrupts the wait through the device lease; the handler
//     still sends its own Stop.
//
// Around them: duration_seconds is required and capped, the seconds of motion
// are charged to a per-device budget before the send, and the device lease
// keeps every other real move off the camera until this handler has stopped it.
const (
	moveContinuousTool = "ptz.move_continuous"
	moveContinuousOp   = "ContinuousMove"

	// maxContinuousVelocity is the server's cap on one axis of a continuous move,
	// in the generic velocity space (whose range is -1..1; see ptzbounds.go for
	// the status of that claim).
	maxContinuousVelocity = 0.5
	minContinuousSeconds  = 0.5
	maxContinuousSeconds  = 5.0

	// The generic velocity spaces, sent explicitly on every vector. SPEC STATUS:
	// as for the translation spaces in ptzbounds.go, recalled from the ONVIF PTZ
	// Service Specification and not checked against its text.
	panTiltVelocitySpace = "http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace"
	zoomVelocitySpace    = "http://www.onvif.org/ver10/tptz/ZoomSpaces/VelocityGenericSpace"

	motionStopAttempts = 3
)

// Seams, variables so tests do not wait for real durations.
var (
	// motionStopGap separates the stop attempts, motionStopAttempt bounds one,
	// and motionStopBudget bounds all of them: 3 attempts of at most 2 s, 1 s
	// apart, 8 s in all.
	motionStopGap     = time.Second
	motionStopAttempt = 2 * time.Second
	motionStopBudget  = 8 * time.Second
	// motionTimer starts the wait until the motion deadline.
	motionTimer = func(d time.Duration) (<-chan time.Time, func() bool) {
		t := time.NewTimer(d)
		return t.C, t.Stop
	}
	// afterContinuousSend, when set, runs right after the ContinuousMove request
	// returns. Tests use it to panic past the send.
	afterContinuousSend func()
)

// What ended a continuous move's wait (audit stopped_by and the result).
const (
	stoppedDeadline   = "deadline"
	stoppedByStop     = "ptz.stop"
	stoppedCancelled  = "cancelled"
	stoppedShutdown   = "shutdown"
	stoppedSendFailed = "send_failed"
	stoppedPanic      = "panic"
)

// MoveContinuousIn is the input of ptz.move_continuous. Every axis is a pointer
// so absent differs from 0. duration_seconds is required and has no default.
type MoveContinuousIn struct {
	safety.WriteBase
	Profile         string   `json:"profile" jsonschema:"the token of a media profile with has_ptz true; call media.profiles first to get it"`
	Pan             *float64 `json:"pan,omitempty" jsonschema:"pan velocity in the ONVIF generic velocity space; magnitude at most 0.5, larger values are refused, not clamped; which way a positive value moves the camera, and how fast, is defined by the camera; omit for no pan"`
	Tilt            *float64 `json:"tilt,omitempty" jsonschema:"tilt velocity in the ONVIF generic velocity space; magnitude at most 0.5, larger values are refused, not clamped; which way a positive value moves the camera, and how fast, is defined by the camera; omit for no tilt"`
	Zoom            *float64 `json:"zoom,omitempty" jsonschema:"zoom velocity in the ONVIF generic velocity space; magnitude at most 0.5, larger values are refused, not clamped; what a positive value does is defined by the camera; omit for no zoom"`
	DurationSeconds float64  `json:"duration_seconds" jsonschema:"required: how long to move, from 0.5 to 5 seconds; the call blocks this long, then stops the camera itself; also sent to the camera as its ONVIF Timeout"`
}

// ContinuousData is what ptz.move_continuous reports, for a dry run and a real
// call. A move whose stop could not be delivered is reported through the error
// envelope, never here.
type ContinuousData struct {
	Mode            string      `json:"mode" jsonschema:"always continuous"`
	Executed        bool        `json:"executed" jsonschema:"true only when the move command was sent to the camera; false for a dry run"`
	DryRun          bool        `json:"dry_run" jsonschema:"true when this call only checked the move and sent nothing"`
	Profile         string      `json:"profile" jsonschema:"the profile token the call addressed"`
	Requested       Axes        `json:"requested" jsonschema:"the exact velocities sent (or that a real call would send); an omitted pan or tilt next to a sent one is 0"`
	DurationSeconds float64     `json:"duration_seconds" jsonschema:"the requested duration"`
	CameraTimeout   string      `json:"camera_timeout" jsonschema:"the ONVIF Timeout sent with the move (the duration rounded up to the millisecond), after which an attested camera stops by itself"`
	SpaceSent       string      `json:"space_sent" jsonschema:"the ONVIF generic velocity space URIs the command carries, so the unit is visible"`
	StoppedBy       string      `json:"stopped_by,omitempty" jsonschema:"what ended the move: deadline (duration_seconds ran out), ptz.stop, cancelled (the request was cancelled), shutdown (the server is stopping) or send_failed; absent for a dry run"`
	StopStatus      string      `json:"stop_status,omitempty" jsonschema:"confirmed_idle: the server's stop was delivered and the camera reports it idle; sent_unconfirmed: delivered but not confirmed; absent for a dry run"`
	Final           *StatusData `json:"final,omitempty" jsonschema:"the last PTZ status read after the stop, same shape as ptz.status; absent means none could be read"`
	Note            string      `json:"note" jsonschema:"what happened and what to do next"`
}

func moveContinuousSchema() *jsonschema.Schema {
	s, err := jsonschema.For[MoveContinuousIn](nil)
	if err != nil {
		panic("tools: ptz.move_continuous input schema: " + err.Error())
	}
	one := 1
	p, ok := s.Properties["profile"]
	if !ok {
		panic("tools: ptz.move_continuous input schema has no property profile")
	}
	p.MinLength = &one
	// No minimum/maximum on the axes or the duration: the SDK would refuse them
	// before the handler with its own generic text. The handler owns the refusal.
	return s
}

// registerPTZMoveContinuous registers ptz.move_continuous through GuardedTool as
// RiskWrite, NonIdempotent and RequiresTimeoutAttestation.
//
// onvif-go (v1.2.1): (*Client).ContinuousMove(ctx, profileToken string,
// velocity *PTZSpeed, timeout *string) error, ptz.go:244; the timeout is written
// verbatim into tptz:Timeout, so it must already be an xs:duration. The stop is
// (*Client).Stop, ptz.go:340, and confirmation (*Client).GetStatus, ptz.go:377.
func registerPTZMoveContinuous(srv *mcp.Server, d Deps) {
	GuardedTool(srv, d, safety.RiskWrite, &mcp.Tool{
		InputSchema: moveContinuousSchema(),
		Name:        moveContinuousTool,
		Description: "Use this to sweep a PTZ camera for a short, fixed time. Call media.profiles first for a profile with " +
			"has_ptz true. Pass pan, tilt and/or zoom, each a velocity sent in the ONVIF generic velocity space whose " +
			"magnitude is at most 0.5 (larger values are refused, not clamped; at least one must be non-zero), and the " +
			"required duration_seconds, 0.5 to 5. What a value means physically, and which way a positive value moves the " +
			"camera, is defined by the camera: check ptz.status or camera.snapshot afterwards. A real call blocks for the " +
			"duration, then the server stops the camera itself and reports stop_status; the duration is also sent as the " +
			"camera's ONVIF Timeout. It only exists for cameras whose operator set ptz_honours_timeout, attesting that the " +
			"camera stops by itself when that Timeout runs out, because if this server dies mid-move nothing else stops it. " +
			"It is a dry run by default: with dry_run omitted or true it validates and reports what it would send, and moves " +
			"nothing; pass dry_run false to move. Real moves draw on a per-camera budget of seconds of motion, are rate " +
			"limited, and keep the camera busy for every other move until stopped. ptz.stop ends one early. If the call " +
			"fails after the command was sent, the camera may still be moving: call ptz.stop at once, then ptz.status. " +
			"Does not do absolute moves or set a speed.",
		Annotations: safety.WriteAnnotationsNonIdempotent("Sweep PTZ camera for a fixed time"),
	}, moveContinuousRun(d), moveContinuousDryRun(d), NonIdempotent(), RequiresTimeoutAttestation())
}

// onvifTimeout renders secs as the xs:duration sent in tptz:Timeout: rounded up
// to whole milliseconds (so the camera never ends the move before the server
// would), in plain decimal (FormatFloat 'f', never an exponent, never a locale
// separator). The rounding first goes to the microsecond, so float noise such as
// 2.3 being 2.2999999999999998 cannot add a millisecond.
func onvifTimeout(secs float64) string {
	us := math.Round(secs * 1e6)
	ms := math.Ceil(us / 1000)
	return "PT" + strconv.FormatFloat(ms/1000, 'f', -1, 64) + "S"
}

func invalidContinuous(camera, msg, hint string) *mcperr.ToolError {
	te := invalid(camera, msg, hint)
	te.Operation = moveContinuousOp
	return te
}

// validateContinuous applies the bounds to the agent's input. It touches no
// camera. -0 becomes 0, NaN and infinities are refused, an omitted axis is 0, at
// least one axis must be non-zero, and duration_seconds must be within bounds.
// Out-of-range input is refused, never clamped.
func validateContinuous(in MoveContinuousIn) (relativeVector, time.Duration, *mcperr.ToolError) {
	cam := in.Camera
	if in.Profile == "" || len(in.Profile) > maxProfileBytes {
		return relativeVector{}, 0, invalidContinuous(cam, fmt.Sprintf("profile must be a token of 1 to %d bytes", maxProfileBytes), noPTZHint)
	}
	vals := map[string]float64{}
	for _, a := range []struct {
		name string
		v    *float64
	}{{"pan", in.Pan}, {"tilt", in.Tilt}, {"zoom", in.Zoom}} {
		if a.v == nil {
			continue
		}
		v := *a.v
		if !finite(v) {
			return relativeVector{}, 0, invalidContinuous(cam, a.name+" must be a finite number",
				fmt.Sprintf("call ptz.move_continuous again with %s between -%g and %g", a.name, maxContinuousVelocity, maxContinuousVelocity))
		}
		if math.Abs(v) > maxContinuousVelocity {
			return relativeVector{}, 0, invalidContinuous(cam,
				fmt.Sprintf("%s %s is outside the allowed range -%g to %g (source: server cap, not configurable); it was refused, not clamped",
					a.name, strconv.FormatFloat(v, 'g', 6, 64), maxContinuousVelocity, maxContinuousVelocity),
				fmt.Sprintf("call ptz.move_continuous again with %s at most %g in magnitude, for example %s %g",
					a.name, maxContinuousVelocity, a.name, math.Copysign(maxContinuousVelocity, v)))
		}
		if v == 0 {
			v = 0 // -0 becomes 0
		}
		vals[a.name] = v
	}
	var out relativeVector
	if vals["pan"] != 0 || vals["tilt"] != 0 {
		out.panTilt = &[2]float64{vals["pan"], vals["tilt"]}
	}
	if vals["zoom"] != 0 {
		z := vals["zoom"]
		out.zoom = &z
	}
	if out.panTilt == nil && out.zoom == nil {
		return relativeVector{}, 0, invalidContinuous(cam,
			"at least one of pan, tilt or zoom must be present and non-zero; an omitted axis is 0",
			fmt.Sprintf("call ptz.move_continuous again with a non-zero pan, tilt or zoom of at most %g in magnitude; to stop a camera use ptz.stop", maxContinuousVelocity))
	}
	secs := in.DurationSeconds
	if !finite(secs) || secs < minContinuousSeconds || secs > maxContinuousSeconds {
		return relativeVector{}, 0, invalidContinuous(cam,
			fmt.Sprintf("duration_seconds %s is outside the allowed range %g to %g (source: server cap, not configurable); it was refused, not clamped",
				strconv.FormatFloat(secs, 'g', 6, 64), minContinuousSeconds, maxContinuousSeconds),
			fmt.Sprintf("call ptz.move_continuous again with duration_seconds from %g to %g, for example 1", minContinuousSeconds, maxContinuousSeconds))
	}
	return out, time.Duration(secs * float64(time.Second)), nil
}

func velocitySpaceSent(v relativeVector) string {
	switch {
	case v.panTilt != nil && v.zoom != nil:
		return panTiltVelocitySpace + " (pan, tilt); " + zoomVelocitySpace + " (zoom)"
	case v.panTilt != nil:
		return panTiltVelocitySpace + " (pan, tilt)"
	default:
		return zoomVelocitySpace + " (zoom)"
	}
}

// continuousPlan is a validated continuous move: the camera is reachable, the
// profile carries PTZ. c is the call's own client, used for the move and for the
// stop that ends it, and never shared.
type continuousPlan struct {
	c    *onvif.Client
	vel  relativeVector
	dur  time.Duration
	data ContinuousData
}

// planContinuous is the validation the dry run and the real call share. It sends
// only reads (GetProfiles).
//
// onvif-go calls (v1.2.1): (*Client).GetProfiles, media.go.
func planContinuous(ctx context.Context, d Deps, in MoveContinuousIn) (*continuousPlan, *mcperr.ToolError) {
	safety.NoteTarget(ctx, in.Profile)
	vel, dur, te := validateContinuous(in)
	if te != nil {
		return nil, te
	}
	ax := vel.axes()
	safety.NoteMotion(ctx, safety.MotionAudit{Mode: "continuous", Pan: ax.Pan, Tilt: ax.Tilt, Zoom: ax.Zoom})

	c, te := d.client(ctx, in.Camera, moveContinuousOp)
	if te != nil {
		return nil, notSent(te)
	}
	profiles, err := c.GetProfiles(ctx)
	if err != nil {
		return nil, notSent(mcperr.FromError(err, in.Camera, "GetProfiles"))
	}
	prof := findProfile(profiles, in.Profile)
	if prof == nil {
		return nil, invalidContinuous(in.Camera, "the camera has no media profile with that token",
			"profiles on this camera: "+listProfiles(profiles)+"; pass the token of one whose has_ptz is true as profile")
	}
	if prof.PTZConfiguration == nil {
		return nil, &mcperr.ToolError{
			Code: mcperr.CodeNotSupported, Camera: in.Camera, Operation: moveContinuousOp, NotSent: true,
			Message: "that profile carries no PTZ configuration, so it cannot be moved",
			Hint:    noPTZHint,
		}
	}
	return &continuousPlan{c: c, vel: vel, dur: dur, data: ContinuousData{
		Mode:            "continuous",
		Profile:         clip(redact.Scrub(prof.Token)),
		Requested:       ax,
		DurationSeconds: in.DurationSeconds,
		CameraTimeout:   onvifTimeout(in.DurationSeconds),
		SpaceSent:       velocitySpaceSent(vel),
	}}, nil
}

func continuousSummary(p *continuousPlan) string {
	a := p.data.Requested
	return fmt.Sprintf("continuous move %s for %ss", fmtPos(a.Pan, a.Tilt, a.Zoom), strconv.FormatFloat(p.data.DurationSeconds, 'f', -1, 64))
}

func moveContinuousDryRun(d Deps) mcp.ToolHandlerFor[MoveContinuousIn, mcperr.Out[ContinuousData]] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in MoveContinuousIn) (*mcp.CallToolResult, mcperr.Out[ContinuousData], error) {
		planCtx, cancel := wholeCall(ctx, d, in.Camera)
		defer cancel()
		plan, te := planContinuous(planCtx, d, in)
		if te != nil {
			return fail[ContinuousData](te)
		}
		if te := checkBudgetFor(ctx, planCtx, in.Camera, moveContinuousOp); te != nil {
			return fail[ContinuousData](te)
		}
		plan.data.DryRun = true
		plan.data.Note = "Dry run: nothing was sent and the camera did not move. To move it, call ptz.move_continuous again " +
			"with the same arguments and dry_run false; that call blocks for duration_seconds, then stops the camera."
		return text("Dry run, camera not moved; would send " + continuousSummary(plan) + ". Pass dry_run false to move."),
			mcperr.OK(plan.data), nil
	}
}

// newMotionID returns a server-generated id that pairs a motion's start and stop
// audit records.
func newMotionID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "m-" + hex.EncodeToString(b)
}

// motionStop is the outcome of the stop section of a continuous move.
type motionStop struct {
	status string // stopConfirmedIdle, stopSentUnconfirmed or stopFailed
	final  *StatusData
	reason string            // why it is not confirmed
	te     *mcperr.ToolError // set when status is stopFailed
}

// stopMotion is the stop section: Stop(true, true) on profile with the move's own
// client c, up to motionStopAttempts attempts motionStopGap apart, within
// motionStopBudget, then confirmation (confirmStopped) through c on a fresh
// confirmWindow. Both run on contexts detached from ctx, so a cancelled request
// or a shutdown cannot abort them. Every failure is retried, because a Stop on an
// idle camera is harmless and this may be the only one sent.
//
// onvif-go (v1.2.1): (*Client).Stop, ptz.go:340; (*Client).GetStatus, ptz.go:377.
func stopMotion(ctx context.Context, c *onvif.Client, camera, profile string) motionStop {
	detached := context.WithoutCancel(ctx)
	sctx, cancel := context.WithTimeout(detached, motionStopBudget)
	defer cancel()
	var last error
	unverified := false
	delivered := false
	for i := 0; i < motionStopAttempts && sctx.Err() == nil; i++ {
		if i > 0 {
			select {
			case <-time.After(motionStopGap):
			case <-sctx.Done():
			}
			if sctx.Err() != nil {
				break
			}
		}
		actx, acancel := context.WithTimeout(sctx, motionStopAttempt)
		err := c.Stop(actx, profile, true, true)
		acancel()
		if err == nil || errors.Is(err, onvif.ErrEmptyResponseBody) {
			// An empty 200 may have acted, but cannot be vouched for.
			delivered, unverified = true, err != nil
			break
		}
		last = err
	}
	if !delivered {
		if last == nil {
			last = context.DeadlineExceeded
		}
		return motionStop{status: stopFailed, te: mcperr.FromError(last, camera, "Stop")}
	}
	cctx, ccancel := context.WithTimeout(detached, confirmWindow)
	defer ccancel()
	status, final, reason := confirmStopped(cctx, func(rctx context.Context) (*onvif.PTZStatus, bool) {
		st, err := c.GetStatus(rctx, profile)
		return st, err == nil
	}, unverified)
	return motionStop{status: status, final: final, reason: reason}
}

// stopDoneNote describes a delivered stop for the result note (clipped at 256).
func stopDoneNote(by string, s motionStop) string {
	var b strings.Builder
	switch by {
	case stoppedDeadline:
		b.WriteString("Moved for duration_seconds; the server then stopped it.")
	case stoppedByStop:
		b.WriteString("Ended early by ptz.stop; the server also sent its own stop.")
	case stoppedShutdown:
		b.WriteString("Ended early: the server is shutting down; it stopped the camera first.")
	default:
		b.WriteString("Ended early: the request was cancelled; the server stopped the camera.")
	}
	if s.status == stopConfirmedIdle {
		b.WriteString(" The camera reports it idle.")
	} else {
		b.WriteString(" Stop delivered, not confirmed: " + s.reason + ". Check ptz.status.")
	}
	return b.String()
}

// moveContinuousRun validates exactly as the dry run does, charges the motion
// budget, sends ContinuousMove once (never retried) with the explicit generic
// velocity space and the ONVIF Timeout, waits for the deadline, a cancel, a
// shutdown or an interrupt, and always stops the camera itself (stopMotion), from
// a defer, so that also happens after a send failure or a panic.
func moveContinuousRun(d Deps) mcp.ToolHandlerFor[MoveContinuousIn, mcperr.Out[ContinuousData]] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in MoveContinuousIn) (
		res *mcp.CallToolResult, out mcperr.Out[ContinuousData], err error,
	) {
		planCtx, cancel := wholeCall(ctx, d, in.Camera)
		defer cancel()
		plan, te := planContinuous(planCtx, d, in)
		if te != nil {
			return fail[ContinuousData](te)
		}
		if te := checkBudgetFor(ctx, planCtx, in.Camera, moveContinuousOp); te != nil {
			return fail[ContinuousData](te)
		}
		lease := safety.LeaseFrom(ctx)
		if lease == nil {
			// Unreachable through the guard, which grants every real write a lease.
			return fail[ContinuousData](&mcperr.ToolError{
				Code: mcperr.CodeInternal, Camera: in.Camera, Operation: moveContinuousOp, NotSent: true,
				Message: "the call holds no device lease, so continuous movement is refused",
				Hint:    misconfiguredTool,
			})
		}
		// Charged in full, last, immediately before the send: nothing after this
		// point can avoid it, and it is never refunded.
		if te := d.Policy.ChargeMotion(in.Camera, moveContinuousTool, in.DurationSeconds); te != nil {
			return fail[ContinuousData](te)
		}

		timeout := plan.data.CameraTimeout
		v := &onvif.PTZSpeed{}
		if plan.vel.panTilt != nil {
			v.PanTilt = &onvif.Vector2D{X: plan.vel.panTilt[0], Y: plan.vel.panTilt[1], Space: panTiltVelocitySpace}
		}
		if plan.vel.zoom != nil {
			v.Zoom = &onvif.Vector1D{X: *plan.vel.zoom, Space: zoomVelocitySpace}
		}

		id := newMotionID()
		ax := plan.data.Requested
		t0 := time.Now() // before the send: the send's own time counts toward the duration
		lease.SetUntil(t0.Add(plan.dur))
		d.Policy.AuditMotionStarted(moveContinuousTool, in.Camera, id,
			safety.MotionAudit{Mode: "continuous", Pan: ax.Pan, Tilt: ax.Tilt, Zoom: ax.Zoom}, plan.dur.Milliseconds())

		stoppedBy := stoppedPanic
		var sendErr error
		defer func() {
			// Runs on every exit past this point, panics included. It must stay
			// the first thing this handler does on the way out.
			s := stopMotion(ctx, plan.c, in.Camera, in.Profile)
			d.Policy.AuditMotionStopped(moveContinuousTool, in.Camera, id, stoppedBy, s.status, s.status != stopFailed)
			res, out, err = continuousResult(in, plan, stoppedBy, sendErr, s)
		}()

		sendErr = plan.c.ContinuousMove(ctx, in.Profile, v, &timeout)
		if afterContinuousSend != nil {
			afterContinuousSend()
		}
		if sendErr != nil {
			// An ambiguous send counts as sent: stop at once.
			stoppedBy = stoppedSendFailed
			return
		}
		tc, stopTimer := motionTimer(plan.dur - time.Since(t0))
		defer stopTimer()
		select {
		case <-tc:
			stoppedBy = stoppedDeadline
		case <-lease.Interrupted():
			stoppedBy = stoppedByStop
		case <-ctx.Done():
			stoppedBy = stoppedCancelled
			if d.Base != nil && d.Base.Err() != nil {
				stoppedBy = stoppedShutdown
			}
		}
		return
	}
}

// misconfiguredTool is the hint for a refusal only a wiring bug can reach.
const misconfiguredTool = "this is a server bug; report it to the operator, do not retry"

// continuousResult builds the reply once the stop section has run.
func continuousResult(in MoveContinuousIn, plan *continuousPlan, stoppedBy string, sendErr error, s motionStop) (
	*mcp.CallToolResult, mcperr.Out[ContinuousData], error,
) {
	if s.status == stopFailed {
		te := *s.te
		te.Camera = in.Camera
		te.Operation = moveContinuousOp
		te.Retryable = false
		what := "after the continuous move"
		if sendErr != nil {
			what = "after a continuous move command whose outcome is unknown (" + mcperr.FromError(sendErr, in.Camera, moveContinuousOp).Message + ")"
		}
		te.Message = "MOTION MAY CONTINUE on camera " + in.Camera + ": the server could not deliver its stop " + what +
			": " + s.te.Message
		te.Hint = "call ptz.stop now and repeat until it succeeds; the camera was also sent an ONVIF Timeout of " +
			plan.data.CameraTimeout + ", which its operator attests it honours; if ptz.stop keeps failing, tell an operator"
		return fail[ContinuousData](&te)
	}
	if sendErr != nil {
		te := mcperr.FromError(sendErr, in.Camera, moveContinuousOp)
		te.Message += "; the server then sent its stop: " + s.status
		if te.SOAP != nil {
			te.Hint = strings.TrimSpace(te.Hint + " The camera answered with a SOAP fault; if it names an unsupported space or velocity, the camera rejected the explicit generic velocity Space or the value. This server never resends without the Space.")
		}
		return fail[ContinuousData](te)
	}
	data := plan.data
	data.Executed = true
	data.StoppedBy = stoppedBy
	data.StopStatus = s.status
	data.Final = s.final
	data.Note = stopDoneNote(stoppedBy, s)
	msg := "Continuous move ran and was stopped (" + stoppedBy + "); camera reports idle."
	if s.status != stopConfirmedIdle {
		msg = "Continuous move ran and was stopped (" + stoppedBy + "); stop not confirmed, check ptz.status."
	}
	return text(msg), mcperr.OK(data), nil
}
