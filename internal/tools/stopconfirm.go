package tools

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	onvif "github.com/0x524a/onvif-go"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/redact"
	"github.com/0x524a/onvif-mcp/internal/registry"
)

// Stop outcomes. failed is reported through the error envelope (a result holds
// either data or an error), the other two as StopData.StopStatus.
const (
	stopConfirmedIdle   = "confirmed_idle"
	stopSentUnconfirmed = "sent_unconfirmed"
	stopFailed          = "failed"
)

const (
	// maxProfileBytes bounds the agent-chosen profile token before it reaches a
	// flight or a camera.
	maxProfileBytes = 128
	// maxBlindStops bounds how many distinct tokens one round sends a Stop for
	// when the camera's profile list could not be read.
	maxBlindStops = 4
	// minAttempt is the floor of one Initialize+Stop attempt.
	minAttempt    = 2 * time.Second
	confirmPolls  = 3
	listedProfMax = 8
)

// Timing seams, variables so tests do not sleep for real durations.
var (
	stopStallAfter = time.Second
	confirmDelay   = 300 * time.Millisecond
	confirmWindow  = 3 * time.Second
)

// ptzGates is the pair of flights behind ptz.stop: one for Stop rounds, one for
// the status reads that confirm them. Both are keyed by device key only.
type ptzGates struct {
	stop   *flight[stopResult]
	status *flight[statusResult]
}

func newGates(stall time.Duration) *ptzGates {
	return &ptzGates{stop: newFlight[stopResult](stall, nil), status: newFlight[statusResult](stall, nil)}
}

var gates = newGates(stopStallAfter)

// stopResult is one token's outcome in a Stop round.
type stopResult struct {
	sent       bool // a Stop request was dispatched for this token
	validation bool // the token itself was refused (unknown profile, no PTZ)
	unverified bool // the camera answered 200 with an empty body
	te         *mcperr.ToolError
}

// statusResult is one token's outcome in a confirmation round.
type statusResult struct {
	st *onvif.PTZStatus
	te *mcperr.ToolError
}

// stopReport is the outcome of stopAndConfirm.
type stopReport struct {
	Status string      // stopConfirmedIdle, stopSentUnconfirmed or stopFailed
	Final  *StatusData // the last status read; nil if none was read
	Sent   bool        // a Stop request left the server
	Err    *mcperr.ToolError
	Note   string
}

// freshClient builds a new, initialised client. Each round builds its own and
// never shares it across goroutines.
func (d Deps) freshClient(ctx context.Context, e *registry.Entry) (*onvif.Client, error) {
	c, err := e.Client(ctx)
	if err == nil && d.clientHook != nil {
		d.clientHook(c)
	}
	return c, err
}

// transient reports whether a failure is worth one immediate retry with a fresh
// client: connect, Initialize, timeout, or a 5xx that is not a SOAP fault. A SOAP
// fault (which names the profile or the state) and an auth failure are not.
func transient(te *mcperr.ToolError) bool {
	if te == nil || te.SOAP != nil {
		return false
	}
	switch te.Code {
	case mcperr.CodeUnreachable, mcperr.CodeTimeout:
		return true
	case mcperr.CodeDeviceFault:
		return true
	}
	return false
}

// attemptBudget returns the overall budget and the per-attempt share.
func attemptBudget(e *registry.Entry) (total, attempt time.Duration) {
	total = e.Timeout()
	attempt = total / 2
	if attempt < minAttempt {
		attempt = minAttempt
	}
	if attempt > total {
		attempt = total
	}
	return total, attempt
}

// stopRoundFor returns the round function for a Stop round on entry e. A round
// is Stop only: one fresh client, Initialize, one GetProfiles, then Stop(true,
// true) for each distinct requested token that exists. Confirmation is not part
// of it.
//
// onvif-go (v1.2.0): (*Client).GetProfiles, media.go; (*Client).Stop(ctx,
// profileToken, panTilt, zoom bool), ptz.go:307. Stop serialises only a true
// flag, so both are true to stop pan/tilt and zoom.
func stopRoundFor(d Deps, e *registry.Entry) func(tokens []string) map[string]stopResult {
	return func(tokens []string) map[string]stopResult {
		total, attempt := attemptBudget(e)
		// The halt guard detaches at haltBudget; keep the round, and the
		// confirmation after it, inside that so a round never outlives its caller.
		if capped := haltBudget - confirmWindow; total > capped {
			total = capped
			if attempt > total {
				attempt = total
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), total)
		defer cancel()

		results := make(map[string]stopResult, len(tokens))
		pending := tokens
		for try := 0; try < 2 && len(pending) > 0 && ctx.Err() == nil; try++ {
			actx, acancel := context.WithTimeout(ctx, attempt)
			pending = stopAttempt(actx, d, e, pending, results)
			acancel()
		}
		for _, tk := range tokens {
			if _, ok := results[tk]; !ok {
				results[tk] = stopResult{te: mcperr.FromError(context.DeadlineExceeded, e.ID(), "Stop")}
			}
		}
		return results
	}
}

// record stores r for tk, keeping sent true if an earlier attempt already
// dispatched a Stop for it: a later failure must not claim nothing was sent.
func record(results map[string]stopResult, tk string, r stopResult) {
	if prev, ok := results[tk]; ok && prev.sent {
		r.sent = true
	}
	results[tk] = r
}

// stopAttempt runs one Initialize+GetProfiles+Stop pass for tokens, recording
// every outcome in results, and returns the tokens worth retrying.
func stopAttempt(ctx context.Context, d Deps, e *registry.Entry, tokens []string, results map[string]stopResult) (retry []string) {
	fail := func(te *mcperr.ToolError, sent bool, which []string) []string {
		for _, tk := range which {
			cp := *te
			record(results, tk, stopResult{sent: sent, te: &cp})
		}
		if transient(te) {
			return which
		}
		return nil
	}

	c, err := d.freshClient(ctx, e)
	if err != nil {
		te := mcperr.FromError(err, e.ID(), "Initialize")
		te.NotSent = true
		return fail(te, false, tokens)
	}
	// The profile read is best effort and never gates Stop: it gets half the
	// attempt so a hung media service leaves time for the Stop itself.
	pctx, pcancel := context.WithTimeout(ctx, attemptShare(ctx))
	profiles, err := c.GetProfiles(pctx)
	pcancel()
	targets := tokens
	known := map[string]*onvif.Profile{}
	listed := err == nil
	if err != nil {
		te := mcperr.FromError(err, e.ID(), "GetProfiles")
		te.NotSent = true
		// The profile list is unreadable (of any class, transient or not), so the
		// tokens cannot be checked. Stop is harmless on an idle camera and the PTZ
		// service may be healthy when the media service is not, so send it for a
		// few tokens; refuse the rest.
		if len(tokens) > maxBlindStops {
			over := &mcperr.ToolError{
				Code: mcperr.CodeUnreachable, Retryable: true, Camera: e.ID(), Operation: "Stop", NotSent: true,
				Message: "the camera's profile list could not be read, so only a few profiles can be stopped at once",
			}
			fail(over, false, tokens[maxBlindStops:])
			targets = tokens[:maxBlindStops]
		}
	} else {
		for _, p := range profiles {
			if p != nil {
				known[p.Token] = p
			}
		}
	}

	for _, tk := range targets {
		if listed {
			p, ok := known[tk]
			if !ok {
				record(results, tk, stopResult{validation: true, te: &mcperr.ToolError{
					Code: mcperr.CodeInvalidArgument, Camera: e.ID(), Operation: "Stop", NotSent: true,
					Message: "the camera has no media profile with that token, so nothing was stopped",
					Hint:    "profiles on this camera: " + listProfiles(profiles) + "; pass one of them as profile",
				}})
				continue
			}
			if p.PTZConfiguration == nil {
				record(results, tk, stopResult{validation: true, te: &mcperr.ToolError{
					Code: mcperr.CodeNotSupported, Camera: e.ID(), Operation: "Stop", NotSent: true,
					Message: "that profile carries no PTZ configuration, so there is nothing to stop",
					Hint:    noPTZHint,
				}})
				continue
			}
		}
		err := c.Stop(ctx, tk, true, true)
		switch {
		case err == nil:
			record(results, tk, stopResult{sent: true})
		case errors.Is(err, onvif.ErrEmptyResponseBody):
			// HTTP 200 with no body: the camera may have acted, but nothing can be
			// vouched for.
			record(results, tk, stopResult{sent: true, unverified: true})
		default:
			te := mcperr.FromError(err, e.ID(), "Stop")
			record(results, tk, stopResult{sent: true, te: te})
			if transient(te) {
				retry = append(retry, tk)
			}
		}
	}
	return retry
}

// attemptShare is half of what is left of ctx, for the profile read.
func attemptShare(ctx context.Context) time.Duration {
	dl, ok := ctx.Deadline()
	if !ok {
		return minAttempt
	}
	d := time.Until(dl) / 2
	if d < time.Millisecond {
		d = time.Millisecond
	}
	return d
}

// listProfiles renders up to listedProfMax profile tokens for a hint.
func listProfiles(ps []*onvif.Profile) string {
	var toks []string
	for _, p := range ps {
		if p == nil {
			continue
		}
		if len(toks) == listedProfMax {
			toks = append(toks, "...")
			break
		}
		toks = append(toks, clip(redact.Scrub(cleanString(p.Token, 64))))
	}
	if len(toks) == 0 {
		return "none reported"
	}
	return strings.Join(toks, ", ")
}

// statusRoundFor returns the round function for a confirmation round: one fresh
// client, Initialize, then GetStatus per token. It only reads.
//
// onvif-go (v1.2.0): (*Client).GetStatus(ctx, profileToken), ptz.go:344.
func statusRoundFor(d Deps, e *registry.Entry) func(tokens []string) map[string]statusResult {
	return func(tokens []string) map[string]statusResult {
		budget := e.Timeout()
		if budget > confirmWindow {
			budget = confirmWindow
		}
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		out := make(map[string]statusResult, len(tokens))
		c, err := d.freshClient(ctx, e)
		if err != nil {
			te := mcperr.FromError(err, e.ID(), "Initialize")
			for _, tk := range tokens {
				out[tk] = statusResult{te: te}
			}
			return out
		}
		for _, tk := range tokens {
			st, err := c.GetStatus(ctx, tk)
			if err != nil {
				out[tk] = statusResult{te: mcperr.FromError(err, e.ID(), "GetStatus")}
				continue
			}
			out[tk] = statusResult{st: st}
		}
		return out
	}
}

const retryStopHint = "call ptz.stop again immediately; if it keeps failing, treat the camera as possibly still moving and tell an operator"

// deliveryFailure turns a failed Stop round result into the error an agent sees.
func deliveryFailure(r stopResult, camera string) *mcperr.ToolError {
	te := *r.te
	te.Camera = camera
	te.NotSent = !r.sent
	te.Message = "the stop was not delivered: " + te.Message
	if te.Code != mcperr.CodeAuthFailed && te.Code != mcperr.CodeNotSupported {
		te.Retryable = true
		te.Hint = retryStopHint
	}
	return &te
}

// stopAndConfirm stops motion on a profile and reports how sure it is.
//
// Stage 1 is the Stop round through the stop gate (its own deadline, one retry on
// a transport error). Stage 2 is confirmation: up to confirmPolls GetStatus reads
// confirmDelay apart through the second flight, on a fresh context, so it can
// neither consume the Stop's budget nor delay a following stop.
//
//   - confirmed_idle: Stop succeeded and a read reported IDLE for every state
//     field the camera reported, at least one being present.
//   - sent_unconfirmed: Stop succeeded but the camera said MOVING or UNKNOWN,
//     reported no state at all, answered the stop with an empty body, or the
//     reads failed.
//   - failed: reported through Err.
func stopAndConfirm(ctx context.Context, d Deps, camera, profile string) stopReport {
	e, err := d.Reg.Get(camera)
	if err != nil {
		return stopReport{Status: stopFailed, Err: &mcperr.ToolError{
			Code: mcperr.CodeNotFound, Camera: redact.ScrubBounded(camera, maxEchoedCamera, "..."), Operation: "Stop", NotSent: true,
			Message: "no camera with that id is configured", Hint: "call camera.list to see the configured camera ids",
		}}
	}
	if profile == "" || len(profile) > maxProfileBytes {
		return stopReport{Status: stopFailed, Err: &mcperr.ToolError{
			Code: mcperr.CodeInvalidArgument, Camera: camera, Operation: "Stop", NotSent: true,
			Message: fmt.Sprintf("profile must be a token of 1 to %d bytes", maxProfileBytes),
			Hint:    "call media.profiles and pass the token of a profile whose has_ptz is true",
		}}
	}
	// The camera id is part of the key: two ids on one endpoint may hold different
	// credentials, and a round runs with its creator's registry entry.
	key := e.DeviceKey() + "\x00" + e.ID()

	r, err := gates.stop.do(ctx, key, profile, stopRoundFor(d, e))
	if err != nil {
		// The round may already have dispatched Stop (the caller's context ended
		// while it ran, or it panicked after sending), so never claim NotSent.
		msg := "the stop may not have been delivered: " + err.Error()
		return stopReport{Status: stopFailed, Sent: true, Err: &mcperr.ToolError{
			Code: mcperr.CodeInternal, Retryable: true, Camera: camera, Operation: "Stop",
			Message: msg, Hint: retryStopHint,
		}}
	}
	if r.te != nil {
		if r.validation {
			te := *r.te
			te.Camera = camera
			return stopReport{Status: stopFailed, Err: &te}
		}
		return stopReport{Status: stopFailed, Sent: r.sent, Err: deliveryFailure(r, camera)}
	}

	rep := stopReport{Status: stopSentUnconfirmed, Sent: true}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), confirmWindow)
	defer cancel()
	reason := ""
poll:
	for i := 0; i < confirmPolls; i++ {
		if i > 0 {
			select {
			case <-time.After(confirmDelay):
			case <-cctx.Done():
				reason = "the confirmation window ended"
				break poll
			}
		}
		sr, err := gates.status.do(cctx, key, profile, statusRoundFor(d, e))
		if err != nil || sr.te != nil {
			reason = "the camera's status could not be read afterwards"
			break
		}
		sd := statusOf(sr.st)
		rep.Final = &sd
		reported := 0
		allIdle := true
		for _, s := range []string{sd.PanTiltState, sd.ZoomState} {
			if s == "" {
				continue
			}
			reported++
			if !strings.EqualFold(s, "IDLE") {
				allIdle = false
			}
		}
		if reported == 0 {
			reason = "the camera reports no movement state"
			break
		}
		if allIdle {
			if r.unverified {
				reason = "the camera answered the stop with an empty reply"
				break
			}
			rep.Status = stopConfirmedIdle
			reason = ""
			break
		}
		reason = "the camera still reported MOVING or UNKNOWN"
	}
	if r.unverified && rep.Status == stopConfirmedIdle {
		rep.Status = stopSentUnconfirmed
	}
	switch rep.Status {
	case stopConfirmedIdle:
		rep.Note = "The stop was delivered and the camera reports it idle."
	default:
		if reason == "" {
			reason = "the camera did not confirm"
		}
		rep.Note = "The stop was delivered but not confirmed: " + reason +
			". Check ptz.status or camera.snapshot; call ptz.stop again if it still moves."
	}
	return rep
}
