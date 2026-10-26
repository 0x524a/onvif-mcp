package safety

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/registry"
)

// Reason codes name why the guard refused a call. They appear in the audit
// trail; the agent-facing code is the ToolError's Code.
const (
	ReasonUnknownCamera    = "unknown_camera"
	ReasonControlDisabled  = "control_disabled"
	ReasonCameraNotGranted = "camera_not_granted"
	ReasonRateLimited      = "rate_limited"
	ReasonNoRateLimiter    = "no_rate_limiter"
	ReasonInvalidArguments = "invalid_arguments"
	// ReasonCallerUnidentified: the call carried no valid Caller. The guard
	// fails closed on it; no transport may reach a write or halt tool without
	// establishing one.
	ReasonCallerUnidentified = "caller_unidentified"
	// ReasonCallerNotGranted: a valid Caller without control (every remote
	// caller). The agent-facing text is identical to ReasonCallerUnidentified;
	// only the audit line tells them apart.
	ReasonCallerNotGranted = "caller_not_granted"
	// ReasonDeviceBusy: another real write holds the device lease.
	ReasonDeviceBusy = "device_busy"
	// ReasonNoLeases: the policy has no lease table, so it fails closed.
	ReasonNoLeases = "no_device_lease"
	// ReasonTimeoutNotAttested: the tool needs the camera's ptz_honours_timeout
	// attestation and the camera does not carry it.
	ReasonTimeoutNotAttested = "timeout_not_attested"
	// ReasonMotionBudget: the camera's seconds-of-motion budget is spent.
	ReasonMotionBudget = "motion_budget"
	// ReasonNoMotionBudget: the policy has no motion budget, so it fails closed.
	ReasonNoMotionBudget = "no_motion_budget"
)

// CameraLookup resolves a camera id to its registry entry. *registry.Registry
// implements it. The guard reads the per-camera control grant from the entry
// rather than trusting a caller-supplied flag.
type CameraLookup interface {
	Get(id string) (*registry.Entry, error)
}

// Policy holds the process-wide write posture. The zero value, and a nil
// *Policy, refuse everything: a half-built policy must never let a motor move.
// Build one with NewPolicy.
type Policy struct {
	// ControlEnabled mirrors --enable-control. It is the master switch: when
	// false, write tools are never registered and so never appear in
	// tools/list. An agent cannot call what it cannot see. Evaluate also
	// refuses every call when it is false, as defence in depth.
	ControlEnabled bool
	// Cameras is the set of configured cameras. Evaluate refuses an id not in
	// it before the limiter is touched, which is what bounds limiter memory.
	// Nil means no camera is known.
	Cameras CameraLookup
	// Limiter rate limits real (non-dry-run) moves per camera. Nil refuses all
	// real moves.
	Limiter *Limiter
	// Log receives the audit trail; it must write to stderr, never stdout,
	// which carries JSON-RPC. Nil refuses all real moves: no motion without a
	// record of it.
	Log *slog.Logger
	// Leases is the per-device busy gate every real write passes (see Leases).
	// Nil refuses all real moves.
	Leases *Leases
	// MotionBudget limits continuous motion per device, measured in seconds of
	// motion rather than in calls (ChargeMotion). Nil refuses all continuous
	// moves.
	MotionBudget *Limiter

	// WritesUnavailable, when non-empty, says this transport offers no write
	// tool at all (HTTP in v0.2.0). The policy resource then reports read-only,
	// an empty gated list and this text as how_to_enable, so it neither
	// advises --enable-control nor names tools the caller can never use.
	WritesUnavailable string

	// gated is the set of write tools the guarded registration helper has
	// been asked to register, whether or not control is enabled. The policy
	// resource reports it, so the list cannot drift from what exists.
	gatedMu sync.Mutex
	gated   map[string]struct{}
	halts   map[string]struct{}
	timed   map[string]struct{}
}

// NoteTimed records that a gated write tool moves for a duration and so also
// needs each camera's ptz_honours_timeout attestation (ptz.move_continuous). The
// policy resource names it in its explanation. Nil-safe.
func (p *Policy) NoteTimed(tool string) {
	if p == nil {
		return
	}
	p.gatedMu.Lock()
	defer p.gatedMu.Unlock()
	if p.timed == nil {
		p.timed = make(map[string]struct{})
	}
	p.timed[tool] = struct{}{}
}

// TimedTools returns the noted timed tools, sorted. It never returns nil.
func (p *Policy) TimedTools() []string {
	out := []string{}
	if p == nil {
		return out
	}
	p.gatedMu.Lock()
	defer p.gatedMu.Unlock()
	for t := range p.timed {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// NoteGated records that a write tool exists and is gated by this policy. The
// guarded registration helper calls it for every write tool, including the
// ones it then declines to register because control is off, which is what
// lets the policy resource name a tool an agent cannot see. Nil-safe.
func (p *Policy) NoteGated(tool string) {
	if p == nil {
		return
	}
	p.gatedMu.Lock()
	defer p.gatedMu.Unlock()
	if p.gated == nil {
		p.gated = make(map[string]struct{})
	}
	p.gated[tool] = struct{}{}
}

// NoteHalt records that a halt tool (RiskHalt) exists and is gated by this
// policy. It also counts as gated, so the policy resource and the audit
// middleware treat it like any gated tool. Nil-safe.
func (p *Policy) NoteHalt(tool string) {
	if p == nil {
		return
	}
	p.NoteGated(tool)
	p.gatedMu.Lock()
	defer p.gatedMu.Unlock()
	if p.halts == nil {
		p.halts = make(map[string]struct{})
	}
	p.halts[tool] = struct{}{}
}

// HaltTools returns the noted halt tools, sorted. It never returns nil.
func (p *Policy) HaltTools() []string {
	out := []string{}
	if p == nil {
		return out
	}
	p.gatedMu.Lock()
	defer p.gatedMu.Unlock()
	for t := range p.halts {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// GatedTools returns the noted write tools, sorted. It never returns nil.
func (p *Policy) GatedTools() []string {
	out := []string{}
	if p == nil {
		return out
	}
	p.gatedMu.Lock()
	defer p.gatedMu.Unlock()
	for t := range p.gated {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// PolicyOptions configures NewPolicy.
type PolicyOptions struct {
	ControlEnabled bool
	Cameras        CameraLookup
	// Interval and Burst configure the per-camera rate limit: one movement per
	// Interval, up to Burst at once. Zero values mean DefaultInterval (2s) and
	// DefaultBurst (1). v0.1 deliberately has no flag or config key for them:
	// main leaves them zero, so the defaults are what operators get.
	Interval time.Duration
	Burst    int
	// MotionBurstSeconds and MotionRefill configure the continuous-motion budget:
	// up to MotionBurstSeconds seconds of motion at once, one second regained per
	// MotionRefill. Zero values mean DefaultMotionBurstSeconds (5) and
	// DefaultMotionRefill (4s), about a 20 percent duty cycle. main leaves them
	// zero; there is no flag or config key.
	MotionBurstSeconds int
	MotionRefill       time.Duration
	// WritesUnavailable: see Policy.WritesUnavailable.
	WritesUnavailable string
	// Clock overrides the limiter's time source; nil means time.Now.
	Clock func() time.Time
	// Log is the audit logger. Nil leaves the policy unable to approve real
	// moves.
	Log *slog.Logger
}

// Continuous-motion budget defaults (PolicyOptions).
const (
	DefaultMotionBurstSeconds = 5
	DefaultMotionRefill       = 4 * time.Second
)

// NewPolicy builds a Policy with a rate limiter, a lease table and a motion
// budget from opts.
func NewPolicy(opts PolicyOptions) *Policy {
	burst, refill := opts.MotionBurstSeconds, opts.MotionRefill
	if burst < 1 {
		burst = DefaultMotionBurstSeconds
	}
	if refill <= 0 {
		refill = DefaultMotionRefill
	}
	return &Policy{
		ControlEnabled: opts.ControlEnabled,
		Cameras:        opts.Cameras,
		Limiter:        NewLimiter(opts.Interval, opts.Burst, WithClock(opts.Clock)),
		Log:            opts.Log,
		Leases:         NewLeases(opts.Clock),
		MotionBudget:   NewLimiter(refill, burst, WithClock(opts.Clock)),

		WritesUnavailable: opts.WritesUnavailable,
	}
}

// Decision is the guard's verdict for one call.
type Decision struct {
	// DryRun is true when the call must simulate rather than execute.
	DryRun bool
	// Blocked is non-nil when the call must not proceed at all. For an
	// unknown camera it carries not_found; every other refusal is
	// blocked_by_policy.
	Blocked *mcperr.ToolError
	// Refund, non-nil only for an allowed real call, returns the rate budget
	// that call took. The caller invokes it when the call ended before
	// anything was sent to the camera (a mistyped token must not cost the
	// agent the lockout). Calling it more than once is the caller's bug.
	Refund func()
	// Lease, non-nil only for an allowed real write, holds the device until the
	// caller releases it. The caller must defer Lease.Release() (nil-safe) as
	// soon as Evaluate returns.
	Lease *Lease
}

// EvalOption adds a gate to Evaluate for one tool.
type EvalOption func(*evalOpts)

type evalOpts struct{ requireAttestation bool }

// RequireTimeoutAttestation makes Evaluate refuse, for dry runs and real calls
// alike, a camera without the operator's ptz_honours_timeout attestation
// (registry.Entry.HonoursTimeout), and marks a real call's lease as a timed
// motion that ptz.stop can interrupt (Leases). ptz.move_continuous passes it.
func RequireTimeoutAttestation() EvalOption {
	return func(o *evalOpts) { o.requireAttestation = true }
}

// WriteRegistered reports whether write tools should be registered at all.
func (p *Policy) WriteRegistered() bool { return p != nil && p.ControlEnabled }

// Evaluate applies the gates in order:
//
//  1. the call carries a valid Caller with control (safety.CallerFrom); none, or
//     one without control, is refused before the camera id is even looked up,
//     so a caller without control gets one answer whatever camera it names
//  2. the camera is configured (an unknown id never reaches anything else)
//  3. control is enabled for the process
//  4. control is granted to this camera
//  5. with RequireTimeoutAttestation, the camera carries ptz_honours_timeout
//  6. a dry run stops here: it moves nothing, so it consumes no rate budget
//  7. the audit log exists
//  8. the rate limiter and the lease table exist
//  9. the device lease is free and is taken (TryAcquire, atomic): a device
//     busy with another real write is refused with no rate token spent
//  10. the camera's device has rate budget (the budget is per device, keyed by
//     the normalised endpoint, so two ids for one device share it, as they
//     share the lease); a refusal here releases the lease again
//
// There is no permissive default: a context without a Caller is refused.
// Stdio supplies safety.StdioOperator() explicitly; a network transport can
// only build a Caller without control (safety.RemoteCaller).
//
// The process-level registration gate is applied earlier, at registration.
// Every refusal is audited here, so no tool can forget to record one. Allowed
// calls are audited by the tool through Audit once their outcome is known.
//
// camera is agent input. Only ids of configured cameras ever reach the
// limiter, so its memory is bounded by the config, not by the agent.
func (p *Policy) Evaluate(ctx context.Context, camera, tool string, dryRun bool, opts ...EvalOption) Decision {
	var o evalOpts
	for _, f := range opts {
		f(&o)
	}
	if p == nil {
		return Decision{DryRun: dryRun, Blocked: blocked(clean(camera, maxErrCamera), tool,
			"write policy is not configured", nil)}
	}
	refuse := func(te *mcperr.ToolError, reason string) Decision {
		p.auditBlocked(tool, camera, dryRun, reason)
		return Decision{DryRun: dryRun, Blocked: te}
	}
	if te, reason, who := callerGate(ctx, camera, tool); te != nil {
		p.auditBlocked(tool, camera, dryRun, reason, "caller", who)
		return Decision{DryRun: dryRun, Blocked: te}
	}

	var entry *registry.Entry
	if p.Cameras != nil {
		if e, err := p.Cameras.Get(camera); err == nil && e != nil {
			entry = e
		}
	}
	if entry == nil {
		return refuse(&mcperr.ToolError{
			Code:      mcperr.CodeNotFound,
			Camera:    clean(camera, maxErrCamera),
			Operation: tool,
			Message:   "no camera with that id is configured",
			Hint:      "call camera.list to see the configured camera ids",
		}, ReasonUnknownCamera)
	}

	if !p.ControlEnabled {
		return refuse(blocked(camera, tool,
			"control is disabled for this server", nil,
			"an operator must restart the server with --enable-control; an agent cannot change this"),
			ReasonControlDisabled)
	}
	if !entry.ControlAllowed() {
		return refuse(blocked(camera, tool,
			"this camera has not opted in to control", nil,
			"an operator must set \"control\": true on this camera's config entry; do not retry"),
			ReasonCameraNotGranted)
	}
	if o.requireAttestation && !entry.HonoursTimeout() {
		return refuse(blocked(camera, tool,
			"this camera is not attested to end a continuous move by itself when its ONVIF Timeout runs out, so continuous movement is refused", nil,
			"an operator must prove it with the hardware test and set \"ptz_honours_timeout\": true on this camera's config entry; do not retry; use ptz.move_relative instead"),
			ReasonTimeoutNotAttested)
	}

	if dryRun {
		return Decision{DryRun: true}
	}

	if p.Log == nil {
		// Nothing can be logged without a logger, so this refusal is the one
		// that is not audited.
		return Decision{Blocked: blocked(camera, tool,
			"the audit trail is unavailable, so movement is refused", nil, misconfiguredHint)}
	}
	if p.Limiter == nil {
		return refuse(blocked(camera, tool,
			"no rate limiter is configured, so movement is refused", nil, misconfiguredHint), ReasonNoRateLimiter)
	}
	if p.Leases == nil {
		return refuse(blocked(camera, tool,
			"no device lease table is configured, so movement is refused", nil, misconfiguredHint), ReasonNoLeases)
	}
	key := entry.DeviceKey()
	lease, busyFor := p.Leases.TryAcquire(key)
	if lease == nil {
		secs := int(math.Ceil(busyFor.Seconds()))
		return refuse(blocked(camera, tool,
			"the camera is busy with another movement command", &secs,
			"wait retry_after_seconds, then repeat the call; ptz.stop ends a continuous move early"), ReasonDeviceBusy)
	}
	ok, after, grant := p.Limiter.AllowGrant(key)
	if !ok {
		lease.Release()
		// Allow never reports a refusal with a wait under 1ns, so rounding up
		// always yields at least one second.
		secs := int(math.Ceil(after.Seconds()))
		return refuse(blocked(camera, tool,
			"movement is rate limited to protect the camera's mechanism", &secs,
			"wait retry_after_seconds, then repeat the call"), ReasonRateLimited)
	}
	if o.requireAttestation {
		// Only timed motions need the attestation; their lease can be
		// interrupted by ptz.stop from the start, before the move is sent.
		lease.markTimed()
	}
	return Decision{Refund: func() { p.Limiter.RefundGrant(key, grant) }, Lease: lease}
}

// ChargeMotion draws seconds of motion from the camera's device budget
// (MotionBudget), all of it up front: a continuous move calls it after
// validation and immediately before the command is sent, so neither a panic, a
// cancel nor a kill can dodge the charge, and it is never refunded, not even
// when the move ends early. It returns nil when charged. A refusal is a
// blocked_by_policy error marked NotSent with retry_after_seconds, and is
// audited. A nil Policy, an unknown camera or a nil budget refuse (fail
// closed); so does a full key table (Limiter.TakeCost).
func (p *Policy) ChargeMotion(camera, tool string, seconds float64) *mcperr.ToolError {
	if p == nil {
		te := blocked(clean(camera, maxErrCamera), tool, "write policy is not configured", nil)
		te.NotSent = true
		return te
	}
	entry := p.entry(camera)
	if entry == nil {
		return &mcperr.ToolError{
			Code: mcperr.CodeNotFound, Camera: clean(camera, maxErrCamera), Operation: tool, NotSent: true,
			Message: "no camera with that id is configured", Hint: "call camera.list to see the configured camera ids",
		}
	}
	if p.MotionBudget == nil {
		p.auditBlocked(tool, camera, false, ReasonNoMotionBudget)
		te := blocked(camera, tool, "no motion budget is configured, so continuous movement is refused", nil, misconfiguredHint)
		te.NotSent = true
		return te
	}
	ok, wait := p.MotionBudget.TakeCost(entry.DeviceKey(), seconds)
	if ok {
		return nil
	}
	p.auditBlocked(tool, camera, false, ReasonMotionBudget)
	secs := int(math.Ceil(wait.Seconds()))
	te := blocked(camera, tool,
		fmt.Sprintf("continuous movement on this camera is limited to %d seconds of motion, regained at one second per %s, and the requested duration does not fit now",
			p.MotionBudget.Burst(), p.MotionBudget.Interval()), &secs,
		"wait retry_after_seconds, or ask for a shorter duration_seconds; nothing was sent")
	te.NotSent = true
	return te
}

// InterruptMotion wakes the timed motion (a continuous move) holding the
// camera's device, if any, and reports whether there was one. The move then
// sends its own stop. It never blocks: it can only shorten motion, so the
// caller's gate (EvaluateHalt) is all it needs. Nil-safe; an unknown camera
// interrupts nothing.
func (p *Policy) InterruptMotion(camera string) bool {
	entry := p.entry(camera)
	if entry == nil {
		return false
	}
	return p.Leases.Interrupt(entry.DeviceKey())
}

// entry resolves a configured camera, or nil. Nil-safe.
func (p *Policy) entry(camera string) *registry.Entry {
	if p == nil || p.Cameras == nil {
		return nil
	}
	if e, err := p.Cameras.Get(camera); err == nil && e != nil {
		return e
	}
	return nil
}

// EvaluateHalt is Evaluate for a RiskHalt tool. It applies only the gates that
// still make sense for a stop: the caller has control (same gate, same first
// position and same answer as Evaluate), the camera is configured, control is
// enabled and the camera is granted (the server can only have moved a granted camera). It
// never consults the limiter, never requires the audit log and has no dry run,
// so no budget, missing logger or full key table can stand between an agent and
// a stop. Refusals are audited, like Evaluate's. A nil Policy refuses.
func (p *Policy) EvaluateHalt(ctx context.Context, camera, tool string) Decision {
	if p == nil {
		return Decision{Blocked: blocked(clean(camera, maxErrCamera), tool, "write policy is not configured", nil)}
	}
	refuse := func(te *mcperr.ToolError, reason string) Decision {
		p.auditBlocked(tool, camera, false, reason)
		return Decision{Blocked: te}
	}
	if te, reason, who := callerGate(ctx, camera, tool); te != nil {
		p.auditBlocked(tool, camera, false, reason, "caller", who)
		return Decision{Blocked: te}
	}
	var entry *registry.Entry
	if p.Cameras != nil {
		if e, err := p.Cameras.Get(camera); err == nil && e != nil {
			entry = e
		}
	}
	if entry == nil {
		return refuse(&mcperr.ToolError{
			Code:      mcperr.CodeNotFound,
			Camera:    clean(camera, maxErrCamera),
			Operation: tool,
			Message:   "no camera with that id is configured",
			Hint:      "call camera.list to see the configured camera ids",
		}, ReasonUnknownCamera)
	}
	if !p.ControlEnabled {
		return refuse(blocked(camera, tool,
			"control is disabled for this server", nil,
			"an operator must restart the server with --enable-control; an agent cannot change this"),
			ReasonControlDisabled)
	}
	if !entry.ControlAllowed() {
		return refuse(blocked(camera, tool,
			"this camera has not opted in to control", nil,
			"an operator must set \"control\": true on this camera's config entry; do not retry"),
			ReasonCameraNotGranted)
	}
	return Decision{}
}

// callerGate is gate 1 of Evaluate and EvaluateHalt. It returns a refusal, the
// audit reason and the caller id for the audit line ("-" when there is none).
// The agent-facing text does not depend on the camera or on which of the two
// reasons applied, so it is not an oracle for camera ids, grants or caller state.
func callerGate(ctx context.Context, camera, tool string) (*mcperr.ToolError, string, string) {
	c, ok := CallerFrom(ctx)
	if ok && c.Control() {
		return nil, "", ""
	}
	reason, who := ReasonCallerUnidentified, "-"
	if ok {
		reason, who = ReasonCallerNotGranted, c.ID()
	}
	return blocked(clean(camera, maxErrCamera), tool,
		"state-changing tools are not available to this caller", nil,
		"this caller cannot use write tools on this server; do not retry"), reason, who
}

// misconfiguredHint is for the fail-closed refusals that only a broken server
// setup can reach.
const misconfiguredHint = "this is a server misconfiguration; an operator must fix it, do not retry"

func blocked(camera, tool, msg string, retryAfter *int, hint ...string) *mcperr.ToolError {
	te := mcperr.Blocked(camera, tool, msg, retryAfter)
	if len(hint) > 0 {
		te.Hint = hint[0]
	}
	return te
}
