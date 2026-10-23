package safety

import (
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

	// gated is the set of write tools the guarded registration helper has
	// been asked to register, whether or not control is enabled. The policy
	// resource reports it, so the list cannot drift from what exists.
	gatedMu sync.Mutex
	gated   map[string]struct{}
	halts   map[string]struct{}
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
	// Clock overrides the limiter's time source; nil means time.Now.
	Clock func() time.Time
	// Log is the audit logger. Nil leaves the policy unable to approve real
	// moves.
	Log *slog.Logger
}

// NewPolicy builds a Policy with a rate limiter from opts.
func NewPolicy(opts PolicyOptions) *Policy {
	return &Policy{
		ControlEnabled: opts.ControlEnabled,
		Cameras:        opts.Cameras,
		Limiter:        NewLimiter(opts.Interval, opts.Burst, WithClock(opts.Clock)),
		Log:            opts.Log,
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
}

// WriteRegistered reports whether write tools should be registered at all.
func (p *Policy) WriteRegistered() bool { return p != nil && p.ControlEnabled }

// Evaluate applies the gates in order:
//
//  1. the camera is configured (an unknown id never reaches anything else)
//  2. control is enabled for the process and granted to this camera
//  3. a dry run stops here: it moves nothing, so it consumes no rate budget
//  4. the audit log and rate limiter exist, and the camera's device has budget
//     (the budget is per device, keyed by the normalised endpoint, so two ids
//     for one device share it)
//
// The process-level registration gate is applied earlier, at registration.
// Every refusal is audited here, so no tool can forget to record one. Allowed
// calls are audited by the tool through Audit once their outcome is known.
//
// camera is agent input. Only ids of configured cameras ever reach the
// limiter, so its memory is bounded by the config, not by the agent.
func (p *Policy) Evaluate(camera, tool string, dryRun bool) Decision {
	if p == nil {
		return Decision{DryRun: dryRun, Blocked: blocked(clean(camera, maxErrCamera), tool,
			"write policy is not configured", nil)}
	}
	refuse := func(te *mcperr.ToolError, reason string) Decision {
		p.auditBlocked(tool, camera, dryRun, reason)
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
	key := entry.DeviceKey()
	ok, after, grant := p.Limiter.AllowGrant(key)
	if !ok {
		// Allow never reports a refusal with a wait under 1ns, so rounding up
		// always yields at least one second.
		secs := int(math.Ceil(after.Seconds()))
		return refuse(blocked(camera, tool,
			"movement is rate limited to protect the camera's mechanism", &secs,
			"wait retry_after_seconds, then repeat the call"), ReasonRateLimited)
	}
	return Decision{Refund: func() { p.Limiter.RefundGrant(key, grant) }}
}

// EvaluateHalt is Evaluate for a RiskHalt tool. It applies only the gates that
// still make sense for a stop: the camera is configured, control is enabled and
// the camera is granted (the server can only have moved a granted camera). It
// never consults the limiter, never requires the audit log and has no dry run,
// so no budget, missing logger or full key table can stand between an agent and
// a stop. Refusals are audited, like Evaluate's. A nil Policy refuses.
func (p *Policy) EvaluateHalt(camera, tool string) Decision {
	if p == nil {
		return Decision{Blocked: blocked(clean(camera, maxErrCamera), tool, "write policy is not configured", nil)}
	}
	refuse := func(te *mcperr.ToolError, reason string) Decision {
		p.auditBlocked(tool, camera, false, reason)
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
