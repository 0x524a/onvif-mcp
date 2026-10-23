package safety

import (
	"context"
	"math"
	"sync"
	"sync/atomic"

	"github.com/0x524a/onvif-mcp/internal/redact"
)

const (
	maxAuditCamera  = 64
	maxAuditOutcome = 120
	maxAuditTarget  = 64
	maxAuditMode    = 32
	// maxErrCamera bounds the camera id echoed back in a refusal.
	maxErrCamera = 256
)

// AuditOption adds optional detail to an audit record.
type AuditOption func(*auditExtra)

type auditExtra struct {
	target string
	motion *MotionAudit
}

// MotionAudit is the typed description of a motion command for the audit trail.
// Only these fields can reach the log through WithMotion: numbers the server
// validated and a short mode name, never an agent-supplied string. A nil axis
// was not sent and is not logged as zero.
type MotionAudit struct {
	Mode            string
	Pan, Tilt, Zoom *float64
}

// WithMotion records the validated motion of the call.
func WithMotion(m MotionAudit) AuditOption {
	return func(e *auditExtra) { e.motion = &m }
}

// WithTarget records the resolved target of the call (for example the preset
// or profile token a tool resolved), scrubbed and bounded. The tool decides
// what the target is; arguments are still never logged wholesale.
func WithTarget(target string) AuditOption {
	return func(e *auditExtra) { e.target = target }
}

// granted reports whether camera is configured and opted in to control.
func (p *Policy) granted(camera string) bool {
	if p == nil || p.Cameras == nil {
		return false
	}
	e, err := p.Cameras.Get(camera)
	return err == nil && e != nil && e.ControlAllowed()
}

// Audit records the outcome of a write attempt that the guard allowed. It goes
// to the Policy's logger, which must write to stderr: stdout carries JSON-RPC
// and must never be written to.
//
// It logs the tool, camera, dry_run, executed, an outcome, the control posture
// and whether the camera is granted control, plus an optional target
// (WithTarget), and nothing else. Tool arguments are never logged, since they
// could carry secrets into a log. outcome should be a short code such as "ok"
// or "preset_not_found"; it is scrubbed and bounded regardless.
//
// Calls the guard refused are audited by Evaluate itself (blocked: true with a
// reason code), so a tool does not call Audit for those.
func (p *Policy) Audit(tool, camera string, dryRun, executed bool, outcome string, opts ...AuditOption) {
	if p == nil || p.Log == nil {
		return
	}
	var x auditExtra
	for _, o := range opts {
		o(&x)
	}
	attrs := []any{
		"tool", clean(tool, maxAuditCamera),
		"camera", clean(camera, maxAuditCamera),
		"camera_granted", p.granted(camera),
		"control_enabled", p.ControlEnabled,
		"dry_run", dryRun,
		"executed", executed,
		"outcome", clean(outcome, maxAuditOutcome),
		"blocked", false,
	}
	if x.target != "" {
		attrs = append(attrs, "target", clean(x.target, maxAuditTarget))
	}
	if m := x.motion; m != nil {
		attrs = append(attrs, "motion_mode", clean(m.Mode, maxAuditMode))
		for _, a := range []struct {
			k string
			v *float64
		}{{"motion_pan", m.Pan}, {"motion_tilt", m.Tilt}, {"motion_zoom", m.Zoom}} {
			if a.v != nil && !math.IsNaN(*a.v) && !math.IsInf(*a.v, 0) {
				attrs = append(attrs, a.k, *a.v)
			}
		}
	}
	p.Log.Info("write attempt", attrs...)
}

// auditBlocked records a refusal. reason is one of the Reason constants.
func (p *Policy) auditBlocked(tool, camera string, dryRun bool, reason string) {
	if p == nil || p.Log == nil {
		return
	}
	p.Log.Warn("write attempt blocked",
		"tool", clean(tool, maxAuditCamera),
		"camera", clean(camera, maxAuditCamera),
		"camera_granted", p.granted(camera),
		"control_enabled", p.ControlEnabled,
		"dry_run", dryRun,
		"executed", false,
		"outcome", "blocked",
		"blocked", true,
		"reason", reason,
	)
}

// AuditRejected records a call to a gated write tool that was refused before
// the tool's handler ran, such as one the SDK rejected for failing schema
// validation. Neither the arguments nor the camera id are logged: the call
// never reached validation, so they are unvalidated agent input.
func (p *Policy) AuditRejected(tool string) {
	if p == nil || p.Log == nil {
		return
	}
	// With control off the tool was never registered, so the SDK answered
	// "unknown tool"; the arguments were never looked at.
	reason := ReasonInvalidArguments
	if !p.ControlEnabled {
		reason = ReasonControlDisabled
	}
	p.Log.Warn("write attempt blocked",
		"tool", clean(tool, maxAuditCamera),
		"control_enabled", p.ControlEnabled,
		"executed", false,
		"outcome", "blocked",
		"blocked", true,
		"reason", reason,
	)
}

type attemptKey struct{}

// Attempt tells middleware whether a request reached the tool handler.
type Attempt struct{ reached atomic.Bool }

// Reached reports whether NoteReached was called on the attempt's context.
func (a *Attempt) Reached() bool { return a.reached.Load() }

// TrackAttempt returns a context that a guarded handler marks with NoteReached,
// and the Attempt to read it from. Middleware uses it to tell a call the
// handler audited itself from one rejected before the handler ran.
func TrackAttempt(ctx context.Context) (context.Context, *Attempt) {
	a := &Attempt{}
	return context.WithValue(ctx, attemptKey{}, a), a
}

// NoteReached marks the context's Attempt, if any, as having reached a handler.
func NoteReached(ctx context.Context) {
	if a, ok := ctx.Value(attemptKey{}).(*Attempt); ok {
		a.reached.Store(true)
	}
}

// clean scrubs credentials from, and bounds, text that may be agent controlled,
// to at most limit bytes including a trailing ellipsis when anything was cut.
// The bound is applied before the scrub (redact.ScrubBounded), because Scrub
// costs seconds per megabyte and the camera id is unvalidated agent input. The
// log handler quotes or escapes control characters, so a newline cannot forge
// a second record.
func clean(s string, limit int) string {
	return redact.ScrubBounded(s, limit, "...")
}

type targetKey struct{}

// TargetSlot holds the resolved target, and the validated motion, a tool noted
// during one guarded call.
type TargetSlot struct {
	mu     sync.Mutex
	v      string
	motion *MotionAudit
}

// Motion returns the noted motion, or nil.
func (s *TargetSlot) Motion() *MotionAudit {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.motion == nil {
		return nil
	}
	m := *s.motion
	return &m
}

// Get returns the noted target, or "".
func (s *TargetSlot) Get() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.v
}

// WithTargetSlot returns a context a tool can report its target through
// (NoteTarget), and the slot the guard reads when it audits the call. The
// guarded handler uses it so that the target is audited even if the tool
// panics or fails.
func WithTargetSlot(ctx context.Context) (context.Context, *TargetSlot) {
	s := &TargetSlot{}
	return context.WithValue(ctx, targetKey{}, s), s
}

// NoteTarget records the target of the call (for example a preset token) for
// the audit record. The last value wins; it is scrubbed and bounded when
// logged (WithTarget). Without a slot in ctx it does nothing.
func NoteTarget(ctx context.Context, target string) {
	if s, ok := ctx.Value(targetKey{}).(*TargetSlot); ok {
		s.mu.Lock()
		s.v = target
		s.mu.Unlock()
	}
}

// NoteMotion records the validated motion of the call (typed numbers and a short
// mode name, never agent text) for the audit record. Without a slot in ctx it
// does nothing.
func NoteMotion(ctx context.Context, m MotionAudit) {
	if s, ok := ctx.Value(targetKey{}).(*TargetSlot); ok {
		s.mu.Lock()
		s.motion = &m
		s.mu.Unlock()
	}
}
