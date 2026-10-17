package safety

import (
	"github.com/0x524a/onvif-mcp/internal/redact"
)

const (
	maxAuditCamera  = 64
	maxAuditOutcome = 120
	// maxErrCamera bounds the camera id echoed back in a refusal.
	maxErrCamera = 256
)

// Audit records the outcome of a write attempt that the guard allowed. It goes
// to the Policy's logger, which must write to stderr: stdout carries JSON-RPC
// and must never be written to.
//
// It logs the tool, camera, dry_run, executed, an outcome and the control
// posture, and nothing else. Tool arguments are never logged, since they could
// carry secrets into a log. outcome should be a short code such as "ok" or
// "preset_not_found"; it is scrubbed and bounded regardless.
//
// Calls the guard refused are audited by Evaluate itself (blocked: true with a
// reason code), so a tool does not call Audit for those.
func (p *Policy) Audit(tool, camera string, dryRun, executed bool, outcome string) {
	if p == nil || p.Log == nil {
		return
	}
	p.Log.Info("write attempt",
		"tool", clean(tool, maxAuditCamera),
		"camera", clean(camera, maxAuditCamera),
		"control_enabled", p.ControlEnabled,
		"dry_run", dryRun,
		"executed", executed,
		"outcome", clean(outcome, maxAuditOutcome),
		"blocked", false,
	)
}

// auditBlocked records a refusal. reason is one of the Reason constants.
func (p *Policy) auditBlocked(tool, camera string, dryRun bool, reason string) {
	if p == nil || p.Log == nil {
		return
	}
	p.Log.Warn("write attempt blocked",
		"tool", clean(tool, maxAuditCamera),
		"camera", clean(camera, maxAuditCamera),
		"control_enabled", p.ControlEnabled,
		"dry_run", dryRun,
		"executed", false,
		"outcome", "blocked",
		"blocked", true,
		"reason", reason,
	)
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
