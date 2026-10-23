// Package safety implements onvif-mcp's read-only-by-default posture: risk
// classes, dry-run-by-default write input, a per-camera rate limiter, the
// policy that gates every write call, and the audit trail.
//
// SDK type used (github.com/modelcontextprotocol/go-sdk v1.7.0):
//   - mcp.ToolAnnotations   mcp/protocol.go: the behaviour hints on a tool
package safety

import "github.com/modelcontextprotocol/go-sdk/mcp"

// RiskClass declares whether a tool can change device state. Registration
// requires one, so a new write tool cannot be added without saying so.
type RiskClass int

const (
	// RiskRead cannot change device state.
	RiskRead RiskClass = iota
	// RiskWrite physically changes a camera.
	RiskWrite
	// RiskHalt stops motion. It is gated like a write (registered only with
	// control on, camera must exist and be granted) but is never a dry run, never
	// rate limited and never blocked by a missing audit log: the one call that
	// must always get through.
	RiskHalt
)

// String names the class for logs and the policy resource.
func (r RiskClass) String() string {
	switch r {
	case RiskRead:
		return "read"
	case RiskWrite:
		return "write"
	case RiskHalt:
		return "halt"
	default:
		return "unknown"
	}
}

// WriteInput is implemented by every state-changing tool's input struct.
type WriteInput interface {
	CameraID() string
	IsDryRun() bool
}

// HaltInput is implemented by a RiskHalt tool's input struct. It deliberately
// has no IsDryRun: a halt tool whose input also implements WriteInput is
// refused at registration.
type HaltInput interface {
	CameraID() string
}

// WriteBase carries the fields every write tool needs. Embed it.
//
// DryRun is a pointer so that its absence is distinguishable from false: an
// omitted dry_run means true. An agent must therefore opt in explicitly to
// moving a camera, and forgetting to do so produces a no-op rather than motion.
type WriteBase struct {
	Camera string `json:"camera" jsonschema:"the camera id from camera.list"`
	DryRun *bool  `json:"dry_run,omitempty" jsonschema:"defaults to true; pass false to actually move the camera"`
}

// CameraID returns the target camera.
func (w WriteBase) CameraID() string { return w.Camera }

// IsDryRun reports whether this call should simulate rather than execute.
func (w WriteBase) IsDryRun() bool { return w.DryRun == nil || *w.DryRun }

func boolPtr(b bool) *bool { return &b }

// WriteAnnotations builds annotations for a state-changing tool. All four hints
// are explicit.
func WriteAnnotations(title string) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{
		Title:           title,
		ReadOnlyHint:    false,
		DestructiveHint: boolPtr(true),
		// Moving to the same preset twice leaves the camera in the same place,
		// so the end state is idempotent even though motion recurs.
		IdempotentHint: true,
		OpenWorldHint:  boolPtr(false),
	}
}

// WriteAnnotationsNonIdempotent is WriteAnnotations with idempotentHint false,
// for a write that compounds when repeated (a relative move). It is the only
// permitted deviation from WriteAnnotations.
func WriteAnnotationsNonIdempotent(title string) *mcp.ToolAnnotations {
	a := WriteAnnotations(title)
	a.IdempotentHint = false
	return a
}

// HaltAnnotations builds annotations for a tool that stops motion: not
// read-only (it sends a command), not destructive (it only ever reduces what
// the camera is doing), idempotent, closed world.
func HaltAnnotations(title string) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{
		Title:           title,
		ReadOnlyHint:    false,
		DestructiveHint: boolPtr(false),
		IdempotentHint:  true,
		OpenWorldHint:   boolPtr(false),
	}
}
