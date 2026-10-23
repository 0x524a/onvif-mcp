package tools

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"time"
	"weak"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/redact"
	"github.com/0x524a/onvif-mcp/internal/safety"
)

// GuardedTool is the registration path for any tool that must declare whether
// it can change a camera. It requires a safety.RiskClass, so a write tool
// cannot be added without saying so, and it registers only through add, so
// every result still passes the sanitising choke point and the SDK's generic
// registration (input validation, tool-error semantics) is never bypassed.
//
// RiskRead: run is registered as is. The annotations are replaced with
// ReadOnly, keeping only the caller's title, so a caller cannot understate or
// overstate the hints. dryRun must be nil.
//
// RiskWrite:
//   - In must implement safety.WriteInput (embed safety.WriteBase). This is
//     checked on every start, even when control is off and the tool would be
//     skipped, so a mistake cannot hide until an operator enables control.
//   - The annotations are replaced with safety.WriteAnnotations.
//   - The tool is recorded on the Policy as gated (so the policy resource
//     can name it), and then registered only if Policy.WriteRegistered().
//     With control off an agent never sees it in tools/list.
//   - The registered handler runs the guard before anything else:
//     Policy.Evaluate resolves the camera (an unknown id is not_found and
//     never reaches the rate limiter), checks the process and per-camera
//     grants, and rate limits real calls. A refusal is returned as the
//     error envelope and neither function runs.
//   - A dry run (dry_run omitted or true) calls dryRun, never run. The
//     executing function is structurally unreachable on that path.
//   - The attempt is audited from a deferred call, so a panic in either
//     function cannot skip the audit. The panic is then converted to an
//     internal tool error rather than propagated: a misbehaving write tool
//     must not take the whole server, and every other camera, down with it.
//
// RiskHalt (see safety.RiskHalt; ptz.stop):
//   - In must implement safety.HaltInput and must NOT implement
//     safety.WriteInput: a halt has no dry run, so a dry_run field must not exist.
//   - The annotations are replaced with safety.HaltAnnotations.
//   - It is registered under the same gate as a write tool (control on) and is
//     named by the policy resource whether or not it is registered.
//   - The handler (haltHandler) runs Policy.EvaluateHalt, which applies only the
//     camera and grant checks: no dry run, no rate limit, no audit-log
//     requirement. It runs on a context detached from the request and from
//     Deps.Base, so a cancel or a shutdown cannot abort a stop that has been
//     dispatched. The audit is attempted and its failure never blocks the stop.
//
// NonIdempotent is accepted for RiskWrite only.
//
// Misuse panics at registration instead of returning an error. It is a
// programming error in a fixed set of calls made while the server starts, so
// it fails on every run, including the test run, and cannot be ignored the way
// a returned error can.
func GuardedTool[In, Data any](
	srv *mcp.Server, d Deps, risk safety.RiskClass, t *mcp.Tool,
	run, dryRun mcp.ToolHandlerFor[In, mcperr.Out[Data]],
	opts ...GuardedOption,
) {
	if t == nil || run == nil {
		panic("tools.GuardedTool: tool and handler are required")
	}
	var o guardedOpts
	for _, f := range opts {
		f(&o)
	}
	if o.nonIdempotent && risk != safety.RiskWrite {
		panic("tools.GuardedTool: " + t.Name + ": NonIdempotent applies to RiskWrite tools only")
	}
	tc := *t
	title := ""
	if t.Annotations != nil {
		title = t.Annotations.Title
	}

	switch risk {
	case safety.RiskRead:
		if dryRun != nil {
			panic("tools.GuardedTool: " + t.Name + ": a read tool has no dry-run function")
		}
		var zero In
		if _, ok := any(zero).(safety.WriteInput); ok {
			panic("tools.GuardedTool: " + t.Name + ": an input embedding safety.WriteBase must be registered as RiskWrite")
		}
		claimName(srv, t.Name)
		tc.Annotations = ReadOnly(title)
		if t.Annotations != nil && t.Annotations.OpenWorldHint != nil {
			// The one hint a read tool may choose: discovery reaches
			// whatever answers on the network.
			tc.Annotations.OpenWorldHint = boolPtr(*t.Annotations.OpenWorldHint)
		}
		add(srv, &tc, run)

	case safety.RiskWrite:
		var zero In
		if _, ok := any(zero).(safety.WriteInput); !ok {
			panic("tools.GuardedTool: " + t.Name + ": a write tool's input must implement safety.WriteInput (embed safety.WriteBase)")
		}
		if dryRun == nil {
			panic("tools.GuardedTool: " + t.Name + ": a write tool requires a separate dry-run function")
		}
		tc.Annotations = safety.WriteAnnotations(title)
		if o.nonIdempotent {
			tc.Annotations = safety.WriteAnnotationsNonIdempotent(title)
		}
		claimName(srv, t.Name)
		d.Policy.NoteGated(t.Name)
		if !d.Policy.WriteRegistered() {
			return
		}
		add(srv, &tc, guardedHandler(d, t.Name, run, dryRun))

	case safety.RiskHalt:
		var zero In
		if _, ok := any(zero).(safety.WriteInput); ok {
			panic("tools.GuardedTool: " + t.Name + ": a halt tool has no dry run, so its input must not implement safety.WriteInput (do not embed safety.WriteBase)")
		}
		if _, ok := any(zero).(safety.HaltInput); !ok {
			panic("tools.GuardedTool: " + t.Name + ": a halt tool's input must implement safety.HaltInput")
		}
		if dryRun != nil {
			panic("tools.GuardedTool: " + t.Name + ": a halt tool has no dry-run function")
		}
		tc.Annotations = safety.HaltAnnotations(title)
		claimName(srv, t.Name)
		d.Policy.NoteHalt(t.Name)
		if !d.Policy.WriteRegistered() {
			return
		}
		add(srv, &tc, haltHandler(d, t.Name, run))

	default:
		panic("tools.GuardedTool: " + t.Name + ": unknown risk class")
	}
}

// GuardedOption adjusts how GuardedTool registers a tool.
type GuardedOption func(*guardedOpts)

type guardedOpts struct{ nonIdempotent bool }

// NonIdempotent marks a RiskWrite tool whose repeated calls compound (a
// relative move): idempotentHint is false instead of the WriteAnnotations
// default. It is the single permitted deviation from WriteAnnotations.
func NonIdempotent() GuardedOption { return func(o *guardedOpts) { o.nonIdempotent = true } }

// maxEchoedCamera bounds the camera id echoed back in an error.
const maxEchoedCamera = 256

// readTool registers a read-only tool through GuardedTool.
func readTool[In, Data any](srv *mcp.Server, d Deps, t *mcp.Tool, h mcp.ToolHandlerFor[In, mcperr.Out[Data]]) {
	GuardedTool(srv, d, safety.RiskRead, t, h, nil)
}

var (
	namesMu sync.Mutex
	names   = map[weak.Pointer[mcp.Server]]map[string]struct{}{}
)

// claimName records that srv has a tool called name, and panics if it already
// did: the SDK keeps tools in a map, so a second registration would silently
// replace a guarded handler with whatever came later. A write tool that is
// skipped because control is off still claims its name.
func claimName(srv *mcp.Server, name string) {
	key := weak.Make(srv)
	namesMu.Lock()
	defer namesMu.Unlock()
	set, ok := names[key]
	if !ok {
		set = map[string]struct{}{}
		names[key] = set
		runtime.AddCleanup(srv, func(k weak.Pointer[mcp.Server]) {
			namesMu.Lock()
			delete(names, k)
			namesMu.Unlock()
		}, key)
	}
	if _, dup := set[name]; dup {
		panic("tools.GuardedTool: " + name + ": a tool with this name is already registered")
	}
	set[name] = struct{}{}
}

// sentUnknownHint is appended to a device fault that follows a real write: the
// command left the server, so "it failed" does not mean "nothing changed".
const sentUnknownHint = "The command was sent to the camera before this failed, so it may or may not have been executed and the camera's state is unknown; check it with a read tool (for PTZ, ptz.status) before repeating the call."

// unknownStateAfterSend reports whether a failure of this class after a real
// write leaves the outcome unknown. Every class does except a policy refusal,
// which is produced before anything can be sent: a SOAP fault, a timeout, a
// transport error, and equally a malformed or empty reply or a camera that
// answers 500 with a web page can each arrive after the camera acted. The
// camera's reply is not evidence, so the class is not trusted either way.
func unknownStateAfterSend(c mcperr.Code) bool {
	return c != mcperr.CodeBlockedByPolicy
}

// cancelled audits and reports a call that was stopped before it started.
func cancelled[Data any](d Deps, tool, camera, shown string, dry bool) (*mcp.CallToolResult, mcperr.Out[Data], error) {
	d.Policy.Audit(tool, camera, dry, false, "cancelled")
	return fail[Data](&mcperr.ToolError{
		Code: mcperr.CodeInternal, Camera: shown, Operation: tool,
		Message: "the call was cancelled before it started, so nothing was sent to the camera",
		Hint:    "the server may be shutting down or the request was cancelled; check the camera with a read tool before repeating the call",
	})
}

// guardedHandler wraps run and dryRun in the guard. See GuardedTool.
func guardedHandler[In, Data any](
	d Deps, tool string, run, dryRun mcp.ToolHandlerFor[In, mcperr.Out[Data]],
) mcp.ToolHandlerFor[In, mcperr.Out[Data]] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in In) (
		res *mcp.CallToolResult, out mcperr.Out[Data], err error,
	) {
		safety.NoteReached(ctx)
		wi, ok := any(in).(safety.WriteInput)
		if !ok {
			// Unreachable after the registration check; fail closed anyway.
			return fail[Data](&mcperr.ToolError{
				Code: mcperr.CodeInternal, Operation: tool,
				Message: "the tool input carries no camera id, so the call was refused",
			})
		}
		camera, dry := wi.CameraID(), wi.IsDryRun()
		// camera is agent input of any size. Everything below that echoes it
		// uses the bounded, scrubbed form so no path scrubs a huge string.
		shown := redact.ScrubBounded(camera, maxEchoedCamera, "...")

		ctx, cancel := d.Scope(ctx)
		defer cancel()
		if err := ctx.Err(); err != nil {
			return cancelled[Data](d, tool, camera, shown, dry)
		}

		dec := d.Policy.Evaluate(camera, tool, dry)
		if dec.Blocked != nil {
			return fail[Data](dec.Blocked)
		}
		// Evaluate may have spent rate budget; do not start the write if the
		// call was cancelled or the server began shutting down meanwhile.
		refund := func() {
			if dec.Refund != nil {
				dec.Refund()
			}
		}
		if err := ctx.Err(); err != nil {
			refund() // nothing was sent, so the budget is returned
			return cancelled[Data](d, tool, camera, shown, dry)
		}

		ctx, target := safety.WithTargetSlot(ctx)
		executed, outcome := false, "panic"
		defer func() {
			if r := recover(); r != nil {
				// The panic value is deliberately neither logged nor returned:
				// it can carry anything the handler held, including secrets.
				outcome = "panic"
				res, out, err = fail[Data](&mcperr.ToolError{
					Code: mcperr.CodeInternal, Camera: shown, Operation: tool,
					Message: "the tool failed unexpectedly",
					Hint:    "do not retry in a loop; the camera state is unknown, so check it with a read tool and report this to the operator",
				})
			}
			auditOpts := []safety.AuditOption{safety.WithTarget(target.Get())}
			if m := target.Motion(); m != nil {
				auditOpts = append(auditOpts, safety.WithMotion(*m))
			}
			d.Policy.Audit(tool, camera, dry, executed, outcome, auditOpts...)
		}()

		if dry {
			res, out, err = dryRun(ctx, req, in)
		} else {
			executed = true
			res, out, err = run(ctx, req, in)
		}
		if out.Error != nil && out.Error.NotSent {
			// The tool says it failed before anything left the server: the audit
			// must not claim a command was executed. A panic keeps executed true.
			executed = false
			// Nothing was sent, so the call must not cost the camera's budget.
			refund()
		}
		switch {
		case err != nil:
			outcome = "error"
		case out.Error != nil:
			outcome = string(out.Error.Code)
		case dry:
			outcome = "dry_run"
		default:
			outcome = "ok"
		}
		if err != nil {
			return res, out, err
		}
		// Sanitise here, before the deferred audit, so the audited outcome is
		// the one the client is told. (add sanitises again, harmlessly.)
		if finishOut(&out) {
			outcome = string(mcperr.CodeDeviceFault)
			res, out, err = fail[Data](nonFiniteError())
		}
		finishText(res)
		if te := out.Error; executed && te != nil && !te.NotSent && unknownStateAfterSend(te.Code) {
			// The outcome is unknown, so repeating the identical call blindly
			// is not safe whatever the code's usual retry class is.
			te.Retryable = false
			if !strings.Contains(te.Hint, sentUnknownHint) {
				te.Hint = strings.TrimSpace(te.Hint + " " + sentUnknownHint)
			}
			res, out, err = fail[Data](te)
		}
		return res, out, err
	}
}

// haltBudget is the generic ceiling on one halt call. The tool applies its own,
// tighter deadlines (the camera's timeout); this only guarantees that a detached
// context can never run unbounded.
const haltBudget = 30 * time.Second

// haltHandler wraps run in the RiskHalt guard. See GuardedTool.
func haltHandler[In, Data any](
	d Deps, tool string, run mcp.ToolHandlerFor[In, mcperr.Out[Data]],
) mcp.ToolHandlerFor[In, mcperr.Out[Data]] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in In) (
		res *mcp.CallToolResult, out mcperr.Out[Data], err error,
	) {
		safety.NoteReached(ctx)
		hi, ok := any(in).(safety.HaltInput)
		if !ok {
			return fail[Data](&mcperr.ToolError{
				Code: mcperr.CodeInternal, Operation: tool,
				Message: "the tool input carries no camera id, so the call was refused",
			})
		}
		camera := hi.CameraID()
		shown := redact.ScrubBounded(camera, maxEchoedCamera, "...")

		dec := d.Policy.EvaluateHalt(camera, tool)
		if dec.Blocked != nil {
			return fail[Data](dec.Blocked)
		}

		// Detach from the request and from shutdown before anything else: once a
		// stop is dispatched, a client cancel or a SIGTERM must not abort it.
		ctx = context.WithoutCancel(ctx)
		ctx, cancel := context.WithTimeout(ctx, haltBudget)
		defer cancel()
		ctx, target := safety.WithTargetSlot(ctx)

		executed, outcome := true, "panic"
		defer func() {
			if r := recover(); r != nil {
				outcome = "panic"
				res, out, err = fail[Data](&mcperr.ToolError{
					Code: mcperr.CodeInternal, Camera: shown, Operation: tool,
					Message: "the tool failed unexpectedly",
					Hint:    "call the stop tool again; if it keeps failing, report this to the operator",
				})
			}
			// Attempted, never required: a missing logger cannot block a stop.
			d.Policy.Audit(tool, camera, false, executed, outcome, safety.WithTarget(target.Get()))
		}()

		res, out, err = run(ctx, req, in)
		if out.Error != nil && out.Error.NotSent {
			executed = false
		}
		switch {
		case err != nil:
			outcome = "error"
		case out.Error != nil:
			outcome = string(out.Error.Code)
		default:
			outcome = "ok"
		}
		if err != nil {
			return res, out, err
		}
		if finishOut(&out) {
			outcome = string(mcperr.CodeDeviceFault)
			res, out, err = fail[Data](nonFiniteError())
		}
		finishText(res)
		return res, out, err
	}
}
