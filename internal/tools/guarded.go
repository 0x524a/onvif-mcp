package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/safety"
)

// GuardedTool is the registration path for any tool that must declare whether
// it can change a camera. It requires a safety.RiskClass, so a write tool
// cannot be added without saying so, and it registers only through Add, so
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
// Misuse panics at registration instead of returning an error. It is a
// programming error in a fixed set of calls made while the server starts, so
// it fails on every run, including the test run, and cannot be ignored the way
// a returned error can.
func GuardedTool[In, Data any](
	srv *mcp.Server, d Deps, risk safety.RiskClass, t *mcp.Tool,
	run, dryRun mcp.ToolHandlerFor[In, mcperr.Out[Data]],
) {
	if t == nil || run == nil {
		panic("tools.GuardedTool: tool and handler are required")
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
		tc.Annotations = ReadOnly(title)
		Add(srv, &tc, run)

	case safety.RiskWrite:
		var zero In
		if _, ok := any(zero).(safety.WriteInput); !ok {
			panic("tools.GuardedTool: " + t.Name + ": a write tool's input must implement safety.WriteInput (embed safety.WriteBase)")
		}
		if dryRun == nil {
			panic("tools.GuardedTool: " + t.Name + ": a write tool requires a separate dry-run function")
		}
		tc.Annotations = safety.WriteAnnotations(title)
		d.Policy.NoteGated(t.Name)
		if !d.Policy.WriteRegistered() {
			return
		}
		Add(srv, &tc, guardedHandler(d, t.Name, run, dryRun))

	default:
		panic("tools.GuardedTool: " + t.Name + ": unknown risk class")
	}
}

// guardedHandler wraps run and dryRun in the guard. See GuardedTool.
func guardedHandler[In, Data any](
	d Deps, tool string, run, dryRun mcp.ToolHandlerFor[In, mcperr.Out[Data]],
) mcp.ToolHandlerFor[In, mcperr.Out[Data]] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in In) (
		res *mcp.CallToolResult, out mcperr.Out[Data], err error,
	) {
		wi, ok := any(in).(safety.WriteInput)
		if !ok {
			// Unreachable after the registration check; fail closed anyway.
			return fail[Data](&mcperr.ToolError{
				Code: mcperr.CodeInternal, Operation: tool,
				Message: "the tool input carries no camera id, so the call was refused",
			})
		}
		camera, dry := wi.CameraID(), wi.IsDryRun()

		dec := d.Policy.Evaluate(camera, tool, dry)
		if dec.Blocked != nil {
			return fail[Data](dec.Blocked)
		}

		ctx, cancel := d.Scope(ctx)
		defer cancel()

		executed, outcome := false, "panic"
		defer func() {
			if r := recover(); r != nil {
				// The panic value is deliberately neither logged nor returned:
				// it can carry anything the handler held, including secrets.
				outcome = "panic"
				res, out, err = fail[Data](&mcperr.ToolError{
					Code: mcperr.CodeInternal, Camera: camera, Operation: tool,
					Message: "the tool failed unexpectedly",
					Hint:    "do not retry in a loop; the camera state is unknown, so check it with a read tool and report this to the operator",
				})
			}
			d.Policy.Audit(tool, camera, dry, executed, outcome)
		}()

		if dry {
			res, out, err = dryRun(ctx, req, in)
		} else {
			executed = true
			res, out, err = run(ctx, req, in)
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
		return res, out, err
	}
}
