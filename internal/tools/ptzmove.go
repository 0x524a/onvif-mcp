package tools

import (
	"context"
	"strings"

	onvif "github.com/0x524a/onvif-go"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/redact"
	"github.com/0x524a/onvif-mcp/internal/safety"
)

// MoveRelativeIn is the input of ptz.move_relative. WriteBase supplies camera and
// dry_run (default true). Every axis is a pointer so absent differs from 0.
type MoveRelativeIn struct {
	safety.WriteBase
	Profile string   `json:"profile" jsonschema:"the token of a media profile with has_ptz true; call media.profiles first to get it"`
	Pan     *float64 `json:"pan,omitempty" jsonschema:"pan translation in the ONVIF generic translation space; magnitude at most 0.25 per call, larger values are refused, not clamped; which way a positive value moves the camera is defined by the camera; omit for no pan"`
	Tilt    *float64 `json:"tilt,omitempty" jsonschema:"tilt translation in the ONVIF generic translation space; magnitude at most 0.25 per call, larger values are refused, not clamped; which way a positive value moves the camera is defined by the camera; omit for no tilt"`
	Zoom    *float64 `json:"zoom,omitempty" jsonschema:"zoom translation in the ONVIF generic translation space; magnitude at most 0.25 per call, larger values are refused, not clamped; what a positive value does is defined by the camera; omit for no zoom"`
}

// MoveData is what ptz.move_relative reports, for a dry run and a real call.
type MoveData struct {
	Mode      string `json:"mode" jsonschema:"always relative"`
	Executed  bool   `json:"executed" jsonschema:"true only when the move command was sent to the camera; false for a dry run"`
	DryRun    bool   `json:"dry_run" jsonschema:"true when this call only checked the move and sent nothing"`
	Profile   string `json:"profile" jsonschema:"the profile token the call addressed"`
	Requested Axes   `json:"requested" jsonschema:"the exact numbers sent (or that a real call would send); an omitted pan or tilt next to a sent one is 0"`
	SpaceSent string `json:"space_sent" jsonschema:"the ONVIF generic translation space URIs the command carries, so the unit is visible"`
	Note      string `json:"note" jsonschema:"what happened and what to do next"`
}

const moveRelativeTool = "ptz.move_relative"

func moveRelativeSchema() *jsonschema.Schema {
	s, err := jsonschema.For[MoveRelativeIn](nil)
	if err != nil {
		panic("tools: ptz.move_relative input schema: " + err.Error())
	}
	one := 1
	p, ok := s.Properties["profile"]
	if !ok {
		panic("tools: ptz.move_relative input schema has no property profile")
	}
	p.MinLength = &one
	// No minimum/maximum on pan, tilt or zoom: the SDK would refuse them before
	// the handler with its own generic text. The handler owns the range refusal.
	return s
}

// registerPTZMoveRelative registers ptz.move_relative through GuardedTool as
// RiskWrite and NonIdempotent: repeating it compounds.
func registerPTZMoveRelative(srv *mcp.Server, d Deps) {
	GuardedTool(srv, d, safety.RiskWrite, &mcp.Tool{
		InputSchema: moveRelativeSchema(),
		Name:        moveRelativeTool,
		Description: "Use this to nudge a PTZ camera by a small relative amount. Call media.profiles first for a profile " +
			"with has_ptz true. Pass pan, tilt and/or zoom, each a number sent in the ONVIF generic translation space whose " +
			"magnitude is at most 0.25 per call; larger values are refused, not clamped, and at least one must be non-zero. " +
			"What a value means physically, and which way a positive value moves the camera, is defined by the camera: after " +
			"a small move check ptz.status or camera.snapshot. The camera's own speed applies and may be its maximum. This " +
			"tool physically moves the camera and is a dry run by default: with dry_run omitted or true it validates the " +
			"request and reports the exact numbers and space it would send, and moves nothing. Pass dry_run false to actually " +
			"move. A real move is rate limited per camera (the limit is shared with ptz.goto_preset), only works on cameras " +
			"the operator opted in to control, and is never retried. The call returns when the camera answers the command, " +
			"which does not mean it has finished moving: call ptz.status to see where it is, and ptz.stop to stop it. If a " +
			"real call times out or faults after the command was sent, the camera may or may not have moved: check " +
			"ptz.status before trying again. A camera that ignores the requested space is not detected by this server. " +
			"Does not do continuous or absolute moves.",
		Annotations: safety.WriteAnnotationsNonIdempotent("Nudge PTZ camera"),
	}, moveRelativeRun(d), moveRelativeDryRun(d), NonIdempotent())
}

// movePlan is a validated relative move: the camera is reachable and the profile
// carries PTZ.
type movePlan struct {
	c    *onvif.Client
	vec  relativeVector
	data MoveData
}

// planMove is the validation both the dry run and the real call perform, so a
// dry run tells the truth about what a real call would do. It sends only reads
// (GetProfiles) and never reads a configuration or a position.
//
// onvif-go calls (v1.2.0): (*Client).GetProfiles, media.go.
func planMove(ctx context.Context, d Deps, in MoveRelativeIn) (*movePlan, *mcperr.ToolError) {
	const op = moveRelativeOp
	safety.NoteTarget(ctx, in.Profile)

	vec, te := validateRelative(in)
	if te != nil {
		return nil, te
	}
	ax := vec.axes()
	safety.NoteMotion(ctx, safety.MotionAudit{Mode: "relative", Pan: ax.Pan, Tilt: ax.Tilt, Zoom: ax.Zoom})

	c, te := d.client(ctx, in.Camera, op)
	if te != nil {
		return nil, notSent(te)
	}
	profiles, err := c.GetProfiles(ctx)
	if err != nil {
		return nil, notSent(mcperr.FromError(err, in.Camera, "GetProfiles"))
	}
	prof := findProfile(profiles, in.Profile)
	if prof == nil {
		return nil, invalid(in.Camera,
			"the camera has no media profile with that token",
			"profiles on this camera: "+listProfiles(profiles)+"; pass the token of one whose has_ptz is true as profile")
	}
	if prof.PTZConfiguration == nil {
		return nil, &mcperr.ToolError{
			Code: mcperr.CodeNotSupported, Camera: in.Camera, Operation: op, NotSent: true,
			Message: "that profile carries no PTZ configuration, so it cannot be moved",
			Hint:    noPTZHint,
		}
	}
	return &movePlan{c: c, vec: vec, data: MoveData{
		Mode:      "relative",
		Profile:   clip(redact.Scrub(prof.Token)),
		Requested: ax,
		SpaceSent: vec.spaceSent(),
	}}, nil
}

// moveRelativeFaultHint is added when RelativeMove is answered with a SOAP fault.
const moveRelativeFaultHint = "The camera answered with a SOAP fault; if it names an unsupported space or an invalid translation, the camera rejected the explicit generic translation Space or the step size. This server never resends without the Space; try a smaller step, and report the fault to the operator."

func moveSummary(a Axes) string { return "relative move " + fmtPos(a.Pan, a.Tilt, a.Zoom) }

func moveRelativeDryRun(d Deps) mcp.ToolHandlerFor[MoveRelativeIn, mcperr.Out[MoveData]] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in MoveRelativeIn) (*mcp.CallToolResult, mcperr.Out[MoveData], error) {
		planCtx, cancel := wholeCall(ctx, d, in.Camera)
		defer cancel()
		plan, te := planMove(planCtx, d, in)
		if te != nil {
			return fail[MoveData](te)
		}
		if te := checkBudgetFor(ctx, planCtx, in.Camera, moveRelativeOp); te != nil {
			return fail[MoveData](te)
		}
		plan.data.DryRun = true
		plan.data.Note = "Dry run: nothing was sent and the camera did not move. " +
			"To move it, call ptz.move_relative again with the same arguments and dry_run false."
		return text("Dry run, camera not moved; would send " + moveSummary(plan.data.Requested) + ". Pass dry_run false to move."),
			mcperr.OK(plan.data), nil
	}
}

// moveRelativeRun validates exactly as the dry run does, then sends RelativeMove
// once. There is no retry: after a timeout the camera may already have moved.
//
// onvif-go (v1.2.0): (*Client).RelativeMove(ctx, profileToken string,
// translation *PTZVector, speed *PTZSpeed) error, ptz.go:275. The translation's
// vectors carry the explicit generic Space; speed is nil, which omits Speed
// (convertToPTZSpeedXML), so the camera's default speed applies.
func moveRelativeRun(d Deps) mcp.ToolHandlerFor[MoveRelativeIn, mcperr.Out[MoveData]] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in MoveRelativeIn) (*mcp.CallToolResult, mcperr.Out[MoveData], error) {
		planCtx, cancel := wholeCall(ctx, d, in.Camera)
		defer cancel()
		plan, te := planMove(planCtx, d, in)
		if te != nil {
			return fail[MoveData](te)
		}
		// Last point before the command leaves: honour a cancel or shutdown that
		// arrived during validation, and refuse a validation that outlived its
		// budget.
		if te := checkBudgetFor(ctx, planCtx, in.Camera, moveRelativeOp); te != nil {
			return fail[MoveData](te)
		}
		v := &onvif.PTZVector{}
		if plan.vec.panTilt != nil {
			v.PanTilt = &onvif.Vector2D{X: plan.vec.panTilt[0], Y: plan.vec.panTilt[1], Space: panTiltTranslationSpace}
		}
		if plan.vec.zoom != nil {
			v.Zoom = &onvif.Vector1D{X: *plan.vec.zoom, Space: zoomTranslationSpace}
		}
		if err := plan.c.RelativeMove(ctx, in.Profile, v, nil); err != nil {
			// The request left the server, so the outcome is unknown: the guard adds
			// the may-or-may-not-have-moved hint and clears retryable.
			te := mcperr.FromError(err, in.Camera, moveRelativeOp)
			if te.SOAP != nil {
				// The camera named a rejection. It may be the explicit generic
				// translation Space or the value; the server never retries without it.
				te.Hint = strings.TrimSpace(te.Hint + " " + moveRelativeFaultHint)
			}
			return fail[MoveData](te)
		}
		plan.data.Executed = true
		plan.data.Note = "Command accepted, not 'arrived': the camera may still be moving. Call ptz.status after a second; " +
			"ptz.stop stops it. The camera's default speed applies."
		return text("Relative move sent; " + moveSummary(plan.data.Requested) + ". It may still be moving: check ptz.status."),
			mcperr.OK(plan.data), nil
	}
}
