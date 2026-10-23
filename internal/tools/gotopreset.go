package tools

import (
	"context"

	onvif "github.com/0x524a/onvif-go"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/redact"
	"github.com/0x524a/onvif-mcp/internal/safety"
)

const (
	gotoPresetTool = "ptz.goto_preset"
	presetsHint    = "call ptz.presets to list the preset tokens of this profile, then pass one of them as preset"
	noPTZHint      = "call media.profiles and pass the token of a profile whose has_ptz is true"
)

// GotoPresetIn is the input of ptz.goto_preset. WriteBase supplies camera and
// dry_run, and dry_run defaults to true when omitted.
type GotoPresetIn struct {
	safety.WriteBase
	Profile string `json:"profile" jsonschema:"the token of a media profile with has_ptz true; call media.profiles first to get it"`
	Preset  string `json:"preset" jsonschema:"the token of a stored preset on that profile; call ptz.presets first to get it (the token, not the name)"`
}

// GotoPresetData is what ptz.goto_preset reports, for a dry run and a real call.
type GotoPresetData struct {
	Executed   bool     `json:"executed" jsonschema:"true only when the move command was sent to the camera; false for a dry run"`
	DryRun     bool     `json:"dry_run" jsonschema:"true when this call only checked the move and sent nothing"`
	Profile    string   `json:"profile" jsonschema:"the profile token the call addressed"`
	Preset     string   `json:"preset" jsonschema:"the preset token the call addressed"`
	PresetName string   `json:"preset_name,omitempty" jsonschema:"human-readable preset name; absent means the camera reported none"`
	TargetPan  *float64 `json:"target_pan,omitempty" jsonschema:"pan position stored in the preset, in the camera's PTZ position space; absent means the camera did not report one"`
	TargetTilt *float64 `json:"target_tilt,omitempty" jsonschema:"tilt position stored in the preset, in the camera's PTZ position space; absent means the camera did not report one"`
	TargetZoom *float64 `json:"target_zoom,omitempty" jsonschema:"zoom position stored in the preset, in the camera's PTZ position space; absent means the camera did not report one"`
	Limits     *Limits  `json:"reported_limits,omitempty" jsonschema:"movement limits of the profile's PTZ configuration; absent means the camera reported none or they could not be read"`
	Note       string   `json:"note" jsonschema:"what happened and what to do next"`
}

// RegisterPTZWrites registers ptz.goto_preset, the only state-changing tool.
// It goes through GuardedTool as RiskWrite: with control off it is not
// registered (and so absent from tools/list) but is still named by the policy
// resource; with control on it defaults to a dry run, needs the camera's own
// grant, and is rate limited.
func RegisterPTZWrites(srv *mcp.Server, d Deps) {
	GuardedTool(srv, d, safety.RiskWrite, &mcp.Tool{
		InputSchema: gotoPresetSchema(),
		Name:        gotoPresetTool,
		Description: "Use this to move a PTZ camera to a preset it has stored. Call media.profiles first for a profile " +
			"with has_ptz true, then ptz.presets for the preset token. This tool physically moves the camera and is " +
			"a dry run by default: with dry_run omitted or true it checks that the profile has PTZ and the preset " +
			"exists, reports the preset's stored target position and the camera's movement limits, and moves nothing. " +
			"Pass dry_run false to actually move. A real move is rate limited per camera and only works on cameras " +
			"the operator opted in to control. The call returns when the camera answers the command, which does " +
			"not mean it has arrived or even accepted it: call ptz.status to see where it is. If a real call times out or faults after " +
			"the command was sent, the camera may or may not have moved: check ptz.status before trying again. " +
			"Does not create or change presets and does not do free pan, tilt or zoom.",
		Annotations: safety.WriteAnnotations("Go to PTZ preset"),
	}, gotoPresetRun(d), gotoPresetDryRun(d))
}

// gotoPresetSchema is the schema the SDK would infer for GotoPresetIn, plus
// minLength 1 on both tokens: an empty token can never name a profile or a
// preset, so the agent is told so up front. The handler checks again.
func gotoPresetSchema() *jsonschema.Schema {
	s, err := jsonschema.For[GotoPresetIn](nil)
	if err != nil {
		panic("tools: ptz.goto_preset input schema: " + err.Error())
	}
	one := 1
	for _, k := range []string{"profile", "preset"} {
		p, ok := s.Properties[k]
		if !ok {
			panic("tools: ptz.goto_preset input schema has no property " + k)
		}
		p.MinLength = &one
	}
	return s
}

// gotoPlan is a validated move: the camera is reachable, the profile carries
// PTZ and the preset exists on it.
type gotoPlan struct {
	c    *onvif.Client
	data GotoPresetData
	dup  bool // the camera repeats the token with an identical position
}

// notSent marks a failure that happened before any move command was sent.
func notSent(te *mcperr.ToolError) *mcperr.ToolError {
	if te != nil {
		te.NotSent = true
	}
	return te
}

// planGoto is the validation both the dry run and the real call perform, so a
// dry run tells the truth about what a real call would do. It sends only reads.
//
// onvif-go calls (v1.2.0): (*Client).GetProfiles, media.go; (*Client).GetPresets,
// ptz.go:432, whose entries carry Token, Name and an optional PTZPosition;
// (*Client).GetConfiguration, ptz.go:672, for the limits.
func planGoto(ctx context.Context, d Deps, in GotoPresetIn) (*gotoPlan, *mcperr.ToolError) {
	const op = gotoPresetOp
	safety.NoteTarget(ctx, in.Preset)

	if in.Profile == "" || in.Preset == "" {
		return nil, &mcperr.ToolError{
			Code: mcperr.CodeInvalidArgument, Camera: in.Camera, Operation: op, NotSent: true,
			Message: "profile and preset must each be a non-empty token",
			Hint:    "call media.profiles for a profile token, then ptz.presets for a preset token of that profile, and pass both",
		}
	}

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
		return nil, &mcperr.ToolError{
			Code: mcperr.CodeNotFound, Camera: in.Camera, Operation: op, NotSent: true,
			Message: "the camera has no media profile with that token",
			Hint:    "call media.profiles to list the profile tokens, then pass the token of a profile whose has_ptz is true",
		}
	}
	if prof.PTZConfiguration == nil {
		return nil, &mcperr.ToolError{
			Code: mcperr.CodeNotSupported, Camera: in.Camera, Operation: op, NotSent: true,
			Message: "that profile carries no PTZ configuration, so it cannot be moved",
			Hint:    noPTZHint,
		}
	}
	presets, err := c.GetPresets(ctx, in.Profile)
	if err != nil {
		return nil, notSent(withHint(mcperr.FromError(err, in.Camera, "GetPresets"), presetsHint))
	}
	var target *onvif.PTZPreset
	dup := false
	for _, p := range presets {
		// A preset without a token cannot be addressed, so it never matches.
		if p == nil || p.Token == "" || p.Token != in.Preset {
			continue
		}
		if target == nil {
			target = p
			continue
		}
		if !samePosition(target.PTZPosition, p.PTZPosition) {
			return nil, &mcperr.ToolError{
				Code: mcperr.CodeDeviceFault, Camera: in.Camera, Operation: op, NotSent: true,
				Message: "camera lists this preset token more than once with different positions; it will not be moved",
				Hint:    "the camera's preset table is inconsistent, so which position it would go to is unknown; an operator must fix the presets on the camera",
			}
		}
		dup = true
	}
	if target == nil {
		return nil, &mcperr.ToolError{
			Code: mcperr.CodeNotFound, Camera: in.Camera, Operation: op, NotSent: true,
			Message: "that profile has no preset with that token",
			Hint:    presetsHint,
		}
	}

	data := GotoPresetData{
		Profile:    clip(redact.Scrub(prof.Token)),
		Preset:     clip(redact.Scrub(target.Token)),
		PresetName: clip(redact.Scrub(target.Name)),
		Limits:     limitsOfProfile(ctx, c, profiles, in.Profile),
	}
	data.TargetPan, data.TargetTilt, data.TargetZoom = positionOf(target.PTZPosition)
	return &gotoPlan{c: c, data: data, dup: dup}, nil
}

// samePosition reports whether two stored preset positions are identical,
// treating a missing vector, axis or non-finite number as "not reported".
func samePosition(a, b *onvif.PTZVector) bool {
	ap, at, az := positionOf(a)
	bp, bt, bz := positionOf(b)
	eq := func(x, y *float64) bool { return (x == nil && y == nil) || (x != nil && y != nil && *x == *y) }
	return eq(ap, bp) && eq(at, bt) && eq(az, bz)
}

// dupNote is appended to the note when the camera repeats the preset token with
// one and the same position.
const dupNote = " The camera lists this preset token more than once, with the same position."

const gotoPresetOp = "GotoPreset"

func (p *gotoPlan) targetText() string {
	return "preset target " + fmtPos(p.data.TargetPan, p.data.TargetTilt, p.data.TargetZoom)
}

// wholeCall bounds validation, for a dry and a real call alike, to twice the
// camera's per-request timeout. Each request has its own timeout, so without
// this a camera answering every one just under it holds the call open for
// several times that, and the move would be sent on a stale view.
func wholeCall(ctx context.Context, d Deps, camera string) (context.Context, context.CancelFunc) {
	e, err := d.Reg.Get(camera)
	if err != nil {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, 2*e.Timeout())
}

// checkBudget reports a call that was cancelled (ctx) or outlived its
// validation budget (planCtx) as a failure that sent nothing.
func checkBudget(ctx, planCtx context.Context, camera string) *mcperr.ToolError {
	return checkBudgetFor(ctx, planCtx, camera, gotoPresetOp)
}

// checkBudgetFor is checkBudget for the named ONVIF operation.
func checkBudgetFor(ctx, planCtx context.Context, camera, op string) *mcperr.ToolError {
	if ctx.Err() != nil {
		return &mcperr.ToolError{
			Code: mcperr.CodeInternal, Camera: camera, Operation: op, NotSent: true,
			Message: "the call was cancelled before the move command was sent",
			Hint:    "nothing was sent; the server may be shutting down",
		}
	}
	if planCtx.Err() != nil {
		return &mcperr.ToolError{
			Code: mcperr.CodeTimeout, Retryable: true, Camera: camera, Operation: op, NotSent: true,
			Message: "checking the profile and preset took longer than the camera's time budget, so nothing was sent",
			Hint:    "retry, or ask the operator to raise timeout_seconds for this camera in the config",
		}
	}
	return nil
}

// gotoPresetDryRun validates and reports; it never sends GotoPreset. It is
// the only function GuardedTool calls for a dry run.
func gotoPresetDryRun(d Deps) mcp.ToolHandlerFor[GotoPresetIn, mcperr.Out[GotoPresetData]] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in GotoPresetIn) (*mcp.CallToolResult, mcperr.Out[GotoPresetData], error) {
		planCtx, cancel := wholeCall(ctx, d, in.Camera)
		defer cancel()
		plan, te := planGoto(planCtx, d, in)
		if te != nil {
			return fail[GotoPresetData](te)
		}
		if te := checkBudget(ctx, planCtx, in.Camera); te != nil {
			return fail[GotoPresetData](te)
		}
		plan.data.DryRun = true
		// Notes are clipped to 256 characters on the way out, so keep this short.
		plan.data.Note = "Dry run: nothing was sent and the camera did not move. " +
			"To move it, call ptz.goto_preset again with the same arguments and dry_run false."
		if plan.data.Limits == nil {
			plan.data.Note += " Movement limits not reported."
		}
		if plan.dup {
			plan.data.Note += dupNote
		}
		return text("Dry run, camera not moved; " + plan.targetText() + ". Pass dry_run false to move."), mcperr.OK(plan.data), nil
	}
}

// gotoPresetRun validates exactly as the dry run does, then sends GotoPreset
// once. There is no retry: after a timeout the camera may already have moved.
//
// onvif-go: (*Client).GotoPreset(ctx, profileToken, presetToken string, speed
// *PTZSpeed) error, ptz.go:508. speed may be nil, which omits Speed from the
// request (convertToPTZSpeedXML, ptz.go:83) so the camera uses its default;
// v0.1 never sets a speed.
func gotoPresetRun(d Deps) mcp.ToolHandlerFor[GotoPresetIn, mcperr.Out[GotoPresetData]] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in GotoPresetIn) (*mcp.CallToolResult, mcperr.Out[GotoPresetData], error) {
		planCtx, cancel := wholeCall(ctx, d, in.Camera)
		defer cancel()
		plan, te := planGoto(planCtx, d, in)
		if te != nil {
			return fail[GotoPresetData](te)
		}
		// Last point before the command leaves: honour a cancel or shutdown that
		// arrived during validation, and refuse a validation that outlived its
		// budget, since what it saw may be stale.
		if te := checkBudget(ctx, planCtx, in.Camera); te != nil {
			return fail[GotoPresetData](te)
		}
		if err := plan.c.GotoPreset(ctx, in.Profile, in.Preset, nil); err != nil {
			// The request left the server, so the outcome is unknown: the guard adds
			// the may-or-may-not-have-moved hint and clears retryable.
			return fail[GotoPresetData](mcperr.FromError(err, in.Camera, gotoPresetOp))
		}
		plan.data.Executed = true
		plan.data.Note = "The camera returned HTTP success for the move command; that does not confirm it accepted it, " +
			"and it may still be moving. Call ptz.status to confirm where it is."
		if plan.dup {
			plan.data.Note += dupNote
		}
		return text("Move to preset sent; " + plan.targetText() + ". It may still be moving: check ptz.status."), mcperr.OK(plan.data), nil
	}
}
