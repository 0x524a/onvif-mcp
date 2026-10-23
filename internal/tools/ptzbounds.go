package tools

import (
	"fmt"
	"math"
	"strconv"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
)

// Relative-move bounds and the ONVIF generic translation space.
//
// SPEC STATUS (plan 2026-10-18-phase13a, Task 0 step 1): the two Translation
// space URIs below and the -1..1 range of the generic translation spaces are
// recalled from the ONVIF PTZ Service Specification (section on generic
// coordinate spaces, "Translation" under PanTiltSpaces and ZoomSpaces). They
// could NOT be checked against the specification text in the session that wrote
// this file (no network access to the spec), so no section numbers are recorded
// and nothing below claims a sign convention or what +-1 spans. Re-verify
// against the spec before relying on them; until then the agent-facing text says
// only that the camera defines what a value means. The Velocity generic space
// URIs (VelocityGenericSpace, Stage B) are likewise unverified and unused.
const (
	// maxRelativeStep is the server's own cap on one axis of one relative move.
	// It is a constant, not configuration, until a real need appears.
	maxRelativeStep = 0.25

	panTiltTranslationSpace = "http://www.onvif.org/ver10/tptz/PanTiltSpaces/TranslationGenericSpace"
	zoomTranslationSpace    = "http://www.onvif.org/ver10/tptz/ZoomSpaces/TranslationGenericSpace"
)

// Axes carries the numbers of a motion command. A nil axis was not sent.
type Axes struct {
	Pan  *float64 `json:"pan,omitempty" jsonschema:"pan value sent; absent means no pan was sent"`
	Tilt *float64 `json:"tilt,omitempty" jsonschema:"tilt value sent; absent means no tilt was sent"`
	Zoom *float64 `json:"zoom,omitempty" jsonschema:"zoom value sent; absent means no zoom was sent"`
}

// relativeVector is a validated translation: PanTilt is present when pan or tilt
// is non-zero (the other is sent as 0), Zoom when zoom is non-zero.
type relativeVector struct {
	panTilt *[2]float64
	zoom    *float64
}

func (v relativeVector) axes() Axes {
	var a Axes
	if v.panTilt != nil {
		p, t := v.panTilt[0], v.panTilt[1]
		a.Pan, a.Tilt = &p, &t
	}
	if v.zoom != nil {
		z := *v.zoom
		a.Zoom = &z
	}
	return a
}

// spaceSent names the generic space URIs the command carries, for the dry run.
func (v relativeVector) spaceSent() string {
	switch {
	case v.panTilt != nil && v.zoom != nil:
		return panTiltTranslationSpace + " (pan, tilt); " + zoomTranslationSpace + " (zoom)"
	case v.panTilt != nil:
		return panTiltTranslationSpace + " (pan, tilt)"
	default:
		return zoomTranslationSpace + " (zoom)"
	}
}

const moveRelativeOp = "RelativeMove"

func invalid(camera, msg, hint string) *mcperr.ToolError {
	return &mcperr.ToolError{
		Code: mcperr.CodeInvalidArgument, Camera: camera, Operation: moveRelativeOp, NotSent: true,
		Message: msg, Hint: hint,
	}
}

// overCap is the refusal for an axis outside the server cap. It names the field,
// the legal range, the source and a corrected call.
func overCap(camera, field string, v float64) *mcperr.ToolError {
	fixed := math.Copysign(maxRelativeStep, v)
	return invalid(camera,
		fmt.Sprintf("%s %s is outside the allowed range -%g to %g (source: server cap, per call, not configurable); it was refused, not clamped",
			field, strconv.FormatFloat(v, 'g', 6, 64), maxRelativeStep, maxRelativeStep),
		fmt.Sprintf("call ptz.move_relative again with %s at most %g in magnitude, for example %s %g", field, maxRelativeStep, field, fixed))
}

// validateRelative applies the Stage A bounds to the agent's input. It touches
// no camera. -0 becomes 0, NaN and infinities are refused, an omitted axis is 0,
// and at least one axis must be non-zero. Out-of-range input is refused, never
// clamped: the handler (not the input schema) owns this refusal so an agent
// always gets the legible envelope.
func validateRelative(in MoveRelativeIn) (relativeVector, *mcperr.ToolError) {
	cam := in.Camera
	if in.Profile == "" || len(in.Profile) > maxProfileBytes {
		return relativeVector{}, invalid(cam,
			fmt.Sprintf("profile must be a token of 1 to %d bytes", maxProfileBytes),
			noPTZHint)
	}
	axes := []struct {
		name string
		v    *float64
	}{{"pan", in.Pan}, {"tilt", in.Tilt}, {"zoom", in.Zoom}}
	vals := map[string]float64{}
	for _, a := range axes {
		if a.v == nil {
			continue
		}
		v := *a.v
		if !finite(v) {
			return relativeVector{}, invalid(cam,
				a.name+" must be a finite number",
				fmt.Sprintf("call ptz.move_relative again with %s between -%g and %g", a.name, maxRelativeStep, maxRelativeStep))
		}
		if math.Abs(v) > maxRelativeStep {
			return relativeVector{}, overCap(cam, a.name, v)
		}
		if v == 0 {
			v = 0 // -0 becomes 0
		}
		vals[a.name] = v
	}
	var out relativeVector
	if vals["pan"] != 0 || vals["tilt"] != 0 {
		out.panTilt = &[2]float64{vals["pan"], vals["tilt"]}
	}
	if vals["zoom"] != 0 {
		z := vals["zoom"]
		out.zoom = &z
	}
	if out.panTilt == nil && out.zoom == nil {
		return relativeVector{}, invalid(cam,
			"at least one of pan, tilt or zoom must be present and non-zero; an omitted axis is 0",
			fmt.Sprintf("call ptz.move_relative again with a non-zero pan, tilt or zoom of at most %g in magnitude; to stop a camera use ptz.stop", maxRelativeStep))
	}
	return out, nil
}
