package tools

import (
	"context"
	"fmt"
	"strings"

	onvif "github.com/0x524a/onvif-go"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/redact"
)

// Range is a reported min/max interval.
type Range struct {
	Min float64 `json:"min" jsonschema:"lowest value the camera accepts on this axis, in the camera's PTZ position space"`
	Max float64 `json:"max" jsonschema:"highest value the camera accepts on this axis, in the camera's PTZ position space"`
}

// Limits mirrors the PTZ ranges a camera reports for a profile. Each axis is
// a pointer: an axis the camera did not report is absent, never zero.
type Limits struct {
	Pan  *Range `json:"pan,omitempty" jsonschema:"allowed pan interval; absent means the camera reported no pan limit"`
	Tilt *Range `json:"tilt,omitempty" jsonschema:"allowed tilt interval; absent means the camera reported no tilt limit"`
	Zoom *Range `json:"zoom,omitempty" jsonschema:"allowed zoom interval; absent means the camera reported no zoom limit"`
}

func rangeOf(r *onvif.FloatRange) *Range {
	if r == nil || !finite(r.Min) || !finite(r.Max) {
		return nil
	}
	return &Range{Min: r.Min, Max: r.Max}
}

// limitsFor reads the limits off a PTZ configuration (onvif-go types.go:
// PTZConfiguration.PanTiltLimits / ZoomLimits). Every hop is a pointer and is
// checked; a camera that reports no limits yields nil.
func limitsFor(cfg *onvif.PTZConfiguration) *Limits {
	if cfg == nil {
		return nil
	}
	l := &Limits{}
	if cfg.PanTiltLimits != nil && cfg.PanTiltLimits.Range != nil {
		l.Pan = rangeOf(cfg.PanTiltLimits.Range.XRange)
		l.Tilt = rangeOf(cfg.PanTiltLimits.Range.YRange)
	}
	if cfg.ZoomLimits != nil && cfg.ZoomLimits.Range != nil {
		l.Zoom = rangeOf(cfg.ZoomLimits.Range.XRange)
	}
	if l.Pan == nil && l.Tilt == nil && l.Zoom == nil {
		return nil
	}
	return l
}

func findProfile(ps []*onvif.Profile, token string) *onvif.Profile {
	for _, p := range ps {
		if p != nil && p.Token == token {
			return p
		}
	}
	return nil
}

// positionOf copies a PTZ vector, leaving unreported axes nil. A non-finite
// axis is treated as not reported: JSON cannot carry NaN or infinity.
func positionOf(v *onvif.PTZVector) (pan, tilt, zoom *float64) {
	if v == nil {
		return nil, nil, nil
	}
	if pt := v.PanTilt; pt != nil {
		x, y := pt.X, pt.Y
		if finite(x) {
			pan = &x
		}
		if finite(y) {
			tilt = &y
		}
	}
	if z := v.Zoom; z != nil && finite(z.X) {
		x := z.X
		zoom = &x
	}
	return pan, tilt, zoom
}

func fmtPos(pan, tilt, zoom *float64) string {
	if pan == nil && tilt == nil && zoom == nil {
		return "position not reported"
	}
	f := func(name string, v *float64) string {
		if v == nil {
			return name + " not reported"
		}
		return fmt.Sprintf("%s %g", name, *v)
	}
	return strings.Join([]string{f("pan", pan), f("tilt", tilt), f("zoom", zoom)}, ", ")
}

// PresetSummary is one PTZ preset. Position fields are absent when the camera
// stored or reported no position for the preset.
type PresetSummary struct {
	Token string   `json:"token" jsonschema:"the preset token, the handle a later tool would use to go to this preset"`
	Name  string   `json:"name,omitempty" jsonschema:"human-readable preset name; absent means the camera reported none"`
	Pan   *float64 `json:"pan,omitempty" jsonschema:"stored pan position; in ONVIF's generic space this is normalised from -1 to 1, otherwise in the camera's own space (compare reported_limits); absent means not reported"`
	Tilt  *float64 `json:"tilt,omitempty" jsonschema:"stored tilt position; in ONVIF's generic space this is normalised from -1 to 1, otherwise in the camera's own space (compare reported_limits); absent means not reported"`
	Zoom  *float64 `json:"zoom,omitempty" jsonschema:"stored zoom position; in ONVIF's generic space this runs from 0 to 1, otherwise in the camera's own space (compare reported_limits); absent means not reported"`
}

// PresetsData is the ptz.presets result.
type PresetsData struct {
	Presets []PresetSummary `json:"presets" jsonschema:"the profile's stored presets in the order the camera reported them, at most 256, one per token; empty means the camera has none"`
	// Total is the number of distinct preset tokens the camera reported.
	Total int `json:"total" jsonschema:"number of distinct preset tokens the camera reported, which can exceed the length of presets"`
	// Truncated is true when Total exceeds the number listed.
	Truncated bool `json:"truncated" jsonschema:"true when total is larger than the number of presets listed"`
	// DuplicatesDropped counts presets dropped for repeating an earlier token;
	// the first is kept.
	DuplicatesDropped int     `json:"duplicates_dropped,omitempty" jsonschema:"number of presets left out because they repeated an earlier token; absent means none"`
	Limits            *Limits `json:"reported_limits,omitempty" jsonschema:"movement limits of the profile's PTZ configuration, in the same space as the preset positions; absent means the camera reported none or they could not be read"`
}

// maxPresets bounds ptz.presets; ONVIF cameras commonly hold up to 255.
const maxPresets = 256

// StatusData is the ptz.status result. Absent position fields were not
// reported by the camera.
type StatusData struct {
	Pan          *float64 `json:"pan,omitempty" jsonschema:"current pan position; in ONVIF's generic space this is normalised from -1 to 1, otherwise in the camera's own space (ptz.presets reports the limits); absent means not reported"`
	Tilt         *float64 `json:"tilt,omitempty" jsonschema:"current tilt position; in ONVIF's generic space this is normalised from -1 to 1, otherwise in the camera's own space (ptz.presets reports the limits); absent means not reported"`
	Zoom         *float64 `json:"zoom,omitempty" jsonschema:"current zoom position; in ONVIF's generic space this runs from 0 to 1, otherwise in the camera's own space (ptz.presets reports the limits); absent means not reported"`
	PanTiltState string   `json:"pan_tilt_state,omitempty" jsonschema:"pan/tilt movement state as the camera names it, normally IDLE, MOVING or UNKNOWN; absent means not reported"`
	ZoomState    string   `json:"zoom_state,omitempty" jsonschema:"zoom movement state as the camera names it, normally IDLE, MOVING or UNKNOWN; absent means not reported"`
	DeviceError  string   `json:"device_error,omitempty" jsonschema:"error text the camera reports in its PTZ status; absent means none was reported"`
}

// statusOf copies a PTZ status; nil status (an empty reply) reports nothing.
func statusOf(st *onvif.PTZStatus) StatusData {
	var out StatusData
	if st == nil {
		return out
	}
	out.DeviceError = clip(redact.Scrub(st.Error))
	out.Pan, out.Tilt, out.Zoom = positionOf(st.Position)
	if st.MoveStatus != nil {
		out.PanTiltState = clip(redact.Scrub(st.MoveStatus.PanTilt))
		out.ZoomState = clip(redact.Scrub(st.MoveStatus.Zoom))
	}
	return out
}

// presetsOf reduces the camera's preset list: nil entries are skipped, a
// repeated token keeps its first occurrence, and the list is capped at
// maxPresets. noPos counts listed presets with no position at all.
func presetsOf(presets []*onvif.PTZPreset) (out PresetsData, noPos int) {
	out.Presets = make([]PresetSummary, 0, min(len(presets), maxPresets))
	seen := map[string]bool{}
	for _, p := range presets {
		if p == nil {
			continue
		}
		tok := cleanString(p.Token, maxFieldRunes)
		if seen[tok] {
			out.DuplicatesDropped++
			continue
		}
		seen[tok] = true
		out.Total++
		if len(out.Presets) >= maxPresets {
			out.Truncated = true
			continue
		}
		s := PresetSummary{Token: clip(redact.Scrub(p.Token)), Name: clip(redact.Scrub(p.Name))}
		s.Pan, s.Tilt, s.Zoom = positionOf(p.PTZPosition)
		if s.Pan == nil && s.Tilt == nil && s.Zoom == nil {
			noPos++
		}
		out.Presets = append(out.Presets, s)
	}
	return out, noPos
}

// configTokenFor returns the PTZ configuration token of the named profile, or
// "" when the profile is absent or has no PTZ configuration.
func configTokenFor(ps []*onvif.Profile, profile string) string {
	p := findProfile(ps, profile)
	if p == nil || p.PTZConfiguration == nil {
		return ""
	}
	return p.PTZConfiguration.Token
}

// limitsOfProfile reads the movement limits of the named profile's PTZ
// configuration (onvif-go ptz.go: (*Client).GetConfiguration, which returns the
// same PTZConfiguration type as GetConfigurations). Failing to read them is
// not a failure of the caller, so any error yields nil, as does a camera that
// reports no limits.
func limitsOfProfile(ctx context.Context, c *onvif.Client, ps []*onvif.Profile, profile string) *Limits {
	tok := configTokenFor(ps, profile)
	if tok == "" {
		return nil
	}
	cfg, err := c.GetConfiguration(ctx, tok)
	if err != nil {
		return nil
	}
	return limitsFor(cfg)
}

// RegisterPTZReads registers ptz.status and ptz.presets.
func RegisterPTZReads(srv *mcp.Server, d Deps) {
	// onvif-go: (*Client).GetStatus, ptz.go.
	readTool(srv, d, &mcp.Tool{
		Name: "ptz.status",
		Description: "Use this to see where a camera is pointing and whether it is moving. Call media.profiles first " +
			"and pass the token of a profile with has_ptz true as profile. Pan and tilt are normalised -1 to 1 " +
			"and zoom 0 to 1 when the camera uses ONVIF's generic position space; a camera may use its own " +
			"space, and this tool does not say which. An absent pan, tilt or zoom was not reported by the " +
			"camera. Fails with not_supported if the camera has no PTZ service. Does not move the camera.",
		Annotations: ReadOnly("Get PTZ status"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ProfileIn) (*mcp.CallToolResult, mcperr.Out[StatusData], error) {
		ctx, cancel := d.Scope(ctx)
		defer cancel()
		c, te := d.client(ctx, in.Camera, "GetStatus")
		if te != nil {
			return fail[StatusData](te)
		}
		st, err := c.GetStatus(ctx, in.Profile)
		if err != nil {
			return fail[StatusData](withHint(mcperr.FromError(err, in.Camera, "GetStatus"), profilesHint))
		}
		out := statusOf(st)
		msg := "PTZ " + fmtPos(out.Pan, out.Tilt, out.Zoom) + "."
		if out.PanTiltState != "" {
			msg += " Pan/tilt " + out.PanTiltState + "."
		}
		return text(msg), mcperr.OK(out), nil
	})

	// onvif-go: (*Client).GetPresets and (*Client).GetConfiguration, ptz.go; (*Client).GetProfiles, media.go.
	readTool(srv, d, &mcp.Tool{
		Name: "ptz.presets",
		Description: "Use this to list the named positions stored on a camera, and its movement limits. Call " +
			"media.profiles first and pass the token of a profile with has_ptz true as profile. Each preset has " +
			"token, name and, when the camera reports them, pan and tilt (normalised -1 to 1 in ONVIF's generic " +
			"space) and zoom (0 to 1); reported_limits holds the movement limits when the camera reports " +
			"them. Absent means not reported. At most 256 presets are listed; total and truncated say when " +
			"there were more. Fails with not_supported if the camera has no PTZ service. Does not move the " +
			"camera or go to a preset.",
		Annotations: ReadOnly("List PTZ presets"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ProfileIn) (*mcp.CallToolResult, mcperr.Out[PresetsData], error) {
		ctx, cancel := d.Scope(ctx)
		defer cancel()
		c, te := d.client(ctx, in.Camera, "GetPresets")
		if te != nil {
			return fail[PresetsData](te)
		}
		presets, err := c.GetPresets(ctx, in.Profile)
		if err != nil {
			return fail[PresetsData](withHint(mcperr.FromError(err, in.Camera, "GetPresets"), profilesHint))
		}
		out, noPos := presetsOf(presets)
		// GetProfiles does not populate limits; they come from GetConfiguration
		// on the profile's PTZ configuration token. Failing to read them is not
		// a failure of this tool: they are reported when available.
		if ps, perr := c.GetProfiles(ctx); perr == nil {
			out.Limits = limitsOfProfile(ctx, c, ps, in.Profile)
		}
		msg := fmt.Sprintf("%d preset(s)", out.Total)
		if out.Truncated {
			msg += fmt.Sprintf(" (first %d listed)", len(out.Presets))
		}
		if noPos > 0 {
			msg += fmt.Sprintf(", %d with position not reported", noPos)
		}
		if out.Limits == nil {
			msg += "; movement limits not reported"
		}
		return text(msg + "."), mcperr.OK(out), nil
	})
}
