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
	Min float64 `json:"min"`
	Max float64 `json:"max"`
}

// Limits mirrors the PTZ ranges a camera reports for a profile. Each axis is
// a pointer: an axis the camera did not report is absent, never zero.
type Limits struct {
	Pan  *Range `json:"pan,omitempty"`
	Tilt *Range `json:"tilt,omitempty"`
	Zoom *Range `json:"zoom,omitempty"`
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
	Token string   `json:"token"`
	Name  string   `json:"name,omitempty"`
	Pan   *float64 `json:"pan,omitempty"`
	Tilt  *float64 `json:"tilt,omitempty"`
	Zoom  *float64 `json:"zoom,omitempty"`
}

// PresetsData is the ptz.presets result.
type PresetsData struct {
	Presets []PresetSummary `json:"presets"`
	// Total is the number of distinct preset tokens the camera reported.
	Total int `json:"total"`
	// Truncated is true when Total exceeds the number listed.
	Truncated bool `json:"truncated"`
	// DuplicatesDropped counts presets dropped for repeating an earlier token;
	// the first is kept.
	DuplicatesDropped int     `json:"duplicates_dropped,omitempty"`
	Limits            *Limits `json:"reported_limits,omitempty"`
}

// maxPresets bounds ptz.presets; ONVIF cameras commonly hold up to 255.
const maxPresets = 256

// StatusData is the ptz.status result. Absent position fields were not
// reported by the camera.
type StatusData struct {
	Pan          *float64 `json:"pan,omitempty"`
	Tilt         *float64 `json:"tilt,omitempty"`
	Zoom         *float64 `json:"zoom,omitempty"`
	PanTiltState string   `json:"pan_tilt_state,omitempty"`
	ZoomState    string   `json:"zoom_state,omitempty"`
	DeviceError  string   `json:"device_error,omitempty"`
}

// RegisterPTZReads registers ptz.status and ptz.presets.
func RegisterPTZReads(srv *mcp.Server, d Deps) {
	// onvif-go: (*Client).GetStatus, ptz.go.
	Add(srv, &mcp.Tool{
		Name: "ptz.status",
		Description: "Read a profile's current PTZ position and movement state. An absent pan, tilt or zoom " +
			"was not reported by the camera. Fails with not_supported if the camera has no PTZ service.",
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
		var out StatusData
		if st != nil {
			out.DeviceError = clip(redact.Scrub(st.Error))
			out.Pan, out.Tilt, out.Zoom = positionOf(st.Position)
			if st.MoveStatus != nil {
				out.PanTiltState = clip(redact.Scrub(st.MoveStatus.PanTilt))
				out.ZoomState = clip(redact.Scrub(st.MoveStatus.Zoom))
			}
		}
		msg := "PTZ " + fmtPos(out.Pan, out.Tilt, out.Zoom) + "."
		if out.PanTiltState != "" {
			msg += " Pan/tilt " + out.PanTiltState + "."
		}
		return text(msg), mcperr.OK(out), nil
	})

	// onvif-go: (*Client).GetPresets and (*Client).GetConfiguration, ptz.go; (*Client).GetProfiles, media.go.
	Add(srv, &mcp.Tool{
		Name: "ptz.presets",
		Description: "List a profile's stored PTZ presets (token, name, and pan/tilt/zoom when the camera " +
			"reports them) and, when reported, the movement limits in reported_limits. Absent means not " +
			"reported. Fails with not_supported if the camera has no PTZ service.",
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
		out := PresetsData{Presets: make([]PresetSummary, 0, min(len(presets), maxPresets))}
		noPos := 0
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
		// GetProfiles does not populate limits; they come from GetConfiguration
		// on the profile's PTZ configuration token. Failing to read them is not
		// a failure of this tool: they are reported when available.
		if ps, perr := c.GetProfiles(ctx); perr == nil {
			if p := findProfile(ps, in.Profile); p != nil && p.PTZConfiguration != nil && p.PTZConfiguration.Token != "" {
				if cfg, cerr := c.GetConfiguration(ctx, p.PTZConfiguration.Token); cerr == nil {
					out.Limits = limitsFor(cfg)
				}
			}
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
