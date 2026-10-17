package tools

import (
	"context"
	"fmt"
	"strings"

	onvif "github.com/0x524a/onvif-go"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
)

const sourceHint = "call media.profiles and pass a video_source_token from its result as source_token"

// ImagingData reports imaging settings. Every field is optional because the
// library models them as pointers and cameras vary in what they report; an
// absent field was not reported.
type ImagingData struct {
	Brightness      *float64 `json:"brightness,omitempty" jsonschema:"brightness on the camera's own scale; ONVIF fixes no range and this tool does not read the camera's imaging options, so the number is only comparable with the same camera's other readings; absent means not reported"`
	ColorSaturation *float64 `json:"color_saturation,omitempty" jsonschema:"color saturation on the camera's own scale (see brightness); absent means not reported"`
	Contrast        *float64 `json:"contrast,omitempty" jsonschema:"contrast on the camera's own scale (see brightness); absent means not reported"`
	Sharpness       *float64 `json:"sharpness,omitempty" jsonschema:"sharpness on the camera's own scale (see brightness); absent means not reported"`
}

func summarizeImaging(d ImagingData) string {
	f := func(name string, v *float64) string {
		if v == nil {
			return name + " not reported"
		}
		return fmt.Sprintf("%s %g", name, *v)
	}
	return "Imaging: " + strings.Join([]string{
		f("brightness", d.Brightness), f("contrast", d.Contrast),
		f("saturation", d.ColorSaturation), f("sharpness", d.Sharpness),
	}, ", ") + "."
}

// imagingOf copies the four settings this tool reports; nil settings (a camera
// that answered with an empty body) report nothing.
func imagingOf(s *onvif.ImagingSettings) ImagingData {
	if s == nil {
		return ImagingData{}
	}
	return ImagingData{
		Brightness:      finitePtr(s.Brightness),
		ColorSaturation: finitePtr(s.ColorSaturation),
		Contrast:        finitePtr(s.Contrast),
		Sharpness:       finitePtr(s.Sharpness),
	}
}

// RegisterImaging registers imaging.settings.
func RegisterImaging(srv *mcp.Server, d Deps) {
	// onvif-go: (*Client).GetImagingSettings, imaging.go.
	Add(srv, &mcp.Tool{
		Name: "imaging.settings",
		Description: "Use this to read how a camera's image is tuned: brightness, color_saturation, contrast and " +
			"sharpness of one video source. Call media.profiles first and pass a video_source_token from it " +
			"as source_token (not the profile token). Values are on the camera's own scale, which this tool " +
			"does not report, so compare them only with the same camera's other readings. An absent field was " +
			"not reported by the camera. Fails with not_supported if the camera has no imaging service. Does " +
			"not change any setting and does not read exposure, focus or white balance.",
		Annotations: ReadOnly("Get imaging settings"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in SourceIn) (*mcp.CallToolResult, mcperr.Out[ImagingData], error) {
		ctx, cancel := d.Scope(ctx)
		defer cancel()
		c, te := d.client(ctx, in.Camera, "GetImagingSettings")
		if te != nil {
			return fail[ImagingData](te)
		}
		s, err := c.GetImagingSettings(ctx, in.SourceToken)
		if err != nil {
			return fail[ImagingData](withHint(mcperr.FromError(err, in.Camera, "GetImagingSettings"), sourceHint))
		}
		out := imagingOf(s)
		return text(summarizeImaging(out)), mcperr.OK(out), nil
	})
}

// finitePtr drops a NaN or infinite value: JSON cannot carry it, and a value
// that is not a number was not usefully reported.
func finitePtr(v *float64) *float64 {
	if v == nil || !finite(*v) {
		return nil
	}
	return v
}
