package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
)

const sourceHint = "call media.profiles and pass a video_source_token from its result as source_token"

// ImagingData reports imaging settings. Every field is optional because the
// library models them as pointers and cameras vary in what they report; an
// absent field was not reported.
type ImagingData struct {
	Brightness      *float64 `json:"brightness,omitempty"`
	ColorSaturation *float64 `json:"color_saturation,omitempty"`
	Contrast        *float64 `json:"contrast,omitempty"`
	Sharpness       *float64 `json:"sharpness,omitempty"`
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

// RegisterImaging registers imaging.settings.
func RegisterImaging(srv *mcp.Server, d Deps) {
	// onvif-go: (*Client).GetImagingSettings, imaging.go.
	mcp.AddTool(srv, &mcp.Tool{
		Name: "imaging.settings",
		Description: "Read a video source's imaging settings (brightness, color_saturation, contrast, " +
			"sharpness). An absent field was not reported by the camera. Fails with not_supported if the " +
			"camera has no imaging service.",
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
		var out ImagingData
		if s != nil {
			out = ImagingData{
				Brightness:      s.Brightness,
				ColorSaturation: s.ColorSaturation,
				Contrast:        s.Contrast,
				Sharpness:       s.Sharpness,
			}
		}
		return text(summarizeImaging(out)), mcperr.OK(out), nil
	})
}
