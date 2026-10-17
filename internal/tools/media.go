package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/redact"
)

const profilesHint = "call media.profiles to list the valid profile tokens for this camera"

// ProfileSummary is a media profile reduced to what an agent needs. Encoding,
// Width, Height and Framerate are absent when the camera did not report them;
// a missing value is never filled with a zero.
type ProfileSummary struct {
	Token       string `json:"token"`
	Name        string `json:"name,omitempty"`
	HasPTZ      bool   `json:"has_ptz"`
	Encoding    string `json:"encoding,omitempty"`
	Width       int    `json:"width,omitempty"`
	Height      int    `json:"height,omitempty"`
	Framerate   int    `json:"framerate,omitempty"`
	SourceToken string `json:"video_source_token,omitempty"`
}

// ProfilesData is the media.profiles result.
type ProfilesData struct {
	Profiles []ProfileSummary `json:"profiles"`
}

// StreamURIData is the media.stream_uri result. The URI is redacted; the
// server holds the credentials needed to play it.
type StreamURIData struct {
	URI                 string `json:"uri"`
	CredentialsRequired bool   `json:"credentials_required"`
	InvalidAfterConnect bool   `json:"invalid_after_connect"`
	InvalidAfterReboot  bool   `json:"invalid_after_reboot"`
}

func summarizeProfiles(ps []ProfileSummary) string {
	if len(ps) == 0 {
		return "The camera reported no media profiles."
	}
	parts := make([]string, 0, len(ps))
	for _, p := range ps {
		var d []string
		switch {
		case p.Encoding != "" && p.Width > 0 && p.Height > 0:
			d = append(d, fmt.Sprintf("%s %dx%d", p.Encoding, p.Width, p.Height))
		case p.Encoding != "":
			d = append(d, p.Encoding+", resolution not reported")
		default:
			d = append(d, "video encoding not reported")
		}
		if p.HasPTZ {
			d = append(d, "PTZ")
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", p.Token, strings.Join(d, ", ")))
	}
	return fmt.Sprintf("%d profile(s): %s.", len(ps), strings.Join(parts, "; "))
}

// RegisterMedia registers media.profiles and media.stream_uri.
func RegisterMedia(srv *mcp.Server, d Deps) {
	// onvif-go: (*Client).GetProfiles, media.go.
	mcp.AddTool(srv, &mcp.Tool{
		Name: "media.profiles",
		Description: "List a camera's media profiles. Each has token (pass it as profile to other tools), " +
			"has_ptz, and, when the camera reports them, encoding, width, height, framerate and " +
			"video_source_token (pass it as source_token to imaging.settings). An absent field means " +
			"the camera did not report it.",
		Annotations: ReadOnly("List media profiles"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in CameraIn) (*mcp.CallToolResult, mcperr.Out[ProfilesData], error) {
		ctx, cancel := d.Scope(ctx)
		defer cancel()
		c, te := d.client(ctx, in.Camera, "GetProfiles")
		if te != nil {
			return fail[ProfilesData](te)
		}
		ps, err := c.GetProfiles(ctx)
		if err != nil {
			return fail[ProfilesData](mcperr.FromError(err, in.Camera, "GetProfiles"))
		}
		out := ProfilesData{Profiles: make([]ProfileSummary, 0, len(ps))}
		for _, p := range ps {
			if p == nil {
				continue
			}
			s := ProfileSummary{Token: p.Token, Name: p.Name, HasPTZ: p.PTZConfiguration != nil}
			if v := p.VideoEncoderConfiguration; v != nil {
				s.Encoding = v.Encoding
				if v.RateControl != nil {
					s.Framerate = v.RateControl.FrameRateLimit
				}
				if v.Resolution != nil {
					s.Width, s.Height = v.Resolution.Width, v.Resolution.Height
				}
			}
			if p.VideoSourceConfiguration != nil {
				s.SourceToken = p.VideoSourceConfiguration.SourceToken
			}
			out.Profiles = append(out.Profiles, s)
		}
		return text(summarizeProfiles(out.Profiles)), mcperr.OK(out), nil
	})

	// onvif-go: (*Client).GetStreamURI, media.go.
	mcp.AddTool(srv, &mcp.Tool{
		Name: "media.stream_uri",
		Description: "Get the RTSP stream URI for a profile. Credentials are never included, in the URI or " +
			"anywhere else; they stay server-side and are applied by tools that open the stream.",
		Annotations: ReadOnly("Get stream URI"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ProfileIn) (*mcp.CallToolResult, mcperr.Out[StreamURIData], error) {
		ctx, cancel := d.Scope(ctx)
		defer cancel()
		c, te := d.client(ctx, in.Camera, "GetStreamURI")
		if te != nil {
			return fail[StreamURIData](te)
		}
		u, err := c.GetStreamURI(ctx, in.Profile)
		if err != nil {
			return fail[StreamURIData](withHint(mcperr.FromError(err, in.Camera, "GetStreamURI"), profilesHint))
		}
		if u == nil || u.URI == "" {
			return fail[StreamURIData](&mcperr.ToolError{
				Code: mcperr.CodeDeviceFault, Camera: in.Camera, Operation: "GetStreamURI",
				Message: "the camera returned no stream URI for this profile",
				Hint:    profilesHint,
			})
		}
		red, perr := redact.Parse(u.URI)
		if perr != nil {
			return fail[StreamURIData](&mcperr.ToolError{
				Code: mcperr.CodeDeviceFault, Camera: in.Camera, Operation: "GetStreamURI",
				Message: "the camera returned a stream URI that could not be parsed",
			})
		}
		data := StreamURIData{
			URI:                 red.String(),
			CredentialsRequired: true,
			InvalidAfterConnect: u.InvalidAfterConnect,
			InvalidAfterReboot:  u.InvalidAfterReboot,
		}
		return text("Stream URI for profile " + in.Profile + ": " + data.URI + " (credentials held server-side)."),
			mcperr.OK(data), nil
	})
}
