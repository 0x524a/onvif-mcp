package tools

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/redact"
)

const (
	// maxProfiles bounds media.profiles. A real camera has a handful; the cap
	// protects the agent's context window from a hostile or buggy one.
	maxProfiles = 100
	// maxURIChars bounds a stream URI. Longer is treated as a device fault
	// rather than clipped, because a clipped URI is a different, wrong URI.
	maxURIChars = 2048
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
	// Total is the number of distinct profile tokens the camera reported.
	Total int `json:"total"`
	// Truncated is true when Total exceeds the number listed.
	Truncated bool `json:"truncated"`
	// DuplicatesDropped counts profiles dropped for repeating an earlier token;
	// the first is kept.
	DuplicatesDropped int `json:"duplicates_dropped,omitempty"`
}

// StreamURIData is the media.stream_uri result. The URI is redacted; the
// server holds the credentials needed to play it.
type StreamURIData struct {
	URI                 string `json:"uri" sanitize:"noclip"`
	CredentialsRequired bool   `json:"credentials_required"`
	InvalidAfterConnect bool   `json:"invalid_after_connect"`
	InvalidAfterReboot  bool   `json:"invalid_after_reboot"`
}

func summarizeProfiles(d ProfilesData) string {
	if d.Total == 0 {
		return "The camera reported no media profiles."
	}
	parts := make([]string, 0, len(d.Profiles))
	for _, p := range d.Profiles {
		var det []string
		switch {
		case p.Encoding != "" && p.Width > 0 && p.Height > 0:
			det = append(det, fmt.Sprintf("%s %dx%d", p.Encoding, p.Width, p.Height))
		case p.Encoding != "":
			det = append(det, p.Encoding+", resolution not reported")
		default:
			det = append(det, "video encoding not reported")
		}
		if p.HasPTZ {
			det = append(det, "PTZ")
		}
		if p.SourceToken != "" {
			det = append(det, "source="+p.SourceToken)
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", p.Token, strings.Join(det, ", ")))
	}
	return fmt.Sprintf("%d profile(s): %s.", d.Total, joinWithin(parts, "; ", maxTextChars-60, d.Total))
}

// dropFragment removes the URI fragment. RTSP has no use for one, and it is a
// carrier for secrets that the redactor does not recognise by key.
func dropFragment(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		if i := strings.IndexByte(raw, '#'); i >= 0 {
			return raw[:i]
		}
		return raw
	}
	u.Fragment, u.RawFragment = "", ""
	return u.String()
}

// RegisterMedia registers media.profiles and media.stream_uri.
func RegisterMedia(srv *mcp.Server, d Deps) {
	// onvif-go: (*Client).GetProfiles, media.go.
	Add(srv, &mcp.Tool{
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
		out := ProfilesData{Profiles: make([]ProfileSummary, 0, min(len(ps), maxProfiles))}
		seen := map[string]bool{}
		for _, p := range ps {
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
			if len(out.Profiles) >= maxProfiles {
				out.Truncated = true
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
		return text(summarizeProfiles(out)), mcperr.OK(out), nil
	})

	// onvif-go: (*Client).GetStreamURI, media.go.
	Add(srv, &mcp.Tool{
		Name: "media.stream_uri",
		Description: "Get the RTSP stream URI for a profile. Credentials are never included, in the URI or " +
			"anywhere else; they stay server-side. The URI is the address the camera reports, which may be " +
			"an internal one; this tool does not open the stream. invalid_after_connect and " +
			"invalid_after_reboot say whether the camera drops the URI after a connection or a reboot. " +
			"Known secret keys, registered passwords and the fragment are removed from the URI, but a secret " +
			"embedded in the URI path cannot be detected.",
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
		if len(u.URI) > maxURIChars {
			return fail[StreamURIData](&mcperr.ToolError{
				Code: mcperr.CodeDeviceFault, Camera: in.Camera, Operation: "GetStreamURI",
				Message: "the camera returned a stream URI longer than onvif-mcp accepts",
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
			URI:                 dropFragment(red.String()),
			CredentialsRequired: true,
			InvalidAfterConnect: u.InvalidAfterConnect,
			InvalidAfterReboot:  u.InvalidAfterReboot,
		}
		return text("Stream URI for profile " + in.Profile + ": " + data.URI + " (credentials held server-side)."),
			mcperr.OK(data), nil
	})
}
