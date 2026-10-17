package tools

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	onvif "github.com/0x524a/onvif-go"
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
	Token       string `json:"token" jsonschema:"the profile token; pass it as profile to media.stream_uri, ptz.status and ptz.presets"`
	Name        string `json:"name,omitempty" jsonschema:"human-readable profile name; absent means the camera did not report one"`
	HasPTZ      bool   `json:"has_ptz" jsonschema:"true when the camera attached a PTZ configuration to this profile, so the PTZ tools are worth trying on it; this is the camera's claim, not a tested capability"`
	Encoding    string `json:"encoding,omitempty" jsonschema:"video codec as the camera names it, for example H264, H265 or JPEG; absent means not reported"`
	Width       int    `json:"width,omitempty" jsonschema:"video width in pixels; absent means not reported"`
	Height      int    `json:"height,omitempty" jsonschema:"video height in pixels; absent means not reported"`
	Framerate   int    `json:"framerate,omitempty" jsonschema:"configured frame rate limit in frames per second (a cap, not a measured rate); absent means not reported"`
	SourceToken string `json:"video_source_token,omitempty" jsonschema:"token of the video source feeding this profile; pass it as source_token to imaging.settings; absent means not reported"`
}

// ProfilesData is the media.profiles result.
type ProfilesData struct {
	Profiles []ProfileSummary `json:"profiles" jsonschema:"the camera's media profiles in the order it reported them, at most 100, one per token"`
	// Total is the number of distinct profile tokens the camera reported.
	Total int `json:"total" jsonschema:"number of distinct profile tokens the camera reported, which can exceed the length of profiles"`
	// Truncated is true when Total exceeds the number listed.
	Truncated bool `json:"truncated" jsonschema:"true when total is larger than the number of profiles listed"`
	// DuplicatesDropped counts profiles dropped for repeating an earlier token;
	// the first is kept.
	DuplicatesDropped int `json:"duplicates_dropped,omitempty" jsonschema:"number of profiles left out because they repeated an earlier token; absent means none"`
}

// StreamURIData is the media.stream_uri result. The URI is redacted; the
// server holds the credentials needed to play it.
type StreamURIData struct {
	URI                 string `json:"uri" sanitize:"noclip" jsonschema:"the RTSP URI the camera reported, with credentials, secret-looking query values and the fragment removed; it may name an address that is internal to the camera's network; this tool does not open it"`
	InvalidAfterConnect bool   `json:"invalid_after_connect" jsonschema:"true when the camera says the URI stops working after one connection, so fetch a fresh one each time"`
	InvalidAfterReboot  bool   `json:"invalid_after_reboot" jsonschema:"true when the camera says the URI stops working after the camera reboots"`
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

// profilesOf reduces the camera's profile list. Nil entries are skipped, a
// repeated token keeps its first occurrence, and the list is capped at
// maxProfiles with Total and Truncated reporting the rest.
func profilesOf(ps []*onvif.Profile) ProfilesData {
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
		// Cleaned here, not only at the choke point: the text summary is built
		// from these values before the choke point runs.
		s := ProfileSummary{Token: tok, Name: cleanString(p.Name, maxFieldRunes), HasPTZ: p.PTZConfiguration != nil}
		if v := p.VideoEncoderConfiguration; v != nil {
			s.Encoding = cleanString(v.Encoding, maxFieldRunes)
			if v.RateControl != nil {
				s.Framerate = v.RateControl.FrameRateLimit
			}
			if v.Resolution != nil {
				s.Width, s.Height = v.Resolution.Width, v.Resolution.Height
			}
		}
		if p.VideoSourceConfiguration != nil {
			s.SourceToken = cleanString(p.VideoSourceConfiguration.SourceToken, maxFieldRunes)
		}
		out.Profiles = append(out.Profiles, s)
	}
	return out
}

// streamURIOf validates and redacts a camera-reported stream URI. Every
// failure is a device_fault with a fixed message: the URI itself may carry a
// secret, so it is never echoed.
func streamURIOf(camera string, u *onvif.MediaURI) (StreamURIData, *mcperr.ToolError) {
	fault := func(msg, hint string) (StreamURIData, *mcperr.ToolError) {
		return StreamURIData{}, &mcperr.ToolError{
			Code: mcperr.CodeDeviceFault, Camera: camera, Operation: "GetStreamURI", Message: msg, Hint: hint,
		}
	}
	if u == nil || u.URI == "" {
		return fault("the camera returned no stream URI for this profile", profilesHint)
	}
	if len(u.URI) > maxURIChars {
		return fault("the camera returned a stream URI longer than onvif-mcp accepts", "")
	}
	red, err := redact.Parse(u.URI)
	if err != nil {
		return fault("the camera returned a stream URI that could not be parsed", "")
	}
	return StreamURIData{
		URI:                 dropFragment(red.String()),
		InvalidAfterConnect: u.InvalidAfterConnect,
		InvalidAfterReboot:  u.InvalidAfterReboot,
	}, nil
}

// RegisterMedia registers media.profiles and media.stream_uri.
func RegisterMedia(srv *mcp.Server, d Deps) {
	// onvif-go: (*Client).GetProfiles, media.go.
	readTool(srv, d, &mcp.Tool{
		Name: "media.profiles",
		Description: "Use this after camera.list to learn a camera's media profiles; it is the source of the " +
			"profile tokens and source tokens the other tools ask for. Each profile has token (pass it as " +
			"profile to media.stream_uri, ptz.status and ptz.presets), has_ptz (pick a profile where it is " +
			"true for the PTZ tools) and, when the camera reports them, name, encoding, width, height, " +
			"framerate and video_source_token (pass it as source_token to imaging.settings). An absent field " +
			"means the camera did not report it. At most 100 profiles are listed; total and truncated say " +
			"when there were more. Does not open any stream, does not test that a profile works, and " +
			"does not change anything.",
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
		out := profilesOf(ps)
		return text(summarizeProfiles(out)), mcperr.OK(out), nil
	})

	// onvif-go: (*Client).GetStreamURI, media.go.
	readTool(srv, d, &mcp.Tool{
		Name: "media.stream_uri",
		Description: "Use this after media.profiles to get the RTSP address of a profile, for example to hand " +
			"to a human or a player. Credentials are never included, in the URI or anywhere else; they stay " +
			"server-side, so a player must be given them separately if the camera wants them. The URI is the " +
			"address the camera reports, which may be an internal one. invalid_after_connect and " +
			"invalid_after_reboot say whether the camera drops the URI after a connection or a reboot. " +
			"Known secret keys, registered passwords and the fragment are removed from the URI, but a secret " +
			"embedded in the URI path cannot be detected. Does not open the stream, does not check that " +
			"video flows, and does not say whether the stream needs credentials.",
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
		data, te := streamURIOf(in.Camera, u)
		if te != nil {
			return fail[StreamURIData](te)
		}
		return text("Stream URI for profile " + in.Profile + ": " + data.URI + " (credentials held server-side)."),
			mcperr.OK(data), nil
	})
}
