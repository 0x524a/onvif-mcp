package tools

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/probe"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
)

const (
	defaultStreamSeconds = 5
	maxStreamSeconds     = 10
	streamOp             = "DescribeStream"
)

// StreamInspectIn is the stream.inspect input.
type StreamInspectIn struct {
	Camera         string `json:"camera" jsonschema:"the camera id, taken from camera.list (its id field)"`
	Profile        string `json:"profile" jsonschema:"a profile token, taken from media.profiles (its token field)"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"how long to wait for the stream to answer, in whole seconds; omit for the default of 5; values above 10 are treated as 10; 1 is the smallest accepted value"`
}

// TrackInfo is one media track of the stream.
type TrackInfo struct {
	Index  int    `json:"index" jsonschema:"position of the track in the stream description, starting at 0"`
	Type   string `json:"type" jsonschema:"track kind as the stream names it, for example video, audio or application"`
	Format string `json:"format,omitempty" jsonschema:"codec as the stream names it, for example H264, H265 or PCMA; absent means not reported"`
	Width  int    `json:"width,omitempty" jsonschema:"video width in pixels, parsed from the stream's own parameter data; absent means it could not be determined"`
	Height int    `json:"height,omitempty" jsonschema:"video height in pixels, parsed from the stream's own parameter data; absent means it could not be determined"`
}

// InspectData is the stream.inspect result. It never contains the probed URL
// with credentials, and no credential in any form.
type InspectData struct {
	Stream        string      `json:"stream" sanitize:"noclip" jsonschema:"the stream address that was probed: scheme, host, port and path only, with no credentials and no query"`
	Authenticated bool        `json:"authenticated" jsonschema:"true when the camera's configured credentials were offered to the stream (the stream is on the camera's own host); false when the stream was probed without credentials"`
	Reachable     bool        `json:"reachable" jsonschema:"true when a connection to the stream endpoint was made"`
	DescribeOK    bool        `json:"describe_ok" jsonschema:"true when the stream answered the RTSP DESCRIBE request with a usable description"`
	Protocol      string      `json:"protocol,omitempty" jsonschema:"the protocol the stream spoke, for example rtsp"`
	LatencyMs     float64     `json:"latency_ms" jsonschema:"time the handshake took, in milliseconds; 0 when not reported"`
	Tracks        []TrackInfo `json:"tracks" jsonschema:"the stream's media tracks in the order it described them, at most 32"`
	Note          string      `json:"note" jsonschema:"how far to trust width and height: they are best-effort, parsed from the stream's parameter sets, and missing when the stream did not carry them"`
}

const resolutionNote = "width and height are best-effort, parsed from the stream's H.264/H.265 parameter sets; a track without them has an unknown resolution, not a zero one"

// streamSchema is the schema the SDK would infer for StreamInspectIn, plus
// minLength 1 on both tokens and a minimum of 1 on the timeout.
func streamSchema() *jsonschema.Schema {
	s, err := jsonschema.For[StreamInspectIn](nil)
	if err != nil {
		panic("tools: stream.inspect input schema: " + err.Error())
	}
	one, minSecs := 1, 1.0
	for _, k := range []string{"camera", "profile"} {
		p, ok := s.Properties[k]
		if !ok {
			panic("tools: stream.inspect input schema has no property " + k)
		}
		p.MinLength = &one
	}
	p, ok := s.Properties["timeout_seconds"]
	if !ok {
		panic("tools: stream.inspect input schema has no property timeout_seconds")
	}
	p.Minimum = &minSecs
	return s
}

func streamFault(camera, msg, hint string) *mcperr.ToolError {
	return &mcperr.ToolError{
		Code: mcperr.CodeDeviceFault, Camera: camera, Operation: "GetStreamURI", Message: msg, Hint: hint,
	}
}

// refusalError maps a registry refusal to the taxonomy. Nothing is probed.
func refusalError(camera string, err error) *mcperr.ToolError {
	var r *registry.StreamRefusal
	if !errors.As(err, &r) {
		return streamFault(camera, "the camera's stream address could not be used", "")
	}
	switch r.Kind {
	case registry.RefusedForeignHost:
		return streamFault(camera, "camera advertised a stream address on another host",
			"onvif-mcp does not send credentials to, or open connections to, a host other than the camera's "+
				"configured address, so nothing was probed; media.stream_uri shows the address. If this camera "+
				"really streams from another host, the operator can set trust_advertised_hosts for it in the config "+
				"(the stream is then probed without credentials)")
	case registry.RefusedBlockedAddress:
		return streamFault(camera, "camera advertised a stream address that onvif-mcp never probes",
			"unspecified, multicast, broadcast, link-local and numeric-spelled addresses are refused even when "+
				"trust_advertised_hosts is set; nothing was probed")
	default:
		return streamFault(camera, "camera advertised a stream address that is not a usable rtsp or rtsps URL",
			"the scheme must be rtsp or rtsps and any port 1 to 65535; nothing was probed; "+
				"media.stream_uri shows the address the camera advertised")
	}
}

// scrubbedStreamErr carries probe error text with the credentials removed and
// keeps the original chain for errors.Is, which mcperr.FromStreamError uses.
type scrubbedStreamErr struct {
	msg string
	err error
}

func (e *scrubbedStreamErr) Error() string { return e.msg }
func (e *scrubbedStreamErr) Unwrap() error { return e.err }

// inspectSummary is the text content block. It must survive redact.Scrub
// unchanged: a word such as "credentials" followed by a colon reads as a
// key/value secret and would replace the rest of the line, track list
// included, so the auth state sits in parentheses and no colon follows it.
func inspectSummary(d InspectData) string {
	auth := "probed without credentials"
	if d.Authenticated {
		auth = "probed with the camera's credentials"
	}
	if !d.DescribeOK {
		return fmt.Sprintf("Stream %s connected (%s) but it gave no usable description.", d.Stream, auth)
	}
	parts := make([]string, 0, len(d.Tracks))
	for _, t := range d.Tracks {
		s := t.Type
		if t.Format != "" {
			s += " " + t.Format
		}
		if t.Width > 0 && t.Height > 0 {
			s += fmt.Sprintf(" %dx%d", t.Width, t.Height)
		}
		parts = append(parts, s)
	}
	if len(parts) == 0 {
		return fmt.Sprintf("Stream %s was described (%s) with no tracks.", d.Stream, auth)
	}
	return fmt.Sprintf("Stream %s has %d track(s) (%s): %s. Resolution is best-effort.",
		d.Stream, len(parts), auth, joinWithin(parts, "; ", maxTextChars-160, len(parts)))
}

// streamHints adds the recovery advice mcperr cannot know: it depends on
// whether credentials were offered and on the timeout in force. The hints
// contain no colon (see inspectSummary) and no address.
func streamHints(te *mcperr.ToolError, err error, authenticated bool, secs int) *mcperr.ToolError {
	switch {
	case errors.Is(err, probe.ErrRedirected):
		te.Code = mcperr.CodeDeviceFault
		te.Retryable = te.Code.Retryable()
		te.Hint = "the stream answered with an RTSP redirect, which onvif-mcp never follows because it could send " +
			"the camera's credentials to another host; media.stream_uri shows the address the camera advertised"
	case errors.Is(err, probe.ErrEndedDuringDescribe):
		if authenticated {
			te.Hint = "the stream ended the connection during DESCRIBE; the camera's stream credentials may be wrong, " +
				"or the stream closed the connection for another reason"
		} else {
			te.Hint = "the stream ended the connection during DESCRIBE without credentials; it may require them " +
				"or be overloaded"
		}
	case te.Code == mcperr.CodeAuthFailed && !authenticated:
		te.Hint = "the stream requires credentials, none were offered because it is on another host than the " +
			"camera's configured address, and onvif-mcp never sends the camera's credentials to another host"
	case te.Code == mcperr.CodeTimeout:
		te.Hint = fmt.Sprintf("the stream did not answer within %d s; the wait is capped at %d s, so retry once "+
			"(optionally with a larger timeout_seconds, at most %d) and check that the camera is streaming",
			secs, maxStreamSeconds, maxStreamSeconds)
	case te.Code == mcperr.CodeNotFound:
		te.Hint = "the stream server answered but has nothing at this path, so the path may be wrong; " +
			"media.stream_uri shows the address the camera advertised and media.profiles lists the profiles"
	}
	return te
}

func trackInfos(r *probe.Result) []TrackInfo {
	out := make([]TrackInfo, 0, len(r.Tracks))
	for _, t := range r.Tracks {
		out = append(out, TrackInfo{
			Index: t.Index, Type: cleanString(t.Type, maxFieldRunes), Format: cleanString(t.Format, maxFieldRunes),
			Width: t.Width, Height: t.Height,
		})
	}
	return out
}

// RegisterStream registers stream.inspect.
//
// gortsplib v5: Client.Options and Client.Describe, driven by internal/probe
// (not rtspeek.DescribeStream, which follows redirects), through probe.Prober. This is the only tool that handles camera credentials outside
// the registry, and the only file allowed to call registry.Entry.PrepareStream
// or StreamProbe.CredentialedURL (a test enforces both).
func RegisterStream(srv *mcp.Server, d Deps) {
	prober := d.Prober
	if prober == nil {
		prober = probe.NewRTSP()
	}
	GuardedTool(srv, d, safety.RiskRead, &mcp.Tool{
		Name: "stream.inspect",
		Description: "Use this after media.profiles to learn what a profile's stream really carries: it opens the " +
			"profile's RTSP stream and runs the OPTIONS and DESCRIBE handshake, then reports reachable, " +
			"describe_ok, latency_ms and the tracks with their codec (format) and, for H.264 and H.265 video, " +
			"width and height. media.stream_uri only returns the address and checks nothing. Resolution is " +
			"best-effort: it is parsed from the stream's own parameter sets, and a track without it has an " +
			"unknown resolution. The camera's credentials are added by the server and never appear in the input " +
			"or the result, and they are offered only to the camera's own host: if the camera advertises a stream " +
			"on another host the call is refused as device_fault without probing, unless the operator set " +
			"trust_advertised_hosts for the camera, in which case that host is probed without credentials. " +
			"authenticated says which. timeout_seconds defaults to 5 and is clamped to 10; it is independent of " +
			"the camera's own timeout_seconds setting. A stream that answers with an RTSP redirect is not " +
			"followed and is reported as device_fault. At most 32 tracks " +
			"are listed. It connects to a stream endpoint, which is not the ONVIF service, so it is open-world. " +
			"Does not fetch frames, does not record, does not play or time the video, and does not change " +
			"the camera.",
		InputSchema: streamSchema(),
		Annotations: &mcp.ToolAnnotations{Title: "Inspect stream", OpenWorldHint: boolPtr(true)},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in StreamInspectIn) (res *mcp.CallToolResult, out mcperr.Out[InspectData], err error) {
		defer func() {
			if r := recover(); r != nil {
				// The panic value is neither logged nor returned: it can hold
				// the credentialed URL.
				res, out, err = fail[InspectData](&mcperr.ToolError{
					Code: mcperr.CodeInternal, Camera: redactCamera(in.Camera), Operation: streamOp,
					Message: "the tool failed unexpectedly",
				})
			}
		}()
		return inspectStream(ctx, d, prober, in)
	}, nil)
}

func redactCamera(s string) string { return cleanString(s, maxEchoedCamera) }

func inspectStream(ctx context.Context, d Deps, prober probe.Prober, in StreamInspectIn) (*mcp.CallToolResult, mcperr.Out[InspectData], error) {
	if in.TimeoutSeconds < 0 {
		return fail[InspectData](&mcperr.ToolError{
			Code: mcperr.CodeInvalidArgument, Camera: redactCamera(in.Camera), Operation: streamOp,
			Message: "timeout_seconds must not be negative",
			Hint:    fmt.Sprintf("omit it for the default of %ds, or pass 1 to %d", defaultStreamSeconds, maxStreamSeconds),
		})
	}
	secs := in.TimeoutSeconds
	if secs == 0 {
		secs = defaultStreamSeconds
	}
	if secs > maxStreamSeconds {
		secs = maxStreamSeconds
	}
	ctx, cancel := d.Scope(ctx)
	defer cancel()

	c, te := d.client(ctx, in.Camera, "GetStreamURI")
	if te != nil {
		return fail[InspectData](te)
	}
	e, gerr := d.Reg.Get(in.Camera)
	if gerr != nil {
		return fail[InspectData](mcperr.FromError(gerr, in.Camera, streamOp))
	}
	// onvif-go: (*Client).GetStreamURI, media.go.
	u, err := c.GetStreamURI(ctx, in.Profile)
	if err != nil {
		return fail[InspectData](withHint(mcperr.FromError(err, in.Camera, "GetStreamURI"), profilesHint))
	}
	if u == nil || u.URI == "" {
		return fail[InspectData](streamFault(in.Camera, "the camera returned no stream URI for this profile", profilesHint))
	}

	sp, perr := e.PrepareStream(u.URI)
	if perr != nil {
		return fail[InspectData](refusalError(in.Camera, perr))
	}
	res, err := prober.Describe(ctx, sp.CredentialedURL(), time.Duration(secs)*time.Second)
	if err != nil {
		// Scrubbed here as well as by the prober, and again by the sanitiser.
		clean := &scrubbedStreamErr{msg: sp.Scrub(err.Error()), err: err}
		return fail[InspectData](streamHints(mcperr.FromStreamError(clean, in.Camera, streamOp), err, sp.Authenticated(), secs))
	}
	if res == nil {
		return fail[InspectData](mcperr.FromStreamError(errors.New("stream probe returned no data"), in.Camera, streamOp))
	}
	res = probe.Bound(res)
	data := InspectData{
		Stream: sp.Display(), Authenticated: sp.Authenticated(),
		Reachable: res.Reachable, DescribeOK: res.DescribeOK, Protocol: res.Protocol,
		LatencyMs: res.LatencyMs, Tracks: trackInfos(res), Note: resolutionNote,
	}
	return text(strings.TrimSpace(inspectSummary(data))), mcperr.OK(data), nil
}
