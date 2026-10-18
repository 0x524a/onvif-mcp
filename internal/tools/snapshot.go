package tools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg" // registers the JPEG decoder image.DecodeConfig uses
	_ "image/png"  // registers the PNG decoder image.DecodeConfig uses
	"net/http"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
)

// Snapshot size limits. The cap is raw bytes: base64 inflates by a third and
// the bytes land in the agent's context window, so it protects the context
// budget at least as much as memory.
const (
	// DefaultSnapshotMaxBytes is the cap when the operator sets none.
	DefaultSnapshotMaxBytes = 1 << 20
	// MinSnapshotMaxBytes and MaxSnapshotMaxBytes bound what the operator may set.
	MinSnapshotMaxBytes = 1 << 10
	MaxSnapshotMaxBytes = 8 << 20

	// maxSnapshotSide and maxSnapshotPixels refuse an image whose header
	// declares absurd dimensions: a 1 MiB file can claim 65535x65535, and an
	// agent or a viewer that decodes it would allocate gigabytes.
	maxSnapshotSide   = 16384
	maxSnapshotPixels = 64_000_000

	snapshotURIOp   = "GetSnapshotURI"
	snapshotFetchOp = "FetchSnapshot"
)

// CheckSnapshotMaxBytes validates an operator-supplied snapshot cap.
func CheckSnapshotMaxBytes(n int) error {
	if n < MinSnapshotMaxBytes || n > MaxSnapshotMaxBytes {
		return fmt.Errorf("snapshot-max-bytes must be between %d and %d, got %d", MinSnapshotMaxBytes, MaxSnapshotMaxBytes, n)
	}
	return nil
}

// SnapshotData is the camera.snapshot result. The image itself is the result's
// ImageContent; this is the metadata about it. It never holds the snapshot
// address.
type SnapshotData struct {
	Bytes     int    `json:"bytes" jsonschema:"size of the image in bytes, as returned in the image content"`
	MIMEType  string `json:"mime_type" jsonschema:"image/jpeg or image/png, determined from the image bytes themselves, not from anything the camera claimed"`
	Width     int    `json:"width" jsonschema:"image width in pixels, read from the image header"`
	Height    int    `json:"height" jsonschema:"image height in pixels, read from the image header"`
	Profile   string `json:"profile" jsonschema:"the profile token the snapshot was taken from"`
	Truncated bool   `json:"truncated" jsonschema:"always false: an image over the size limit is refused, never cut"`
}

// snapshotSchema is the schema the SDK would infer for ProfileIn, plus
// minLength 1 on both tokens.
func snapshotSchema() *jsonschema.Schema {
	s, err := jsonschema.For[ProfileIn](nil)
	if err != nil {
		panic("tools: camera.snapshot input schema: " + err.Error())
	}
	one := 1
	for _, k := range []string{"camera", "profile"} {
		p, ok := s.Properties[k]
		if !ok {
			panic("tools: camera.snapshot input schema has no property " + k)
		}
		p.MinLength = &one
	}
	return s
}

func snapshotFault(camera, op, msg, hint string) *mcperr.ToolError {
	return &mcperr.ToolError{Code: mcperr.CodeDeviceFault, Camera: camera, Operation: op, Message: msg, Hint: hint}
}

const noSnapshotHint = "this profile has no snapshot; try another profile from media.profiles, or use media.stream_uri and stream.inspect to look at the stream"

// snapshotURIError maps a GetSnapshotUri failure. A camera without snapshot
// support answers with a SOAP fault, not with onvif-go's sentinel, so the
// fault is read for it; the sentinel is handled by mcperr.
func snapshotURIError(camera string, err error) *mcperr.ToolError {
	te := withHint(mcperr.FromError(err, camera, snapshotURIOp), profilesHint)
	if te.Code == mcperr.CodeNotSupported {
		te.Hint = noSnapshotHint
	}
	if te.Code == mcperr.CodeDeviceFault && te.SOAP != nil {
		r := strings.ToLower(te.SOAP.Code + " " + te.SOAP.Reason)
		if strings.Contains(r, "snapshot") && (strings.Contains(r, "not supported") ||
			strings.Contains(r, "unsupported") || strings.Contains(r, "not implemented")) ||
			strings.Contains(r, "actionnotsupported") {
			te.Code, te.Retryable, te.Hint = mcperr.CodeNotSupported, false, noSnapshotHint
		}
	}
	return te
}

// snapshotRefusalError maps an address refusal. Nothing was sent.
func snapshotRefusalError(camera string, r *registry.SnapshotRefusal) *mcperr.ToolError {
	switch r.Kind {
	case registry.RefusedSnapshotForeignHost:
		return snapshotFault(camera, snapshotFetchOp, "camera advertised a snapshot address on another host",
			"onvif-mcp does not send credentials to, or open connections to, a host other than the camera's "+
				"configured address, so nothing was requested. If this camera really serves snapshots from "+
				"another host, the operator can set trust_advertised_hosts for it in the config (the snapshot "+
				"is then requested without credentials)")
	case registry.RefusedSnapshotBlockedAddress:
		return snapshotFault(camera, snapshotFetchOp, "camera advertised a snapshot address that onvif-mcp never contacts",
			"unspecified, multicast, broadcast, link-local and numeric-spelled addresses are refused even when "+
				"trust_advertised_hosts is set; nothing was requested")
	default:
		return snapshotFault(camera, snapshotFetchOp, "camera advertised a snapshot address that is not a usable http or https URL",
			"the scheme must be http or https and any port 1 to 65535; nothing was requested")
	}
}

// snapshotFetchError maps a failed fetch onto the taxonomy. It classifies on
// the registry's typed result or on the transport error, never on anything the
// camera wrote in a reply body.
func snapshotFetchError(camera string, err error) *mcperr.ToolError {
	var ref *registry.SnapshotRefusal
	if errors.As(err, &ref) {
		return snapshotRefusalError(camera, ref)
	}
	var se *registry.SnapshotError
	if !errors.As(err, &se) {
		return mcperr.FromError(err, camera, snapshotFetchOp)
	}
	te := &mcperr.ToolError{Camera: camera, Operation: snapshotFetchOp, Message: se.Error()}
	switch se.Kind {
	case registry.SnapshotTooLarge:
		te.Code = mcperr.CodeInvalidArgument
		size := "more than " + fmt.Sprint(se.Limit) + " bytes"
		if se.Size >= 0 {
			size = fmt.Sprintf("%d bytes", se.Size)
		}
		te.Message = fmt.Sprintf("the snapshot is %s, over the %d byte limit", size, se.Limit)
		te.Hint = "pick a lower-resolution profile from media.profiles (or lower the resolution or quality of this " +
			"one on the camera), or ask the operator to raise -snapshot-max-bytes; nothing was returned"
	case registry.SnapshotRedirected:
		te.Code = mcperr.CodeDeviceFault
		te.Hint = "the snapshot address answered with a redirect, which onvif-mcp never follows because it could " +
			"send the camera's credentials to another host; the camera's snapshot setup may need fixing"
	case registry.SnapshotUnauthorized:
		te.Code = mcperr.CodeAuthFailed
		te.Hint = "the snapshot address requires credentials, none were offered because it is on another host than " +
			"the camera's configured address, and onvif-mcp never sends the camera's credentials to another host"
	case registry.SnapshotCredentialsRejected:
		te.Code = mcperr.CodeAuthFailed
		te.Hint = "verify the username and password configured for this camera; the snapshot address rejected them"
	case registry.SnapshotAuthUnsupported:
		te.Code = mcperr.CodeAuthFailed
		te.Hint = "the snapshot address asked for an authentication method onvif-mcp does not support (it supports " +
			"HTTP Basic and Digest with qop auth); the camera's web authentication setting may need changing"
	case registry.SnapshotForbidden:
		te.Code = mcperr.CodeAuthFailed
		te.Hint = "the camera refused access to snapshots; the configured user may lack permission to view them"
	default:
		te.Code = statusCode(se.Status)
		te.Hint = statusHint(se.Status)
	}
	te.Retryable = te.Code.Retryable()
	return te
}

// statusCode classifies an unexpected HTTP status of the snapshot request.
func statusCode(status int) mcperr.Code {
	switch status {
	case http.StatusNotImplemented:
		return mcperr.CodeNotSupported
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return mcperr.CodeTimeout
	case http.StatusBadGateway, http.StatusServiceUnavailable:
		return mcperr.CodeUnreachable
	}
	return mcperr.CodeDeviceFault
}

func statusHint(status int) string {
	switch status {
	case http.StatusNotImplemented:
		return noSnapshotHint
	case http.StatusNotFound, http.StatusGone:
		return "the camera no longer serves the snapshot address it advertised; call camera.snapshot again to get a fresh one, and check media.profiles"
	case http.StatusRequestTimeout, http.StatusGatewayTimeout, http.StatusBadGateway, http.StatusServiceUnavailable:
		return "the camera or a gateway in front of it is busy or unavailable; retry shortly"
	case http.StatusTooManyRequests:
		return "the camera is limiting snapshot requests; wait before trying again"
	}
	return "the snapshot address answered with an unexpected HTTP status; the camera may be misconfigured"
}

func notAnImage(camera, hint string) *mcperr.ToolError {
	return snapshotFault(camera, snapshotFetchOp, "the snapshot address did not return an image", hint)
}

// sniffImage decides what the bytes are. The reply's Content-Type is never
// consulted: it is the camera's word, and an HTML login page is routinely
// served 200 with an image type. Only JPEG and PNG are returned to the agent.
// GIF and WebP are refused: ONVIF snapshots are JPEG (PNG is rare but legal),
// the standard library cannot read WebP headers, and an animated GIF is not a
// still. SVG and HTML sniff as text and are refused, which also keeps active
// content out of the agent's context.
//
// The header is parsed with image.DecodeConfig, which reads dimensions without
// decoding pixels, so a 1 MiB file cannot make this allocate a large bitmap.
// The pixel data itself is not decoded; a truncated image with a valid header
// is returned as is.
func sniffImage(camera string, b []byte) (mime string, w, h int, te *mcperr.ToolError) {
	const loginHint = "the camera answered with something that is not a JPEG or PNG image, for example a login or " +
		"error page; check the configured credentials and the camera's snapshot setting. The reply is not shown"
	switch http.DetectContentType(b) {
	case "image/jpeg":
		mime = "image/jpeg"
	case "image/png":
		mime = "image/png"
	default:
		return "", 0, 0, notAnImage(camera, loginHint)
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(b))
	if err != nil || (mime == "image/jpeg") != (format == "jpeg") || (mime == "image/png") != (format == "png") {
		return "", 0, 0, notAnImage(camera, "the data begins like a JPEG or PNG but its header is not a valid image; "+
			"the camera may be sending a truncated or corrupt frame, so retry once")
	}
	if cfg.Width < 1 || cfg.Height < 1 || cfg.Width > maxSnapshotSide || cfg.Height > maxSnapshotSide ||
		int64(cfg.Width)*int64(cfg.Height) > maxSnapshotPixels {
		return "", 0, 0, snapshotFault(camera, snapshotFetchOp,
			"the snapshot declares dimensions that onvif-mcp refuses to return",
			fmt.Sprintf("an image larger than %d pixels on a side or %d megapixels is refused; the camera is "+
				"misbehaving, or pick another profile from media.profiles", maxSnapshotSide, maxSnapshotPixels/1_000_000))
	}
	return mime, cfg.Width, cfg.Height, nil
}

func snapshotSummary(mime string, w, h, n int, profile string) string {
	kind := "JPEG"
	if mime == "image/png" {
		kind = "PNG"
	}
	return fmt.Sprintf("%s %dx%d, %d bytes from profile %s.", kind, w, h, n, profile)
}

// RegisterSnapshot registers camera.snapshot. The cap is d.SnapshotMaxBytes,
// or DefaultSnapshotMaxBytes when that is not positive; range validation of an
// operator's value is CheckSnapshotMaxBytes, applied where the flag is read.
//
// onvif-go v1.2.0: (*Client).GetSnapshotURI, media.go, returns the address the
// camera reports. The bytes are NOT fetched with (*Client).DownloadFile,
// client.go: it sends Basic credentials unprompted to the camera-chosen host,
// its Digest fallback builds an unguarded client that follows redirects, and it
// reads the body without a limit (see the comment at the top of
// registry/snapshot.go). registry.Entry.FetchSnapshot does the GET instead, so
// the credentials stay inside the registry and no accessor for them exists.
func RegisterSnapshot(srv *mcp.Server, d Deps) {
	limit := d.SnapshotMaxBytes
	if limit <= 0 {
		limit = DefaultSnapshotMaxBytes
	}
	GuardedTool(srv, d, safety.RiskRead, &mcp.Tool{
		Name: "camera.snapshot",
		Description: "Use this after media.profiles to see what a camera sees: it captures one still image from a " +
			"profile and returns it as an image together with a one-line summary and data with bytes, " +
			"mime_type (image/jpeg or image/png), width, height and profile. The image enters your context " +
			"window, so it is capped at " + fmt.Sprint(limit) + " bytes (default 1 MiB, set by the operator): a " +
			"larger one is refused with its size and a hint to pick a lower-resolution profile, never cut. " +
			"The camera's credentials are added by the server and never appear in the input or the result; " +
			"they are offered only to the camera's own host, and only after it asks for them. If the camera " +
			"advertises its snapshot address on another host the call is refused as device_fault without any " +
			"request, unless the operator set trust_advertised_hosts for the camera, in which case that " +
			"host is fetched without credentials (so it must serve snapshots unauthenticated). Redirects are " +
			"not followed. Anything that is not a valid JPEG or PNG, such as a login page, is refused as " +
			"device_fault. A camera without snapshot support gives not_supported. Does not record or stream " +
			"video, does not move the camera, and does not change anything; use stream.inspect for codecs.",
		InputSchema: snapshotSchema(),
		Annotations: &mcp.ToolAnnotations{Title: "Capture snapshot"},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ProfileIn) (res *mcp.CallToolResult, out mcperr.Out[SnapshotData], err error) {
		defer func() {
			if r := recover(); r != nil {
				// Neither logged nor returned: the value can hold anything.
				res, out, err = fail[SnapshotData](&mcperr.ToolError{
					Code: mcperr.CodeInternal, Camera: redactCamera(in.Camera), Operation: "camera.snapshot",
					Message: "the tool failed unexpectedly",
				})
			}
		}()
		return takeSnapshot(ctx, d, in, limit)
	}, nil)
}

func takeSnapshot(ctx context.Context, d Deps, in ProfileIn, limit int) (*mcp.CallToolResult, mcperr.Out[SnapshotData], error) {
	ctx, cancel := d.Scope(ctx)
	defer cancel()
	camera := redactCamera(in.Camera)

	c, te := d.client(ctx, in.Camera, snapshotURIOp)
	if te != nil {
		return fail[SnapshotData](te)
	}
	e, gerr := d.Reg.Get(in.Camera)
	if gerr != nil {
		return fail[SnapshotData](mcperr.FromError(gerr, in.Camera, snapshotURIOp))
	}
	// onvif-go: (*Client).GetSnapshotURI, media.go.
	u, err := c.GetSnapshotURI(ctx, in.Profile)
	if err != nil {
		return fail[SnapshotData](snapshotURIError(in.Camera, err))
	}
	if u == nil || u.URI == "" {
		return fail[SnapshotData](snapshotFault(camera, snapshotURIOp,
			"the camera returned no snapshot address for this profile", noSnapshotHint))
	}

	body, err := e.FetchSnapshot(ctx, u.URI, int64(limit), e.Timeout())
	if err != nil {
		return fail[SnapshotData](snapshotFetchError(in.Camera, err))
	}
	mime, w, h, te := sniffImage(camera, body.Data)
	if te != nil {
		return fail[SnapshotData](te)
	}
	profile := cleanString(in.Profile, maxFieldRunes)
	// The summary comes first so a host that shows only the first block still
	// says what the image is. The image holds the raw bytes (the SDK base64-
	// encodes them on the wire); they are not text, so neither the sanitiser
	// nor Scrub touches them.
	res := &mcp.CallToolResult{Content: []mcp.Content{
		&mcp.TextContent{Text: snapshotSummary(mime, w, h, len(body.Data), profile)},
		&mcp.ImageContent{Data: body.Data, MIMEType: mime},
	}}
	return res, mcperr.OK(SnapshotData{
		Bytes: len(body.Data), MIMEType: mime, Width: w, Height: h, Profile: profile,
	}), nil
}
