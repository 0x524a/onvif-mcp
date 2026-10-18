package tools

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg" // registers the JPEG decoder image.DecodeConfig uses
	_ "image/png"  // registers the PNG decoder image.DecodeConfig uses
	"net/http"
	"strings"
	"time"

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
	case registry.RefusedSnapshotSchemeDowngrade:
		return snapshotFault(camera, snapshotFetchOp, "camera is configured with an https endpoint but advertised an http snapshot address",
			"onvif-mcp never offers the camera's credentials over plain http to a camera it reaches over https, "+
				"so nothing was requested. The camera's snapshot setting should serve https, or the operator can "+
				"configure an http endpoint for it if the network is trusted")
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
		if se.Size >= 0 {
			te.Message = fmt.Sprintf("the snapshot is %d bytes, over the %d byte limit", se.Size, se.Limit)
		} else {
			te.Message = fmt.Sprintf("the snapshot is larger than the %d byte limit", se.Limit)
		}
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
	case registry.SnapshotBasicOverHTTP:
		te.Code = mcperr.CodeAuthFailed
		te.Hint = "the snapshot address over plain http offers only HTTP Basic, which would send the password in " +
			"cleartext, so it was not sent. The operator can set allow_basic_over_http for this camera in the " +
			"config if the network is trusted, or the camera's web authentication can be switched to Digest or " +
			"its snapshots served over https"
	case registry.SnapshotMalformedReply:
		te.Code = mcperr.CodeDeviceFault
		te.Message = "the camera's snapshot server sent a reply that is not valid HTTP"
		te.Hint = "the camera's snapshot server is misbehaving; pick another profile from media.profiles, or have " +
			"the camera checked"
	case registry.SnapshotUntrustedCertificate:
		te.Code = mcperr.CodeDeviceFault
		te.Message = "the snapshot address's certificate is not trusted"
		te.Hint = "the snapshot address uses https with a certificate onvif-mcp does not trust (self-signed or " +
			"from an unknown authority, or not valid for that host). That is for the operator to fix: the camera " +
			"needs a certificate from a trusted CA, or snapshots served over http. onvif-mcp has no option to " +
			"skip certificate verification, and your input is not the cause"
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
		return "the camera does not serve the snapshot address it advertised for this profile; check media.profiles and pick another profile"
	case http.StatusRequestTimeout, http.StatusGatewayTimeout, http.StatusBadGateway, http.StatusServiceUnavailable:
		return "the camera or a gateway in front of it is busy or unavailable; retry shortly"
	case http.StatusTooManyRequests:
		return "the camera is limiting snapshot requests; ask for snapshots less often, and do not repeat the call in a loop"
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
// Trailing NUL padding (some cameras pad) is trimmed. A JPEG must reach its
// end-of-image marker and a PNG its IEND chunk, and whatever follows is cut, so
// a truncated frame is refused and a payload appended after a valid image never
// reaches the agent. The returned slice is the image alone.
//
// The header is parsed with image.DecodeConfig, which reads dimensions without
// decoding pixels, so a 1 MiB file cannot make this allocate a large bitmap.
// The pixel data itself is not decoded.
func sniffImage(camera string, b []byte) (data []byte, mime string, w, h int, te *mcperr.ToolError) {
	const loginHint = "the camera answered with something that is not a JPEG or PNG image, for example a login or " +
		"error page; check the configured credentials and the camera's snapshot setting. The reply is not shown"
	switch http.DetectContentType(b) {
	case "image/jpeg":
		mime = "image/jpeg"
	case "image/png":
		mime = "image/png"
	default:
		return nil, "", 0, 0, notAnImage(camera, loginHint)
	}
	b = bytes.TrimRight(b, "\x00")
	end := -1
	if mime == "image/jpeg" {
		end = jpegEnd(b)
	} else {
		end = pngEnd(b)
	}
	if end < 0 {
		return nil, "", 0, 0, notAnImage(camera, "the data begins like a JPEG or PNG but is not a complete image; the "+
			"camera may be sending a truncated or corrupt frame; if it keeps doing so, pick another profile from media.profiles")
	}
	b = b[:end]
	cfg, format, err := image.DecodeConfig(bytes.NewReader(b))
	if err != nil || (mime == "image/jpeg") != (format == "jpeg") || (mime == "image/png") != (format == "png") {
		return nil, "", 0, 0, notAnImage(camera, "the data begins like a JPEG or PNG but is not a complete, valid image; "+
			"the camera may be sending a truncated or corrupt frame; if it keeps doing so, pick another profile from media.profiles")
	}
	if cfg.Width < 1 || cfg.Height < 1 || cfg.Width > maxSnapshotSide || cfg.Height > maxSnapshotSide ||
		int64(cfg.Width)*int64(cfg.Height) > maxSnapshotPixels {
		return nil, "", 0, 0, snapshotFault(camera, snapshotFetchOp,
			"the snapshot declares dimensions that onvif-mcp refuses to return",
			fmt.Sprintf("an image larger than %d pixels on a side or %d megapixels is refused; the camera is "+
				"misbehaving, or pick another profile from media.profiles", maxSnapshotSide, maxSnapshotPixels/1_000_000))
	}
	return b, mime, cfg.Width, cfg.Height, nil
}

// jpegEnd returns the offset just past the end-of-image marker of the JPEG at
// the start of b, or -1 if b does not reach one. It walks the marker segments
// (an embedded thumbnail inside an APPn segment has its own EOI and is skipped
// whole) and, after a start-of-scan, scans the entropy-coded data for the next
// marker. If the structure cannot be walked, b is accepted only when it ends in
// FF D9, which keeps odd but complete frames working.
func jpegEnd(b []byte) int {
	if end := jpegWalk(b); end > 0 {
		return end
	}
	if n := len(b); n >= 4 && b[n-2] == 0xFF && b[n-1] == 0xD9 {
		return n
	}
	return -1
}

func jpegWalk(b []byte) int {
	i := 2 // past SOI
	for i < len(b) {
		if b[i] != 0xFF {
			return -1
		}
		for i < len(b) && b[i] == 0xFF { // fill bytes
			i++
		}
		if i >= len(b) {
			return -1
		}
		m := b[i]
		i++
		switch {
		case m == 0xD9:
			return i
		case m == 0x01 || (m >= 0xD0 && m <= 0xD8):
			continue // no length
		}
		if i+2 > len(b) {
			return -1
		}
		i += int(b[i])<<8 | int(b[i+1])
		if m != 0xDA {
			continue
		}
		// Entropy-coded data: FF 00 is a stuffed byte, FF D0..D7 a restart.
		for i < len(b) {
			if b[i] != 0xFF {
				i++
				continue
			}
			if i+1 >= len(b) {
				return -1
			}
			if n := b[i+1]; n == 0x00 || (n >= 0xD0 && n <= 0xD7) {
				i += 2
				continue
			}
			break
		}
	}
	return -1
}

// pngEnd returns the offset just past the IEND chunk of the PNG at the start
// of b, or -1 if the chunks do not reach one.
func pngEnd(b []byte) int {
	i := 8 // past the signature
	for i+12 <= len(b) {
		n := int(binary.BigEndian.Uint32(b[i:]))
		if n < 0 || n > len(b) {
			return -1
		}
		next := i + 12 + n
		if next > len(b) {
			return -1
		}
		if string(b[i+4:i+8]) == "IEND" {
			return next
		}
		i = next
	}
	return -1
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
	slots := make(chan struct{}, snapshotSlotCount(d, limit))
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
		Annotations: &mcp.ToolAnnotations{Title: "Capture snapshot", OpenWorldHint: boolPtr(true)},
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
		return takeSnapshot(ctx, d, in, limit, slots)
	}, nil)
}

// Concurrent snapshots. Each in-flight call holds the image several times over
// (the fetched bytes, their base64 form and the marshalled reply), so an
// agent that fires many calls at once could exhaust memory. At most this many
// fetch at a time; a call that cannot get a slot within snapshotSlotWait
// fails with a retryable timeout instead of queueing without bound.
const (
	defaultSnapshotSlots    = 4
	bigSnapshotSlots        = 2 // when the cap is above bigSnapshotCap
	bigSnapshotCap          = 2 << 20
	defaultSnapshotSlotWait = 2 * time.Second
)

func snapshotSlotCount(d Deps, limit int) int {
	switch {
	case d.snapshotSlots > 0:
		return d.snapshotSlots
	case limit > bigSnapshotCap:
		return bigSnapshotSlots
	}
	return defaultSnapshotSlots
}

// acquireSnapshotSlot takes a slot or returns the error to report.
func acquireSnapshotSlot(ctx context.Context, slots chan struct{}, d Deps, camera string) (func(), *mcperr.ToolError) {
	release := func() { <-slots }
	select {
	case slots <- struct{}{}:
		return release, nil
	default:
	}
	wait := d.snapshotSlotWait
	if wait <= 0 {
		wait = defaultSnapshotSlotWait
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case slots <- struct{}{}:
		return release, nil
	case <-ctx.Done():
		return nil, mcperr.FromError(ctx.Err(), camera, snapshotFetchOp)
	case <-timer.C:
		return nil, &mcperr.ToolError{
			Code: mcperr.CodeTimeout, Retryable: true, Camera: camera, Operation: snapshotFetchOp,
			Message: "too many camera.snapshot calls are running at once",
			Hint: "other snapshots are still being taken, and each one holds a full image in memory; wait a few " +
				"seconds and call camera.snapshot again, and take snapshots one after another rather than in parallel",
		}
	}
}

func takeSnapshot(ctx context.Context, d Deps, in ProfileIn, limit int, slots chan struct{}) (*mcp.CallToolResult, mcperr.Out[SnapshotData], error) {
	ctx, cancel := d.Scope(ctx)
	defer cancel()
	if d.snapshotHook != nil {
		d.snapshotHook()
	}
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

	release, te := acquireSnapshotSlot(ctx, slots, d, camera)
	if te != nil {
		return fail[SnapshotData](te)
	}
	defer release()

	body, err := e.FetchSnapshot(ctx, u.URI, int64(limit), e.Timeout())
	if err != nil {
		return fail[SnapshotData](snapshotFetchError(in.Camera, err))
	}
	img, mime, w, h, te := sniffImage(camera, body.Data)
	if te != nil {
		return fail[SnapshotData](te)
	}
	profile := cleanString(in.Profile, maxFieldRunes)
	// The summary comes first so a host that shows only the first block still
	// says what the image is. The image holds the raw bytes (the SDK base64-
	// encodes them on the wire); they are not text, so neither the sanitiser
	// nor Scrub touches them.
	res := &mcp.CallToolResult{Content: []mcp.Content{
		&mcp.TextContent{Text: snapshotSummary(mime, w, h, len(img), profile)},
		&mcp.ImageContent{Data: img, MIMEType: mime},
	}}
	return res, mcperr.OK(SnapshotData{
		Bytes: len(img), MIMEType: mime, Width: w, Height: h, Profile: profile,
	}), nil
}
