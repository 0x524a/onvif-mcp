// Package tools implements the MCP tool surface over the camera registry.
//
// Every tool returns the mcperr.Out envelope as its structured result and a
// short, secret-free text summary as its content. The structured result
// carries the data; the text is for a human skimming a transcript.
package tools

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	onvif "github.com/0x524a/onvif-go"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/redact"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
)

// maxTextChars bounds every text summary.
const maxTextChars = 600

// Deps is what every tool needs.
type Deps struct {
	Reg *registry.Registry
	Log *slog.Logger
	// Base, when set, also cancels every tool call once it is done (shutdown).
	// The SDK derives handler contexts from the request, not from the Run
	// context, so without it a SIGTERM waits out a slow camera call.
	Base context.Context
	// Discover performs the WS-Discovery probe for camera.discover. Nil means
	// DefaultDiscoverer. It is injectable so tests never touch the network.
	Discover Discoverer
	// Policy gates write tools. Nil means read-only: GuardedTool registers no
	// write tool and the guard refuses everything.
	Policy *safety.Policy
}

// Scope returns a context cancelled when either ctx or d.Base is done.
func (d Deps) Scope(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	if d.Base == nil {
		return ctx, cancel
	}
	stop := context.AfterFunc(d.Base, cancel)
	// AfterFunc runs cancel on its own goroutine, so a Base that is already
	// done would leave ctx live for a while. Cancel synchronously instead.
	if d.Base.Err() != nil {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}

func boolPtr(b bool) *bool { return &b }

// ReadOnly builds annotations for a tool that cannot change device state and
// only talks to cameras an operator configured. All four hints are explicit
// because two of them are pointers the protocol reads as true when absent.
func ReadOnly(title string) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{
		Title:           title,
		ReadOnlyHint:    true,
		DestructiveHint: boolPtr(false),
		IdempotentHint:  true,
		OpenWorldHint:   boolPtr(false),
	}
}

// text builds a successful result carrying only a short text summary. The SDK
// still fills StructuredContent from the Out value; supplying Content stops it
// from dumping the whole JSON into the text as well.
func text(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: clip(redact.Scrub(s))}}}
}

// joinWithin joins parts with sep, keeping as many whole parts as fit in budget
// bytes. When parts are left out it ends with "(+N more; see structured
// result)" instead of a bare cut, so ids are never silently half-dropped. total
// is the number of items the caller's count covers, which can exceed len(parts)
// when the structured list itself was capped.
func joinWithin(parts []string, sep string, budget, total int) string {
	var b strings.Builder
	shown := 0
	for _, p := range parts {
		add := len(p)
		if shown > 0 {
			add += len(sep)
		}
		if b.Len()+add > budget {
			break
		}
		if shown > 0 {
			b.WriteString(sep)
		}
		b.WriteString(p)
		shown++
	}
	if more := total - shown; more > 0 {
		if shown > 0 {
			b.WriteString(sep)
		}
		fmt.Fprintf(&b, "(+%d more; see structured result)", more)
	}
	return b.String()
}

func clip(s string) string {
	if len(s) <= maxTextChars {
		return s
	}
	cut := maxTextChars
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut] + "..."
}

// fail builds the error triple for a handler: IsError set, the envelope in
// structured content, and a one-line text. te is already scrubbed by mcperr.
func fail[T any](te *mcperr.ToolError) (*mcp.CallToolResult, mcperr.Out[T], error) {
	line := fmt.Sprintf("%s: %s", te.Code, te.Message)
	if te.Hint != "" {
		line += " (" + te.Hint + ")"
	}
	if te.RetryAfterSeconds != nil {
		// The hint says to wait; hosts that show an agent only the text need the number.
		line += fmt.Sprintf(" [retry_after_seconds=%d]", *te.RetryAfterSeconds)
	}
	res := text(line)
	res.IsError = true
	return res, mcperr.Fail[T](te), nil
}

// client resolves a camera ID to an initialised client, translating both an
// unknown ID and a failed initialisation into the taxonomy.
func (d Deps) client(ctx context.Context, camera, op string) (*onvif.Client, *mcperr.ToolError) {
	e, err := d.Reg.Get(camera)
	if err != nil {
		if errors.Is(err, registry.ErrUnknownCamera) {
			return nil, &mcperr.ToolError{
				Code:      mcperr.CodeNotFound,
				Camera:    camera,
				Operation: op,
				Message:   "no camera with that id is configured",
				Hint:      "call camera.list to see the configured camera ids",
			}
		}
		return nil, mcperr.FromError(err, camera, op)
	}
	c, err := e.Client(ctx)
	if err != nil {
		// Connecting failed before op ran, so op is not what failed.
		return nil, mcperr.FromError(err, camera, "Initialize")
	}
	return c, nil
}

// withHint replaces the generic not_found hint with one that names the tool
// that lists valid values.
func withHint(te *mcperr.ToolError, hint string) *mcperr.ToolError {
	if te != nil && te.Code == mcperr.CodeNotFound {
		te.Hint = hint
	}
	return te
}

// CameraIn is the input shape shared by tools that address one camera.
type CameraIn struct {
	Camera string `json:"camera" jsonschema:"the camera id, taken from camera.list (its id field)"`
}

// ProfileIn addresses one media profile on one camera.
type ProfileIn struct {
	Camera  string `json:"camera" jsonschema:"the camera id, taken from camera.list (its id field)"`
	Profile string `json:"profile" jsonschema:"a profile token, taken from media.profiles (its token field); for PTZ tools choose a profile with has_ptz true"`
}

// SourceIn addresses one video source.
type SourceIn struct {
	Camera      string `json:"camera" jsonschema:"the camera id, taken from camera.list (its id field)"`
	SourceToken string `json:"source_token" jsonschema:"a video source token, taken from media.profiles (its video_source_token field, not the profile token)"`
}
