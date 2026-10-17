// Package mcpserver builds the MCP server and registers every tool.
package mcpserver

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/redact"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/tools"
)

// version is the server's reported version.
const version = "v0.1.0"

// Version returns the server version reported during initialisation.
func Version() string { return version }

// ListIn is the input for camera.list.
type ListIn struct {
	Probe bool `json:"probe,omitempty" jsonschema:"contact each camera and report reachable or unreachable"`
}

// ListData is what camera.list reports.
type ListData struct {
	Cameras []registry.Status `json:"cameras"`
}

// summarize renders a short, human-readable account of a camera listing. It
// is written from registry.Status fields only (ID, state, error code), none of
// which can carry a credential, and omits endpoints and error messages.
func summarize(cams []registry.Status) string {
	if len(cams) == 0 {
		return "No cameras are configured."
	}
	parts := make([]string, 0, len(cams))
	for _, c := range cams {
		s := c.ID
		switch {
		case c.State == "":
		case c.ErrorCode != "":
			s += fmt.Sprintf(" (%s: %s)", c.State, c.ErrorCode)
		default:
			s += fmt.Sprintf(" (%s)", c.State)
		}
		parts = append(parts, s)
	}
	return fmt.Sprintf("%d camera(s): %s. Full detail is in the structured result.",
		len(cams), strings.Join(parts, ", "))
}

// Option configures New.
type Option func(*options)

type options struct{ base context.Context }

// WithBaseContext makes every tool call also stop when base is done. The SDK
// derives handler contexts from the request, not from the Run context, so
// without this a SIGTERM during a slow camera probe waits out the probe.
func WithBaseContext(base context.Context) Option {
	return func(o *options) { o.base = base }
}

const argHint = "Pass a JSON object containing only the fields declared in the tool's inputSchema, with the declared types."

// maxArgErrChars bounds the validation message; the SDK text can echo the
// offending value.
const maxArgErrChars = 300

// argumentErrors is receiving middleware. go-sdk v1.7.0 (mcp/server.go,
// toolForErr) answers schema-validation failures with a plain-text error
// result that never reaches the handler; this rewrites exactly those results
// into the Out error envelope so an agent sees one error shape everywhere.
func argumentErrors(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		res, err := next(ctx, method, req)
		if err != nil || method != "tools/call" {
			return res, err
		}
		ctr, ok := res.(*mcp.CallToolResult)
		if !ok || ctr == nil || !ctr.IsError || ctr.StructuredContent != nil || len(ctr.Content) == 0 {
			return res, err
		}
		tc, ok := ctr.Content[0].(*mcp.TextContent)
		if !ok || !strings.HasPrefix(tc.Text, `validating "arguments"`) {
			return res, err
		}
		msg := redact.Scrub(tc.Text)
		if len(msg) > maxArgErrChars {
			msg = msg[:maxArgErrChars] + "..."
		}
		ctr.Content = []mcp.Content{&mcp.TextContent{Text: msg}}
		ctr.StructuredContent = mcperr.Fail[any](&mcperr.ToolError{
			Code:      mcperr.CodeInvalidArgument,
			Retryable: false,
			Message:   msg,
			Hint:      argHint,
		})
		return ctr, nil
	}
}

// New builds the server and registers the tool surface.
func New(reg *registry.Registry, log *slog.Logger, opts ...Option) *mcp.Server {
	var o options
	for _, f := range opts {
		f(&o)
	}
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "onvif-mcp",
		Version: version,
	}, nil)
	srv.AddReceivingMiddleware(argumentErrors)
	deps := tools.Deps{Reg: reg, Log: log, Base: o.base}

	// Always the generic free function mcp.AddTool, never the srv.AddTool
	// method: the method skips input validation and turns handler errors into
	// protocol errors instead of tool errors (go-sdk v1.7.0 server.go).
	mcp.AddTool(srv, &mcp.Tool{
		Name: "camera.list",
		Description: "List the cameras this server is configured with. Each entry has: id (the handle to use for " +
			"other tools); endpoint (the camera's URL, credentials never included); control_allowed (whether " +
			"state-changing tools may act on it). With probe=true each camera is also contacted and gets state " +
			"(reachable or unreachable) and, when unreachable, error and error_code. Without probe nothing is " +
			"contacted and state, error and error_code are absent. A dead camera never fails the call: it is " +
			"reported in its own entry. probe has a built-in time budget, so a hung camera cannot stall it. " +
			"The result is under data.cameras; error is set only if the call itself failed.",
		// Closed world: with probe=true this tool does contact cameras, but
		// only the fixed set an operator wrote into the config. Only
		// discovery, which reaches whatever answers on the network, is
		// open-world.
		Annotations: tools.ReadOnly("List cameras"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ListIn) (*mcp.CallToolResult, mcperr.Out[ListData], error) {
		ctx, cancel := deps.Scope(ctx)
		defer cancel()
		var cams []registry.Status
		if in.Probe {
			// Probe has its own overall budget (15s default) and a bound of 8
			// cameras in flight, so the handler needs no extra timeout. A
			// dead camera is reported in its Status, never as a call failure.
			cams = reg.Probe(ctx)
			// Cancelled (client cancel or shutdown): the per-camera entries
			// say "not probed", so do not present them as a listing.
			if err := ctx.Err(); err != nil {
				return nil, mcperr.Out[ListData]{}, fmt.Errorf("camera.list cancelled: %w", err)
			}
		} else {
			cams = reg.List()
		}
		// Returning a nil result would make the SDK fill Content with the full
		// JSON dump. Supply a short summary instead; the SDK still sets
		// StructuredContent from the Out value.
		res := &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: summarize(cams)}},
		}
		return res, mcperr.OK(ListData{Cameras: cams}), nil
	})

	tools.RegisterMedia(srv, deps)
	tools.RegisterImaging(srv, deps)
	tools.RegisterPTZReads(srv, deps)
	tools.RegisterCamera(srv, deps)

	log.Debug("tools registered", "count", 8)
	return srv
}
