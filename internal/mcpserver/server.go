// Package mcpserver builds the MCP server and registers every tool.
package mcpserver

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/probe"
	"github.com/0x524a/onvif-mcp/internal/redact"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
	"github.com/0x524a/onvif-mcp/internal/tools"
)

// version is the server's reported version. It is a var, not a const, so release
// builds can set it with -ldflags "-X github.com/0x524a/onvif-mcp/internal/mcpserver.version=vX.Y.Z"
// (scripts/build-release.sh does). A plain go build reports the value below.
var version = "v0.2.1"

// Version returns the server version reported during initialisation.
func Version() string { return version }

// ListIn is the input for camera.list.
type ListIn struct {
	Probe bool `json:"probe,omitempty" jsonschema:"contact each camera and report reachable or unreachable; default false, which contacts nothing and returns instantly"`
}

// ListData is what camera.list reports.
type ListData struct {
	Cameras []registry.Status `json:"cameras" jsonschema:"every configured camera, sorted by id"`
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

type options struct {
	base             context.Context
	prober           probe.Prober
	snapshotMaxBytes int
	callers          CallerSource
	http             *HTTPGuardOptions
}

// WithCallerSource sets how the server learns who is calling. Without it no
// request has a caller, so tools/call and resources/read are refused: a
// transport must establish identity explicitly (StdioOperator or HTTPCallers).
func WithCallerSource(s CallerSource) Option {
	return func(o *options) { o.callers = s }
}

// WithHTTPGuard marks the server as serving the HTTP transport and installs the
// HTTP-only middleware (see httpGuard). HTTP offers no write tool, so New
// panics if the policy has control enabled, and sets the policy's
// WritesUnavailable text so the policy resource tells the truth.
func WithHTTPGuard(g HTTPGuardOptions) Option {
	return func(o *options) { o.http = &g }
}

// WithBaseContext makes every tool call also stop when base is done. The SDK
// derives handler contexts from the request, not from the Run context, so
// without this a SIGTERM during a slow camera probe waits out the probe.
func WithBaseContext(base context.Context) Option {
	return func(o *options) { o.base = base }
}

// WithProber replaces the RTSP prober stream.inspect uses. The default is the
// real one (probe.NewRTSP); tests inject a fake or point it at an
// in-process RTSP server.
func WithProber(p probe.Prober) Option {
	return func(o *options) { o.prober = p }
}

// WithSnapshotMaxBytes sets the largest image camera.snapshot returns, in raw
// bytes. The default is tools.DefaultSnapshotMaxBytes (1 MiB). The value is not
// range checked here; the command validates the operator's flag with
// tools.CheckSnapshotMaxBytes.
func WithSnapshotMaxBytes(n int) Option {
	return func(o *options) { o.snapshotMaxBytes = n }
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

// auditRejected is receiving middleware that audits a call to a gated write
// tool which never reached the tool's handler, such as one the SDK refused for
// failing schema validation. The handler audits every call that reaches it, so
// this adds a record only for the rest. It must be the outermost middleware so
// that it sees those failures. It reads no arguments.
func auditRejected(p *safety.Policy) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			sr, ok := req.(*mcp.ServerRequest[*mcp.CallToolParamsRaw])
			if method != "tools/call" || !ok || sr.Params == nil {
				return next(ctx, method, req)
			}
			name := sr.Params.Name
			gated := false
			for _, g := range p.GatedTools() {
				if g == name {
					gated = true
					break
				}
			}
			if !gated {
				return next(ctx, method, req)
			}
			ctx, attempt := safety.TrackAttempt(ctx)
			res, err := next(ctx, method, req)
			if !attempt.Reached() {
				p.AuditRejected(name)
			}
			return res, err
		}
	}
}

// New builds the server and registers the tool surface and the policy
// resource. policy gates write tools (tools.GuardedTool) and is what the
// onvif://server/policy resource describes; nil behaves as read-only. The
// resource is registered whether or not control is enabled.
func New(reg *registry.Registry, log *slog.Logger, policy *safety.Policy, opts ...Option) *mcp.Server {
	var o options
	for _, f := range opts {
		f(&o)
	}
	if o.http != nil && policy != nil {
		if policy.WriteRegistered() {
			// A programming error in the wiring, like GuardedTool misuse: fail
			// on every run rather than ever offering a write tool over HTTP.
			panic("mcpserver.New: write tools must not be registered on the HTTP transport")
		}
		if policy.WritesUnavailable == "" {
			policy.WritesUnavailable = HTTPWritesUnavailable
		}
	}
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "onvif-mcp",
		Version: version,
	}, nil)
	// The first middleware added is the outermost. callerContext is first so
	// every later stage can rely on the Caller; httpGuard (HTTP only) is next so
	// its refusals are audited with the caller; auditRejected must wrap
	// everything else, including the SDK's own argument validation.
	mws := []mcp.Middleware{callerContext(o.callers)}
	if o.http != nil {
		mws = append(mws, httpGuard(*o.http))
	}
	mws = append(mws, auditRejected(policy), argumentErrors)
	srv.AddReceivingMiddleware(mws...)
	prober := o.prober
	if prober == nil {
		prober = probe.NewRTSP()
	}
	deps := tools.Deps{Reg: reg, Log: log, Base: o.base, Policy: policy, Prober: prober, SnapshotMaxBytes: o.snapshotMaxBytes}

	// Always tools.GuardedTool (which wraps the generic free function), never
	// the srv.AddTool method: the method skips input validation and turns
	// handler errors into protocol errors instead of tool errors (go-sdk
	// v1.7.0 server.go).
	tools.GuardedTool(srv, deps, safety.RiskRead, &mcp.Tool{
		Name: "camera.list",
		Description: "Use this first: it lists the cameras this server is configured with, and every other camera " +
			"tool needs one of these ids as camera. Each entry has: id (the handle to use for other tools); " +
			"endpoint (the camera's URL, credentials never included); control_allowed (whether state-changing " +
			"tools may act on it). With probe=true each camera is also contacted and gets state (reachable or " +
			"unreachable) and, when unreachable, error and error_code. Without probe nothing is contacted and " +
			"state, error and error_code are absent. A dead camera never fails the call: it is reported in its " +
			"own entry. probe has a built-in time budget, so a hung camera cannot stall it. The result is " +
			"under data.cameras; error is set only if the call itself failed. Does not find new cameras " +
			"(camera.discover does that), does not check credentials beyond reaching the camera, and does " +
			"not change anything.",
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
	}, nil)

	tools.RegisterMedia(srv, deps)
	tools.RegisterImaging(srv, deps)
	tools.RegisterPTZReads(srv, deps)
	tools.RegisterCamera(srv, deps)
	tools.RegisterStream(srv, deps)
	tools.RegisterSnapshot(srv, deps)

	// The gated tools: ptz.goto_preset and ptz.move_relative (RiskWrite) and
	// ptz.stop (RiskHalt). They go through tools.GuardedTool, which keeps them
	// out of tools/list while control is disabled and lists them in the policy.
	tools.RegisterPTZWrites(srv, deps)
	tools.RegisterPTZMotion(srv, deps)

	safety.RegisterPolicyResource(srv, policy, func() []safety.CameraGrant {
		list := reg.List()
		grants := make([]safety.CameraGrant, 0, len(list))
		for _, c := range list {
			g := safety.CameraGrant{ID: c.ID, ControlAllowed: c.Control}
			if e, err := reg.Get(c.ID); err == nil {
				g.PTZHonoursTimeout = e.HonoursTimeout()
			}
			grants = append(grants, g)
		}
		return grants
	})

	gated := len(policy.GatedTools())
	registered := tools.ClaimedCount(srv) - gated
	if policy.WriteRegistered() {
		registered += gated
	}
	log.Debug("tools registered", "count", registered, "gated", gated)
	return srv
}
