package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/safety"
)

// SDK types used (github.com/modelcontextprotocol/go-sdk v1.7.0):
//   - mcp.Middleware, mcp.MethodHandler   mcp/shared.go
//   - mcp.RequestExtra.TokenInfo          mcp/shared.go (set by auth.RequireBearerToken)

// CallerSource resolves who is making a request. It returns false when there is
// no identity; the server then refuses tools/call and resources/read.
type CallerSource func(ctx context.Context, req mcp.Request) (safety.Caller, bool)

// StdioOperator is the source for the stdio transport: every request comes from
// the operator who started the process, who has control. It is the one place a
// Caller with control is created for the server (cmd/onvif-mcp passes it).
func StdioOperator() CallerSource {
	return func(context.Context, mcp.Request) (safety.Caller, bool) {
		return safety.StdioOperator(), true
	}
}

// HTTPCallers is the source for the HTTP transport. It maps the token id the
// authentication stage attached to the request (RequestExtra.TokenInfo.UserID)
// to a safety.RemoteCaller, which can never carry control. A request without a
// TokenInfo has no caller.
func HTTPCallers() CallerSource {
	return func(_ context.Context, req mcp.Request) (safety.Caller, bool) {
		ex := req.GetExtra()
		if ex == nil || ex.TokenInfo == nil || ex.TokenInfo.UserID == "" {
			return safety.Caller{}, false
		}
		c, err := safety.RemoteCaller(ex.TokenInfo.UserID, "http")
		if err != nil {
			return safety.Caller{}, false
		}
		return c, true
	}
}

// errNoCaller is the protocol error for a call that carries no identity.
var errNoCaller = errors.New("request refused: the caller could not be identified")

// callerContext is the outermost receiving middleware. It resolves the Caller
// and stores it in the context, where the guard reads it. With no source, or a
// source that resolves nothing, tools/call and resources/read are refused
// before anything runs; initialize and the list methods still work so a client
// can see what the server is.
func callerContext(src CallerSource) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			var c safety.Caller
			ok := false
			if src != nil {
				c, ok = src(ctx, req)
				ok = ok && c.Valid()
			}
			if ok {
				ctx = safety.WithCaller(ctx, c)
			} else if method == "tools/call" || method == "resources/read" {
				return nil, errNoCaller
			}
			return next(ctx, method, req)
		}
	}
}

// Limits for the HTTP transport (README, "Serving over HTTP").
const (
	// HTTPMaxCalls is the most tools/call executing at once across all tokens.
	HTTPMaxCalls = 32
	// HTTPMaxCallsPerToken is the most executing at once for one token.
	HTTPMaxCallsPerToken = 8
	// HTTPCallDeadline bounds one tools/call. Handlers outlive the HTTP request
	// (go-sdk v1.7.0 detaches them), so this bounds how long a slot is held.
	HTTPCallDeadline = 120 * time.Second

	// HTTPWritesUnavailable is the policy resource's how_to_enable text on HTTP.
	HTTPWritesUnavailable = "write tools are not offered on this transport"
)

// GrantSource maps a token id to the opt-in tools it was granted. An unknown id
// has no grants.
type GrantSource interface{ Grants(id string) []string }

// HTTPGuardOptions configures WithHTTPGuard. Zero numeric fields take the
// package constants; tests set them smaller.
type HTTPGuardOptions struct {
	Grants           GrantSource
	Log              *slog.Logger // tool-call audit lines; nil discards
	MaxCalls         int
	MaxCallsPerToken int
	CallDeadline     time.Duration
}

// callCaps counts tools/call in flight. A slot is taken before the handler runs
// and released only when it returns (deferred, so a panic frees it too): the
// HTTP layer cannot release it, because the handler outlives a dropped request.
type callCaps struct {
	mu       sync.Mutex
	global   int
	perToken map[string]int
	maxG     int
	maxT     int
}

func (c *callCaps) acquire(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.global >= c.maxG || c.perToken[id] >= c.maxT {
		return false
	}
	c.global++
	c.perToken[id]++
	return true
}

func (c *callCaps) release(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.global--
	if c.perToken[id]--; c.perToken[id] <= 0 {
		delete(c.perToken, id)
	}
}

// refusal builds the tool-error result for a call this middleware refused.
func refusal(te *mcperr.ToolError) *mcp.CallToolResult {
	line := fmt.Sprintf("%s: %s", te.Code, te.Message)
	if te.Hint != "" {
		line += " (" + te.Hint + ")"
	}
	if te.RetryAfterSeconds != nil {
		line += fmt.Sprintf(" [retry_after_seconds=%d]", *te.RetryAfterSeconds)
	}
	return &mcp.CallToolResult{
		IsError:           true,
		Content:           []mcp.Content{&mcp.TextContent{Text: line}},
		StructuredContent: mcperr.Fail[any](te),
	}
}

// notGrantedResult is the one answer for an opt-in tool the token lacks. It
// does not depend on the arguments, so it cannot reveal which cameras exist.
func notGrantedResult(tool string) *mcp.CallToolResult {
	return refusal(&mcperr.ToolError{
		Code:      mcperr.CodeBlockedByPolicy,
		Operation: tool,
		Message:   "this token has not been granted this tool",
		Hint:      "an operator must add the tool to this token's grant list; do not retry",
	})
}

// httpGuard is the HTTP-only receiving middleware, just inside callerContext.
// It (1) rejects subscriptions/listen, which would pin a connection; (2) hides
// opt-in tools from tools/list and refuses tools/call for them unless the
// token's grants include the tool, before the arguments are decoded; (3) bounds
// concurrent tools/call globally and per token; (4) puts a deadline on every
// call; (5) writes one audit line per tools/call naming the caller.
func httpGuard(o HTTPGuardOptions) mcp.Middleware {
	if o.MaxCalls <= 0 {
		o.MaxCalls = HTTPMaxCalls
	}
	if o.MaxCallsPerToken <= 0 {
		o.MaxCallsPerToken = HTTPMaxCallsPerToken
	}
	if o.CallDeadline <= 0 {
		o.CallDeadline = HTTPCallDeadline
	}
	caps := &callCaps{perToken: map[string]int{}, maxG: o.MaxCalls, maxT: o.MaxCallsPerToken}
	log := o.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	grantsFor := func(id string) []string {
		if o.Grants == nil || id == "" {
			return nil
		}
		return o.Grants.Grants(id)
	}
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			switch method {
			case "subscriptions/listen":
				return nil, errors.New("method not supported on this server")
			case "tools/list":
				res, err := next(ctx, method, req)
				lr, ok := res.(*mcp.ListToolsResult)
				if err != nil || !ok || lr == nil {
					return res, err
				}
				id := ""
				if c, ok := safety.CallerFrom(ctx); ok {
					id = c.ID()
				}
				granted := grantsFor(id)
				kept := make([]*mcp.Tool, 0, len(lr.Tools))
				for _, t := range lr.Tools {
					if safety.IsOptInTool(t.Name) && !slices.Contains(granted, t.Name) {
						continue
					}
					kept = append(kept, t)
				}
				lr.Tools = kept
				return lr, nil
			case "tools/call":
				return guardCall(ctx, method, req, next, o, caps, grantsFor, log)
			}
			return next(ctx, method, req)
		}
	}
}

// maxLoggedToolName bounds the caller-supplied tool name written to the audit
// log, so an authenticated caller cannot write a request-sized line per call.
const maxLoggedToolName = 64

// boundedName truncates s to maxLoggedToolName bytes (on a rune boundary) and
// marks the cut. Registered tool names are far shorter, so they pass unchanged.
func boundedName(s string) string {
	if len(s) <= maxLoggedToolName {
		return s
	}
	return strings.ToValidUTF8(s[:maxLoggedToolName], "") + "...(truncated)"
}

func guardCall(ctx context.Context, method string, req mcp.Request, next mcp.MethodHandler,
	o HTTPGuardOptions, caps *callCaps, grantsFor func(string) []string, log *slog.Logger,
) (result mcp.Result, rerr error) {
	c, ok := safety.CallerFrom(ctx)
	sr, isCall := req.(*mcp.ServerRequest[*mcp.CallToolParamsRaw])
	if !ok || !isCall || sr.Params == nil {
		// callerContext guarantees a caller; fail closed anyway.
		return nil, errNoCaller
	}
	tool := sr.Params.Name
	audit := func(outcome string) {
		log.Info("tool call", "tool", boundedName(tool), "caller", c.ID(), "transport", c.Transport(), "outcome", outcome)
	}

	if safety.IsOptInTool(tool) && !slices.Contains(grantsFor(c.ID()), tool) {
		audit("refused")
		return notGrantedResult(tool), nil
	}
	if !caps.acquire(c.ID()) {
		audit("refused")
		one := 1
		return refusal(&mcperr.ToolError{
			Code:              mcperr.CodeBlockedByPolicy,
			Operation:         tool,
			Message:           "too many tool calls are in progress",
			Hint:              "wait retry_after_seconds, then repeat the call",
			Retryable:         true,
			RetryAfterSeconds: &one,
		}), nil
	}
	defer caps.release(c.ID())

	ctx, cancel := context.WithTimeout(ctx, o.CallDeadline)
	defer cancel()
	// The SDK runs handlers on its own goroutines without recovering, so an
	// unrecovered panic in any tool would end the whole process and every other
	// caller with it. Convert it to a tool error; the value is never logged or
	// returned (it can carry anything the handler held). The slot is released by
	// the deferred release above this frame either way.
	defer func() {
		if r := recover(); r != nil {
			audit("protocol_error")
			result = refusal(&mcperr.ToolError{
				Code:      mcperr.CodeInternal,
				Operation: tool,
				Message:   "the tool failed unexpectedly",
				Hint:      "report this to the operator; repeating the call is unlikely to help",
			})
			rerr = nil
		}
	}()
	res, err := next(ctx, method, req)
	switch ctr, _ := res.(*mcp.CallToolResult); {
	case err != nil:
		audit("protocol_error")
	case ctr != nil && ctr.IsError:
		audit("tool_error")
	default:
		audit("ok")
	}
	return res, err
}
