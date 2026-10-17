// Package mcpserver builds the MCP server and registers every tool.
package mcpserver

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/registry"
)

// version is the server's reported version.
const version = "v0.1.0"

// Version returns the server version reported during initialisation.
func Version() string { return version }

func boolPtr(b bool) *bool { return &b }

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

// New builds the server and registers the tool surface.
func New(reg *registry.Registry, log *slog.Logger) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "onvif-mcp",
		Version: version,
	}, nil)

	// Always the generic free function mcp.AddTool, never the srv.AddTool
	// method: the method skips input validation and turns handler errors into
	// protocol errors instead of tool errors (go-sdk v1.7.0 server.go).
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "camera.list",
		Description: "List configured cameras and whether control is allowed. Set probe to contact each camera and report whether it is reachable.",
		Annotations: &mcp.ToolAnnotations{
			Title:           "List cameras",
			ReadOnlyHint:    true,
			DestructiveHint: boolPtr(false),
			IdempotentHint:  true,
			// MCP defines openWorldHint as "may interact with an open world of
			// external entities". With probe=true this tool does contact
			// cameras, but only the fixed set an operator wrote into the
			// config; it never reaches an entity the operator did not name.
			// That is a closed world, so false. Only discovery, which reaches
			// whatever answers on the network, is open-world.
			OpenWorldHint: boolPtr(false),
		},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ListIn) (*mcp.CallToolResult, mcperr.Out[ListData], error) {
		var cams []registry.Status
		if in.Probe {
			// Probe has its own overall budget (15s default) and a bound of 8
			// cameras in flight, so the handler needs no extra timeout. A
			// dead camera is reported in its Status, never as a call failure.
			cams = reg.Probe(ctx)
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

	log.Debug("tools registered", "count", 1)
	return srv
}
