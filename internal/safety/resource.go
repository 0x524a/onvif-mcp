package safety

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// PolicyURI is the resource an agent reads to learn what it may do.
const PolicyURI = "onvif://server/policy"

// CameraGrant is one camera's write posture.
//
// ControlAllowed is the camera's own opt-in from the config file. It only
// takes effect when the process has control enabled, so on its own it does not
// mean the camera can be controlled now. Writable is that combined answer,
// filled in by the policy resource.
type CameraGrant struct {
	ID             string `json:"id" jsonschema:"the camera id"`
	ControlAllowed bool   `json:"control_allowed" jsonschema:"the camera opted in to control in its config entry; only effective when control_enabled is true"`
	Writable       bool   `json:"writable" jsonschema:"true when write tools can act on this camera now: control_allowed and control_enabled"`
}

type policyDoc struct {
	Mode               string        `json:"mode"`
	ControlEnabled     bool          `json:"control_enabled"`
	GatedWriteTools    []string      `json:"gated_write_tools"`
	Cameras            []CameraGrant `json:"cameras"`
	RateLimitPerCamera string        `json:"rate_limit_per_camera"`
	HowToEnable        string        `json:"how_to_enable"`
	DryRunDefault      bool          `json:"dry_run_default"`
	Explanation        string        `json:"explanation"`
	Why                string        `json:"why"`
}

// rateLimitText describes the limiter that is actually in force.
func (p *Policy) rateLimitText() string {
	if p == nil || p.Limiter == nil {
		return "no real movement is permitted: no rate limiter is configured"
	}
	return fmt.Sprintf("one movement per %s, burst %d", p.Limiter.Interval(), p.Limiter.Burst())
}

const whyText = "write tools physically move or reconfigure a real camera; an agent that loops on them " +
	"can wear out or wedge the mechanism, so they are off unless an operator opts in"

// whyEnabledText replaces whyText once the server has control enabled: the
// server-wide opt-in is done, and each camera still needs its own.
const whyEnabledText = "write tools physically move or reconfigure a real camera; an agent that loops on them " +
	"can wear out or wedge the mechanism, so the operator has enabled control on this server and each camera " +
	"must also opt in individually"

func (p *Policy) document(cams []CameraGrant) policyDoc {
	enabled := p != nil && p.ControlEnabled
	mode := "read-only"
	if enabled {
		mode = "control-enabled"
	}
	grants := make([]CameraGrant, 0, len(cams))
	for _, c := range cams {
		c.Writable = enabled && c.ControlAllowed
		grants = append(grants, c)
	}
	gated := p.GatedTools()

	howTo := "an operator must restart the server with --enable-control " +
		"AND set \"control\": true on the camera's config entry"
	explanation := "when control is disabled, the write tools listed in gated_write_tools are not " +
		"registered and do not appear in tools/list; when enabled they still default to dry_run " +
		"true, so a caller must pass dry_run false to change a camera, and only cameras with " +
		"control_allowed true accept it. control_allowed is a camera's own opt-in and only takes " +
		"effect when control_enabled is true; writable says whether a camera can be controlled now"
	why := whyText
	if enabled {
		why = whyEnabledText
		var missing []string
		for _, c := range grants {
			if !c.ControlAllowed {
				missing = append(missing, c.ID)
			}
		}
		if len(missing) == 0 {
			howTo = "control is enabled on this server and every configured camera allows it; nothing more is needed"
		} else {
			howTo = "control is already enabled on this server; cameras that have not " +
				"opted in (" + strings.Join(missing, ", ") + ") need an operator to set \"control\": true on " +
				"their config entry and restart the server"
		}
	}
	if len(gated) == 0 {
		howTo = "nothing to enable: this build registers no write tool, so --enable-control and " +
			"\"control\": true currently change nothing"
		explanation = "this build registers no write tool, so --enable-control currently changes nothing; " +
			"every tool is read-only. " + explanation
	}
	return policyDoc{
		Mode:               mode,
		ControlEnabled:     enabled,
		GatedWriteTools:    gated,
		Cameras:            grants,
		RateLimitPerCamera: p.rateLimitText(),
		HowToEnable:        howTo,
		DryRunDefault:      true,
		Explanation:        explanation,
		Why:                why,
	}
}

// RegisterPolicyResource exposes the current posture as a readable document, so
// an agent can discover that a write tool exists and is gated without calling
// it and failing. It is registered whether or not control is enabled. The
// gated tool list and the rate limit are read from p at request time, not
// written here. A nil p reports read-only.
//
// Resources go through the srv.AddResource method, which is correct; the
// method-versus-generic hazard applies to tools only.
func RegisterPolicyResource(srv *mcp.Server, p *Policy, cams func() []CameraGrant) {
	srv.AddResource(&mcp.Resource{
		URI:         PolicyURI,
		Name:        "server-policy",
		Title:       "Server safety policy",
		Description: "Current write posture: whether control is enabled, which write tools are gated, which cameras opted in, and the rate limit.",
		MIMEType:    "application/json",
	}, func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		var grants []CameraGrant
		if cams != nil {
			grants = cams()
		}
		b, err := json.MarshalIndent(p.document(grants), "", "  ")
		if err != nil {
			return nil, err
		}
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{{
				URI: PolicyURI, MIMEType: "application/json", Text: string(b),
			}},
		}, nil
	})
}
