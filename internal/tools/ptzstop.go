package tools

import (
	"context"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/redact"
	"github.com/0x524a/onvif-mcp/internal/safety"
)

const stopTool = "ptz.stop"

// StopIn is the input of ptz.stop. It deliberately has no dry_run: a stop must
// always act, so GuardedTool refuses an input that implements safety.WriteInput.
type StopIn struct {
	Camera  string `json:"camera" jsonschema:"the camera id, taken from camera.list (its id field)"`
	Profile string `json:"profile" jsonschema:"the token of the media profile to stop, normally the one you moved; call media.profiles and choose one with has_ptz true. Stop is per profile"`
}

// CameraID returns the target camera (safety.HaltInput).
func (s StopIn) CameraID() string { return s.Camera }

// StopData is the ptz.stop result. A stop that could not be delivered is
// reported through the error envelope, not here.
type StopData struct {
	Executed   bool        `json:"executed" jsonschema:"true when the stop command was sent to the camera"`
	StopStatus string      `json:"stop_status" jsonschema:"confirmed_idle: the stop was delivered and the camera reports it idle; sent_unconfirmed: the stop was delivered but the camera did not confirm it (it reported MOVING or UNKNOWN, reported no movement state, or its status could not be read)"`
	Profile    string      `json:"profile" jsonschema:"the profile token the stop addressed"`
	Final      *StatusData `json:"final,omitempty" jsonschema:"the last PTZ status read after the stop, same shape as ptz.status; absent means none could be read; absent fields were not reported"`
	Note       string      `json:"note" jsonschema:"what happened and what to do next"`
}

// RegisterPTZMotion registers the motion tools: ptz.stop (RiskHalt) and
// ptz.move_relative (RiskWrite). With control off neither is registered, but
// both are named by the policy resource.
func RegisterPTZMotion(srv *mcp.Server, d Deps) {
	registerPTZStop(srv, d)
}

func stopSchema() *jsonschema.Schema {
	s, err := jsonschema.For[StopIn](nil)
	if err != nil {
		panic("tools: ptz.stop input schema: " + err.Error())
	}
	one := 1
	p, ok := s.Properties["profile"]
	if !ok {
		panic("tools: ptz.stop input schema has no property profile")
	}
	p.MinLength = &one
	return s
}

// registerPTZStop registers ptz.stop through GuardedTool as RiskHalt.
//
// onvif-go (v1.2.0): (*Client).Stop(ctx, profileToken, panTilt, zoom bool),
// ptz.go:307, through stopAndConfirm; confirmation uses (*Client).GetStatus,
// ptz.go:344.
func registerPTZStop(srv *mcp.Server, d Deps) {
	GuardedTool(srv, d, safety.RiskHalt, &mcp.Tool{
		InputSchema: stopSchema(),
		Name:        stopTool,
		Description: "Use this to stop a PTZ camera that is moving, whether from ptz.move_relative, ptz.goto_preset or " +
			"anything else. Pass the profile you moved (call media.profiles for a profile with has_ptz true). Stop is " +
			"per profile: if you are unsure which profile moved, call it once per has_ptz profile. This tool has no dry " +
			"run and is not rate limited, so it always acts; it only works on cameras the operator opted in to control. " +
			"It stops pan, tilt and zoom, then reads the camera's status: stop_status confirmed_idle means the camera " +
			"reports it idle; sent_unconfirmed means the stop was delivered but not confirmed (many cameras report no " +
			"movement state), so check ptz.status or camera.snapshot. If the stop could not be delivered the call fails " +
			"and you should call ptz.stop again immediately. Stopping a camera that is already idle is harmless. Does " +
			"not move the camera.",
		Annotations: safety.HaltAnnotations("Stop PTZ movement"),
	}, ptzStopRun(d), nil)
}

const perProfileNote = " Stop is per profile; stop other has_ptz profiles too if unsure."

func ptzStopRun(d Deps) mcp.ToolHandlerFor[StopIn, mcperr.Out[StopData]] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in StopIn) (*mcp.CallToolResult, mcperr.Out[StopData], error) {
		// The guard noted nothing yet; the audit target is scrubbed and bounded.
		safety.NoteTarget(ctx, in.Profile)
		rep := stopAndConfirm(ctx, d, in.Camera, in.Profile)
		if rep.Err != nil {
			return fail[StopData](rep.Err)
		}
		data := StopData{
			Executed:   rep.Sent,
			StopStatus: rep.Status,
			Profile:    clip(redact.Scrub(in.Profile)),
			Final:      rep.Final,
			Note:       rep.Note + perProfileNote,
		}
		msg := "Stop delivered; camera reports idle."
		if rep.Status != stopConfirmedIdle {
			msg = "Stop delivered, not confirmed; check ptz.status."
		}
		return text(msg), mcperr.OK(data), nil
	}
}
