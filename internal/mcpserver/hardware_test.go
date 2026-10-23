//go:build hardware

// Real-camera tier. This file is compiled only with -tags hardware and every
// test skips unless the operator opts in through the environment, so the normal
// gate and CI never run it. See the README section "Hardware tests (optional)".
//
// Rules this file keeps:
//   - Credentials come only from the config file the operator names and the
//     existing ONVIF_MCP_<ID>_PASSWORD variables. They are never printed.
//   - Nothing here logs a stream URI, endpoint or raw tool output. Logs carry
//     camera id, tool name and outcome code only.
//   - The read matrix calls read tools only and never moves anything.
package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
)

// hwEnvelope is the mcperr.Out wire shape, decoded loosely so one helper
// serves every tool.
type hwEnvelope struct {
	Data  json.RawMessage `json:"data"`
	Error *struct {
		Code      string `json:"code"`
		Retryable *bool  `json:"retryable"`
		Message   string `json:"message"`
	} `json:"error"`
}

// hwTaxonomy is the closed error-code set (internal/mcperr/code.go).
var hwTaxonomy = map[string]bool{
	"unreachable": true, "timeout": true, "auth_failed": true, "not_supported": true,
	"not_found": true, "invalid_argument": true, "device_fault": true,
	"blocked_by_policy": true, "internal": true,
}

// hwConfig loads the operator's config or skips. The path is only ever read
// from the environment, never from the repository.
func hwConfig(t *testing.T) *config.Config {
	t.Helper()
	path := os.Getenv("ONVIF_MCP_HW_CONFIG")
	if path == "" {
		t.Skip("ONVIF_MCP_HW_CONFIG not set; the real-camera tier is opt-in")
	}
	cfg, err := config.Load(path)
	if err != nil {
		// config.Load errors never quote credentials.
		t.Fatalf("load hardware config: %v", err)
	}
	return cfg
}

func hwSession(t *testing.T, cfg *config.Config) *mcp.ClientSession {
	t.Helper()
	reg := registry.New(cfg)
	pol := safety.NewPolicy(safety.PolicyOptions{ControlEnabled: cfg.ControlEnabled, Cameras: reg, Log: quietLog()})
	return connect(t, New(reg, quietLog(), pol))
}

// hwCall calls a tool and returns the decoded envelope plus all text a client
// would see (structured content and text blocks) for canary scanning. Image
// bytes are not scanned or kept.
func hwCall(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) (hwEnvelope, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", tool, err)
	}
	structured, _ := json.Marshal(res.StructuredContent)
	var sb strings.Builder
	sb.Write(structured)
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	var env hwEnvelope
	if err := json.Unmarshal(structured, &env); err != nil {
		t.Errorf("%s: structured content is not an envelope", tool)
	}
	return env, sb.String()
}

func TestHardwareReadMatrix(t *testing.T) {
	cfg := hwConfig(t)
	cs := hwSession(t, cfg)

	ids := make([]string, 0, len(cfg.Cameras))
	for id := range cfg.Cameras {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		id := id
		secret := cfg.Cameras[id].Password
		t.Run(id, func(t *testing.T) {
			// check applies the invariants every cell must hold and returns
			// the outcome label ("ok" or the error code). Output is never logged.
			check := func(tool string, env hwEnvelope, text string) string {
				t.Helper()
				if (env.Data == nil || string(env.Data) == "null") == (env.Error == nil) {
					t.Errorf("%s: envelope must carry exactly one of data and error", tool)
				}
				if secret != "" && strings.Contains(text, secret) {
					t.Errorf("%s: the camera password appears in tool output", tool)
				}
				if strings.Contains(strings.ToLower(text), "<soap") {
					t.Errorf("%s: raw SOAP appears in tool output", tool)
				}
				if env.Error == nil {
					t.Logf("%-16s ok", tool)
					return "ok"
				}
				code := env.Error.Code
				if !hwTaxonomy[code] {
					t.Errorf("%s: code %q is outside the taxonomy", tool, code)
				}
				// A vendor quirk is a finding to triage, not a failure.
				t.Logf("%-16s %s", tool, code)
				return code
			}

			cam := map[string]any{"camera": id}
			env, text := hwCall(t, cs, "camera.describe", cam)
			check("camera.describe", env, text)

			env, text = hwCall(t, cs, "media.profiles", cam)
			if check("media.profiles", env, text) != "ok" {
				return // no profile token to address; nothing further to read
			}
			var pd struct {
				Profiles []struct {
					Token       string `json:"token"`
					HasPTZ      bool   `json:"has_ptz"`
					SourceToken string `json:"video_source_token"`
				} `json:"profiles"`
			}
			if err := json.Unmarshal(env.Data, &pd); err != nil || len(pd.Profiles) == 0 {
				t.Logf("no usable profile; skipping profile-addressed tools")
				return
			}
			first := pd.Profiles[0]
			prof := map[string]any{"camera": id, "profile": first.Token}

			for _, tool := range []string{"media.stream_uri", "stream.inspect", "camera.snapshot"} {
				env, text = hwCall(t, cs, tool, prof)
				check(tool, env, text)
			}
			if first.SourceToken != "" {
				env, text = hwCall(t, cs, "imaging.settings", map[string]any{"camera": id, "source_token": first.SourceToken})
				check("imaging.settings", env, text)
			}

			// PTZ reads use a profile the camera says has PTZ; a camera with
			// none is skipped, and not_supported from one that claims PTZ
			// is a pass.
			for _, p := range pd.Profiles {
				if !p.HasPTZ {
					continue
				}
				pp := map[string]any{"camera": id, "profile": p.Token}
				for _, tool := range []string{"ptz.status", "ptz.presets"} {
					env, text = hwCall(t, cs, tool, pp)
					check(tool, env, text)
				}
				return
			}
			t.Logf("no profile reports PTZ; skipping ptz.status and ptz.presets")
		})
	}
}

// TestHardwareGatedMove physically moves one camera to one preset.
//
// It skips unless ONVIF_MCP_HW_MOVE is exactly <camera-id>:<profile-token>:<preset-token>.
// The OPERATOR must confirm, before setting it, that the preset is safe to
// visit (clear of people, cabling and obstructions) and that nobody depends on
// the camera's view during the run. This test cannot judge that.
//
// Optional ONVIF_MCP_HW_RETURN=<preset-token> names a second preset on the same
// profile to send the camera back to afterwards; without it the camera stays
// where the move left it.
//
// Both gates are required for the move to execute: the server-wide control
// switch and the named camera's own grant. The test enables them in memory for
// the named camera only; the config file is not modified and no other camera
// can move. A default call (no dry_run) is checked to be a dry run first.
func TestHardwareGatedMove(t *testing.T) {
	spec := os.Getenv("ONVIF_MCP_HW_MOVE")
	if spec == "" {
		t.Skip("ONVIF_MCP_HW_MOVE not set; this test physically moves a camera")
	}
	parts := strings.Split(spec, ":")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		t.Fatal("ONVIF_MCP_HW_MOVE must be <camera-id>:<profile-token>:<preset-token>")
	}
	camID, profile, preset := parts[0], parts[1], parts[2]
	back := os.Getenv("ONVIF_MCP_HW_RETURN")

	cfg := hwConfig(t)
	cam, ok := cfg.Cameras[camID]
	if !ok {
		t.Fatalf("camera %q is not in the hardware config", camID)
	}
	// Both gates, for this camera only.
	cfg.ControlEnabled = true
	cam.Control = true
	cs := hwSession(t, cfg)

	move := func(target string, dry *bool) (hwEnvelope, string) {
		m := map[string]any{"camera": camID, "profile": profile, "preset": target}
		if dry != nil {
			m["dry_run"] = *dry
		}
		return hwCall(t, cs, "ptz.goto_preset", m)
	}
	type gotoOut struct {
		Executed bool `json:"executed"`
		DryRun   bool `json:"dry_run"`
	}

	// 1. Omitting dry_run must simulate and send nothing.
	env, _ := move(preset, nil)
	var d gotoOut
	_ = json.Unmarshal(env.Data, &d)
	if env.Error != nil || d.Executed || !d.DryRun {
		t.Fatalf("default call must be a dry run that does not execute (error present: %t)", env.Error != nil)
	}

	// 2. The preset must exist on this profile before anything real happens.
	env, text := hwCall(t, cs, "ptz.presets", map[string]any{"camera": camID, "profile": profile})
	if env.Error != nil {
		t.Fatalf("ptz.presets failed: %s", env.Error.Code)
	}
	var pd struct {
		Presets []struct {
			Token string `json:"token"`
		} `json:"presets"`
	}
	_ = json.Unmarshal(env.Data, &pd)
	has := func(tok string) bool {
		for _, p := range pd.Presets {
			if p.Token == tok {
				return true
			}
		}
		return false
	}
	if !has(preset) || (back != "" && !has(back)) {
		t.Fatalf("a named preset token is not among the camera's presets for this profile (%d listed)", len(pd.Presets))
	}
	_ = text

	// 3. One real move.
	no := false
	env, _ = move(preset, &no)
	if env.Error != nil {
		t.Fatalf("real move failed: %s (the camera may or may not have moved; check it by hand)", env.Error.Code)
	}
	d = gotoOut{}
	_ = json.Unmarshal(env.Data, &d)
	if !d.Executed {
		t.Errorf("dry_run=false did not execute")
	}

	// 4. An immediate second real move must be refused by the rate limiter,
	// never reach the camera.
	env, _ = move(preset, &no)
	if env.Error == nil || env.Error.Code != "blocked_by_policy" {
		t.Errorf("a second move inside the rate window must be blocked_by_policy")
	}

	// 5. Verify through ptz.status that the camera settles. goto_preset only
	// reports that the camera answered the command.
	settled := false
	for i := 0; i < 30 && !settled; i++ {
		time.Sleep(time.Second)
		env, _ = hwCall(t, cs, "ptz.status", map[string]any{"camera": camID, "profile": profile})
		if env.Error != nil {
			t.Errorf("ptz.status after move: %s", env.Error.Code)
			break
		}
		var st struct {
			PanTiltState string `json:"pan_tilt_state"`
			ZoomState    string `json:"zoom_state"`
			DeviceError  string `json:"device_error"`
		}
		_ = json.Unmarshal(env.Data, &st)
		if st.DeviceError != "" {
			t.Errorf("camera reports a PTZ error after the move")
		}
		settled = !strings.EqualFold(st.PanTiltState, "MOVING") && !strings.EqualFold(st.ZoomState, "MOVING")
	}
	if !settled {
		t.Errorf("camera still reports MOVING after 30s")
	}

	// 6. Optionally go back. Real moves are limited to one per interval, so
	// wait past it; the dry run first keeps the same checks as above.
	if back != "" {
		time.Sleep(safety.DefaultInterval + time.Second)
		if env, _ = move(back, nil); env.Error != nil {
			t.Fatalf("return dry run failed: %s", env.Error.Code)
		}
		env, _ = move(back, &no)
		if env.Error != nil {
			t.Fatalf("return move failed: %s (check the camera by hand)", env.Error.Code)
		}
		time.Sleep(2 * time.Second)
		env, _ = hwCall(t, cs, "ptz.status", map[string]any{"camera": camID, "profile": profile})
		if env.Error != nil {
			t.Errorf("ptz.status after return: %s", env.Error.Code)
		}
	}
}

// TestHardwareRelativeNudge physically moves one camera by a small relative
// amount and back, then calls ptz.stop. NOT YET RUN against hardware.
//
// It skips unless ONVIF_MCP_HW_NUDGE is exactly <camera-id>:<profile-token>. The
// OPERATOR must confirm the camera may move a little in both directions from
// where it is now and that nobody depends on its view during the run.
//
// Both gates are enabled in memory for the named camera only. It sends +0.05 on
// pan, waits past the per-device rate-limit interval (a second real move inside
// it would be refused), sends -0.05, and calls ptz.stop. Whatever the camera
// reports is logged as a code or a status only; the test does not judge where
// the camera ended up.
func TestHardwareRelativeNudge(t *testing.T) {
	spec := os.Getenv("ONVIF_MCP_HW_NUDGE")
	if spec == "" {
		t.Skip("ONVIF_MCP_HW_NUDGE not set; this test physically moves a camera")
	}
	parts := strings.Split(spec, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		t.Fatal("ONVIF_MCP_HW_NUDGE must be <camera-id>:<profile-token>")
	}
	camID, profile := parts[0], parts[1]

	cfg := hwConfig(t)
	cam, ok := cfg.Cameras[camID]
	if !ok {
		t.Fatalf("camera %q is not in the hardware config", camID)
	}
	cfg.ControlEnabled = true
	cam.Control = true
	cs := hwSession(t, cfg)

	nudge := func(pan float64, dry *bool) hwEnvelope {
		m := map[string]any{"camera": camID, "profile": profile, "pan": pan}
		if dry != nil {
			m["dry_run"] = *dry
		}
		env, _ := hwCall(t, cs, "ptz.move_relative", m)
		return env
	}
	// Whatever happens, ask for a stop at the end.
	defer func() {
		env, _ := hwCall(t, cs, "ptz.stop", map[string]any{"camera": camID, "profile": profile})
		if env.Error != nil {
			t.Errorf("ptz.stop failed: %s (check the camera by hand)", env.Error.Code)
			return
		}
		var d struct {
			StopStatus string `json:"stop_status"`
		}
		_ = json.Unmarshal(env.Data, &d)
		t.Logf("ptz.stop: %s", d.StopStatus)
	}()

	// 1. Omitting dry_run must simulate and send nothing.
	env := nudge(0.05, nil)
	var d struct {
		Executed bool `json:"executed"`
		DryRun   bool `json:"dry_run"`
	}
	_ = json.Unmarshal(env.Data, &d)
	if env.Error != nil || d.Executed || !d.DryRun {
		t.Fatalf("default call must be a dry run that does not execute (error present: %t)", env.Error != nil)
	}

	// 2. A value over the cap is refused by the server, not the camera.
	if env := nudge(0.5, nil); env.Error == nil || env.Error.Code != "invalid_argument" {
		t.Errorf("a pan of 0.5 must be refused with invalid_argument")
	}

	// 3. +0.05, wait out the limiter, -0.05.
	no := false
	for i, pan := range []float64{0.05, -0.05} {
		if i > 0 {
			time.Sleep(safety.DefaultInterval + time.Second)
		}
		env = nudge(pan, &no)
		if env.Error != nil {
			t.Fatalf("nudge %d failed: %s (the camera may or may not have moved; check it by hand)", i+1, env.Error.Code)
		}
		d.Executed = false
		_ = json.Unmarshal(env.Data, &d)
		if !d.Executed {
			t.Errorf("nudge %d: dry_run=false did not execute", i+1)
		}
		time.Sleep(2 * time.Second)
	}
}
