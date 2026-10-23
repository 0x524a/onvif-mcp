package safety

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type policyBody struct {
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

// readPolicy serves p over an in-memory transport and reads the resource.
func readPolicy(t *testing.T, p *Policy) (policyBody, string) {
	t.Helper()
	return readPolicyWith(t, p, []CameraGrant{{ID: "cam-a", ControlAllowed: true}})
}

func readPolicyWith(t *testing.T, p *Policy, grants []CameraGrant) (policyBody, string) {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterPolicyResource(srv, p, func() []CameraGrant { return grants })
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()

	res, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: PolicyURI})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if len(res.Contents) != 1 {
		t.Fatalf("contents = %d", len(res.Contents))
	}
	var b policyBody
	if err := json.Unmarshal([]byte(res.Contents[0].Text), &b); err != nil {
		t.Fatalf("body is not JSON: %v: %s", err, res.Contents[0].Text)
	}
	return b, res.Contents[0].Text
}

func TestPolicyResourceExplainsDisabledControl(t *testing.T) {
	p, _, _ := newPolicy(false)
	p.NoteGated("some.write_tool")
	b, raw := readPolicy(t, p)
	if b.Mode != "read-only" || b.ControlEnabled {
		t.Errorf("mode=%q control_enabled=%v", b.Mode, b.ControlEnabled)
	}
	if len(b.GatedWriteTools) != 1 || b.GatedWriteTools[0] != "some.write_tool" {
		t.Errorf("gated tools = %v", b.GatedWriteTools)
	}
	if !strings.Contains(b.HowToEnable, "enable-control") {
		t.Errorf("how_to_enable must name the flag: %q", b.HowToEnable)
	}
	if !b.DryRunDefault {
		t.Error("dry_run_default must be true")
	}
	if len(b.Cameras) != 1 || b.Cameras[0].ID != "cam-a" {
		t.Errorf("cameras = %+v", b.Cameras)
	}
	if strings.Contains(raw, "ptz.goto_preset") {
		t.Errorf("tool names must come from what was registered, not a literal: %s", raw)
	}
}

func TestPolicyResourceReflectsEnabledControl(t *testing.T) {
	p, _, _ := newPolicy(true)
	b, _ := readPolicy(t, p)
	if b.Mode != "control-enabled" || !b.ControlEnabled {
		t.Errorf("mode=%q control_enabled=%v", b.Mode, b.ControlEnabled)
	}
}

func TestPolicyResourceGatedListIsSortedDedupedAndNeverNull(t *testing.T) {
	p, _, _ := newPolicy(false)
	b, raw := readPolicy(t, p)
	if len(b.GatedWriteTools) != 0 || !strings.Contains(raw, `"gated_write_tools": []`) {
		t.Errorf("an empty list must serialise as []: %s", raw)
	}
	p.NoteGated("b.tool")
	p.NoteGated("a.tool")
	p.NoteGated("b.tool")
	b, _ = readPolicy(t, p)
	if len(b.GatedWriteTools) != 2 || b.GatedWriteTools[0] != "a.tool" || b.GatedWriteTools[1] != "b.tool" {
		t.Errorf("gated tools = %v", b.GatedWriteTools)
	}
}

func TestPolicyResourceRateLimitComesFromTheLimiter(t *testing.T) {
	p, _, _ := newPolicy(true) // interval 1h, burst 1
	b, _ := readPolicy(t, p)
	if !strings.Contains(b.RateLimitPerCamera, "1h0m0s") || !strings.Contains(b.RateLimitPerCamera, "burst 1") {
		t.Errorf("rate limit = %q", b.RateLimitPerCamera)
	}
	p.Limiter = NewLimiter(7*time.Second, 4)
	b, _ = readPolicy(t, p)
	if !strings.Contains(b.RateLimitPerCamera, "7s") || !strings.Contains(b.RateLimitPerCamera, "burst 4") {
		t.Errorf("rate limit = %q", b.RateLimitPerCamera)
	}
	p.Limiter = nil
	b, _ = readPolicy(t, p)
	if !strings.Contains(b.RateLimitPerCamera, "no real movement") {
		t.Errorf("a missing limiter must be stated: %q", b.RateLimitPerCamera)
	}
}

func TestPolicyResourceNilPolicyReportsReadOnly(t *testing.T) {
	b, _ := readPolicy(t, nil)
	if b.Mode != "read-only" || b.ControlEnabled {
		t.Errorf("mode=%q control_enabled=%v", b.Mode, b.ControlEnabled)
	}
}

func TestNoteGatedIsNilSafe(t *testing.T) {
	var p *Policy
	p.NoteGated("x")
	if len(p.GatedTools()) != 0 {
		t.Error("nil policy has no gated tools")
	}
}

func TestLimiterReportsItsConfiguration(t *testing.T) {
	l := NewLimiter(3*time.Second, 5)
	if l.Interval() != 3*time.Second || l.Burst() != 5 {
		t.Errorf("interval=%v burst=%d", l.Interval(), l.Burst())
	}
	d := NewLimiter(0, 0)
	if d.Interval() != DefaultInterval || d.Burst() != DefaultBurst {
		t.Errorf("defaults: interval=%v burst=%d", d.Interval(), d.Burst())
	}
}

func TestPolicyResourceStatesWhyWriteToolsAreGated(t *testing.T) {
	for _, on := range []bool{false, true} {
		p, _, _ := newPolicy(on)
		b, _ := readPolicy(t, p)
		for _, w := range []string{"physically", "loop", "wear", "opt"} {
			if !strings.Contains(strings.ToLower(b.Why), w) {
				t.Errorf("control=%v: why = %q, want it to mention %q", on, b.Why, w)
			}
		}
	}
}

func TestPolicyResourceSaysPlainlyWhenNoWriteToolExists(t *testing.T) {
	p, _, _ := newPolicy(false)
	b, _ := readPolicy(t, p)
	for name, text := range map[string]string{"explanation": b.Explanation, "how_to_enable": b.HowToEnable} {
		if !strings.Contains(text, "registers no write tool") {
			t.Errorf("%s = %q, want it to say this build registers no write tool", name, text)
		}
	}
	if !strings.Contains(b.Explanation, "changes nothing") {
		t.Errorf("explanation = %q", b.Explanation)
	}

	p.NoteGated("some.write_tool")
	b, _ = readPolicy(t, p)
	for name, text := range map[string]string{"explanation": b.Explanation, "how_to_enable": b.HowToEnable} {
		if strings.Contains(text, "registers no write tool") || strings.Contains(text, "changes nothing") {
			t.Errorf("%s = %q must not claim there are no write tools", name, text)
		}
	}
	if !strings.Contains(b.HowToEnable, "enable-control") || !strings.Contains(b.HowToEnable, `"control": true`) {
		t.Errorf("how_to_enable = %q", b.HowToEnable)
	}
}

func TestPolicyResourceCamerasReportWhetherTheyAreWritableNow(t *testing.T) {
	grants := []CameraGrant{{ID: "cam-a", ControlAllowed: true}, {ID: "cam-b", ControlAllowed: false}}
	for _, tc := range []struct {
		control bool
		want    map[string]bool
	}{
		{false, map[string]bool{"cam-a": false, "cam-b": false}},
		{true, map[string]bool{"cam-a": true, "cam-b": false}},
	} {
		p, _, _ := newPolicy(tc.control)
		b, raw := readPolicyWith(t, p, grants)
		if !strings.Contains(raw, `"writable"`) {
			t.Fatalf("no writable field: %s", raw)
		}
		for _, c := range b.Cameras {
			if c.Writable != tc.want[c.ID] {
				t.Errorf("control=%v %s writable=%v, want %v", tc.control, c.ID, c.Writable, tc.want[c.ID])
			}
		}
		if !strings.Contains(b.Explanation, "control_allowed") || !strings.Contains(b.Explanation, "control_enabled") {
			t.Errorf("explanation must say control_allowed only matters when control_enabled: %q", b.Explanation)
		}
	}
}

// Once control is enabled, the policy must not tell an agent to restart with
// the flag it already has; it names what is still missing, per camera.
func TestPolicyResourceWhenEnabledNamesWhatIsStillMissing(t *testing.T) {
	p, _, _ := newPolicy(true)
	p.NoteGated("some.write_tool")
	grants := []CameraGrant{{ID: "cam-a", ControlAllowed: true}, {ID: "cam-b", ControlAllowed: false}}
	b, _ := readPolicyWith(t, p, grants)
	if strings.Contains(b.HowToEnable, "--enable-control") {
		t.Errorf("how_to_enable asks for a flag that is already set: %q", b.HowToEnable)
	}
	for _, want := range []string{"cam-b", `"control": true`, "restart"} {
		if !strings.Contains(b.HowToEnable, want) {
			t.Errorf("how_to_enable = %q, want %q", b.HowToEnable, want)
		}
	}
	if strings.Contains(b.HowToEnable, "cam-a") {
		t.Errorf("how_to_enable names a camera that is already writable: %q", b.HowToEnable)
	}
	if strings.Contains(b.Why, "off unless") {
		t.Errorf("why says write tools are off, but control is enabled: %q", b.Why)
	}

	all, _ := readPolicyWith(t, p, []CameraGrant{{ID: "cam-a", ControlAllowed: true}})
	if !strings.Contains(all.HowToEnable, "nothing more") || strings.Contains(all.HowToEnable, "restart") {
		t.Errorf("every camera is writable, so nothing is missing: %q", all.HowToEnable)
	}
}

func TestPolicyResourceNamesHaltToolsAndSaysTheyHaveNoDryRunOrRateLimit(t *testing.T) {
	p, _, _ := newPolicy(true)
	p.NoteGated("ptz.goto_preset")
	p.NoteHalt("ptz.stop")
	body, raw := readPolicy(t, p)
	if len(body.GatedWriteTools) != 2 || body.GatedWriteTools[1] != "ptz.stop" {
		t.Errorf("gated = %v", body.GatedWriteTools)
	}
	for _, want := range []string{`"halt_tools"`, "ptz.stop", "no dry run", "not rate limited"} {
		if !strings.Contains(raw, want) {
			t.Errorf("policy lacks %q: %s", want, raw)
		}
	}
	// Without a halt tool the sentence is absent.
	q, _, _ := newPolicy(true)
	q.NoteGated("ptz.goto_preset")
	if _, raw := readPolicy(t, q); strings.Contains(raw, "not rate limited") {
		t.Errorf("no halt tool, yet the policy talks about one: %s", raw)
	}
}

const writesUnavailableText = "write tools are not offered on this transport"

func TestPolicyResourceWithWritesUnavailable(t *testing.T) {
	// A policy whose control flag is (wrongly) on must still report read-only
	// when the transport offers no write tool, and must not advise --enable-control.
	p, _, _ := newPolicy(true)
	p.NoteGated("ptz.goto_preset")
	p.NoteHalt("ptz.stop")
	p.WritesUnavailable = writesUnavailableText
	b, raw := readPolicyWith(t, p, []CameraGrant{{ID: "cam-a", ControlAllowed: true}, {ID: "cam-b"}})
	if b.Mode != "read-only" || b.ControlEnabled {
		t.Errorf("mode=%q control_enabled=%v", b.Mode, b.ControlEnabled)
	}
	if len(b.GatedWriteTools) != 0 {
		t.Errorf("gated_write_tools must be empty, got %v", b.GatedWriteTools)
	}
	if b.HowToEnable != writesUnavailableText {
		t.Errorf("how_to_enable = %q", b.HowToEnable)
	}
	for _, c := range b.Cameras {
		if c.Writable {
			t.Errorf("camera %s reported writable", c.ID)
		}
		if c.ControlAllowed {
			t.Errorf("camera %s discloses its config-level control opt-in", c.ID)
		}
	}
	for _, bad := range []string{"--enable-control", "ptz.goto_preset", "ptz.stop", "ptz.move_relative"} {
		if strings.Contains(raw, bad) {
			t.Errorf("document mentions %q: %s", bad, raw)
		}
	}
	// Identical for every caller: the resource is a pure function of the policy.
	_, raw2 := readPolicyWith(t, p, []CameraGrant{{ID: "cam-a", ControlAllowed: true}, {ID: "cam-b"}})
	if raw != raw2 {
		t.Error("document differs between reads")
	}
}
