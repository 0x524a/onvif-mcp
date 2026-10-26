package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
	"github.com/0x524a/onvif-mcp/internal/testcam"
)

// testPolicy builds the policy main builds, with the audit trail discarded.
func testPolicy(reg *registry.Registry, control bool) *safety.Policy {
	return safety.NewPolicy(safety.PolicyOptions{ControlEnabled: control, Cameras: reg, Log: quietLog()})
}

func policyServer(t *testing.T, p func(*registry.Registry) *safety.Policy) *mcp.ClientSession {
	t.Helper()
	return policyServerWith(t, false, p)
}

// attestedPolicyServer is policyServer with cam-a also setting
// ptz_honours_timeout.
func attestedPolicyServer(t *testing.T, p func(*registry.Registry) *safety.Policy) *mcp.ClientSession {
	t.Helper()
	return policyServerWith(t, true, p)
}

func policyServerWith(t *testing.T, attest bool, p func(*registry.Registry) *safety.Policy) *mcp.ClientSession {
	t.Helper()
	cam := testcam.Start(t)
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a": {ID: "cam-a", Endpoint: cam.Endpoint(), Username: cam.Username(), Password: cam.Password(), Control: true,
			PTZHonoursTimeout: attest},
		"cam-fixed": {ID: "cam-fixed", Endpoint: cam.Endpoint(), Username: cam.Username(), Password: cam.Password()},
	}})
	return connect(t, newOp(reg, quietLog(), p(reg)))
}

func readPolicy(t *testing.T, cs *mcp.ClientSession) map[string]any {
	t.Helper()
	res, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: safety.PolicyURI})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(res.Contents[0].Text), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPolicyResourceIsRegisteredWhetherOrNotControlIsEnabled(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cs := policyServer(t, func(r *registry.Registry) *safety.Policy { return testPolicy(r, enabled) })
		lr, err := cs.ListResources(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, r := range lr.Resources {
			found = found || r.URI == safety.PolicyURI
		}
		if !found {
			t.Fatalf("control=%v: policy resource not listed", enabled)
		}
		m := readPolicy(t, cs)
		if m["control_enabled"] != enabled {
			t.Errorf("control=%v: control_enabled = %v", enabled, m["control_enabled"])
		}
		wantMode := "read-only"
		if enabled {
			wantMode = "control-enabled"
		}
		if m["mode"] != wantMode {
			t.Errorf("mode = %v", m["mode"])
		}
		cams, _ := m["cameras"].([]any)
		if len(cams) != 2 {
			t.Fatalf("cameras = %v", m["cameras"])
		}
		grants := map[string]bool{}
		for _, c := range cams {
			cm := c.(map[string]any)
			grants[cm["id"].(string)] = cm["control_allowed"].(bool)
		}
		if !grants["cam-a"] || grants["cam-fixed"] {
			t.Errorf("per-camera grants = %v", grants)
		}
		if rl, _ := m["rate_limit_per_camera"].(string); !strings.Contains(rl, "2s") || !strings.Contains(rl, "burst 1") {
			t.Errorf("rate limit text = %q", rl)
		}
	}
}

func TestNilPolicyFailsClosedAndStillServesTheResource(t *testing.T) {
	cs := policyServer(t, func(*registry.Registry) *safety.Policy { return nil })
	if m := readPolicy(t, cs); m["control_enabled"] != false || m["mode"] != "read-only" {
		t.Errorf("policy = %v", m)
	}
}

// The gated tools are ptz.goto_preset, ptz.move_relative and ptz.stop. With
// control off an agent cannot see them in tools/list, but the policy resource
// names them and explains the gate.
func TestWriteToolIsHiddenWithControlOffButNamedByThePolicy(t *testing.T) {
	cs := policyServer(t, func(r *registry.Registry) *safety.Policy { return testPolicy(r, false) })
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range res.Tools {
		if tool.Name == "ptz.goto_preset" {
			t.Fatal("ptz.goto_preset must not be listed while control is off")
		}
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s is not read-only", tool.Name)
		}
	}
	m := readPolicy(t, cs)
	gated, _ := m["gated_write_tools"].([]any)
	if !anyEqual(gated, gatedTools) {
		t.Fatalf("gated_write_tools = %v, want %v", m["gated_write_tools"], gatedTools)
	}
	if halts, _ := m["halt_tools"].([]any); len(halts) != 1 || halts[0] != "ptz.stop" {
		t.Errorf("halt_tools = %v", m["halt_tools"])
	}
	if ex, _ := m["explanation"].(string); !strings.Contains(ex, "no dry run") || !strings.Contains(ex, "not rate limited") {
		t.Errorf("the policy must say ptz.stop has no dry run and is not rate limited: %q", ex)
	}
	for _, k := range []string{"explanation", "how_to_enable"} {
		txt, _ := m[k].(string)
		if strings.Contains(txt, "registers no write tool") || strings.Contains(txt, "changes nothing") {
			t.Errorf("%s still claims there is no write tool: %q", k, txt)
		}
	}
	if how, _ := m["how_to_enable"].(string); !strings.Contains(how, "--enable-control") {
		t.Errorf("how_to_enable = %q", how)
	}
}

func TestWriteToolIsListedWithControlOnAndWritableCamerasAreReported(t *testing.T) {
	// cam-a attests ptz_honours_timeout, so every gated tool is registered.
	cs := attestedPolicyServer(t, func(r *registry.Registry) *safety.Policy { return testPolicy(r, true) })
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var writes []string
	for _, tool := range res.Tools {
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			writes = append(writes, tool.Name)
		}
	}
	sort.Strings(writes)
	if !equal(writes, gatedTools) {
		t.Fatalf("non-read-only tools = %v, want exactly %v", writes, gatedTools)
	}
	m := readPolicy(t, cs)
	if gated, _ := m["gated_write_tools"].([]any); !anyEqual(gated, gatedTools) {
		t.Errorf("gated_write_tools = %v", m["gated_write_tools"])
	}
	writable := map[string]bool{}
	for _, c := range m["cameras"].([]any) {
		cm := c.(map[string]any)
		writable[cm["id"].(string)] = cm["writable"].(bool)
	}
	if !writable["cam-a"] || writable["cam-fixed"] {
		t.Errorf("writable = %v", writable)
	}
}

// A string dry_run is a schema violation, not "false": the middleware answers
// with the invalid_argument envelope and the handler never runs.
func TestWriteToolRejectsAStringDryRunWithTheEnvelope(t *testing.T) {
	cs := policyServer(t, func(r *registry.Registry) *safety.Policy { return testPolicy(r, true) })
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "ptz.goto_preset",
		Arguments: map[string]any{"camera": "cam-a", "profile": "p", "preset": "q", "dry_run": "false"}})
	if err != nil {
		t.Fatal(err)
	}
	e, _ := res.StructuredContent.(map[string]any)["error"].(map[string]any)
	if !res.IsError || e["code"] != "invalid_argument" {
		t.Fatalf("result = %+v", res)
	}
}

// gatedTools are every tool that needs control: three writes and the halt tool.
// The policy names every gated tool, including ptz.move_continuous, which is
// registered only when a camera attests ptz_honours_timeout.
var gatedTools = []string{"ptz.goto_preset", "ptz.move_continuous", "ptz.move_relative", "ptz.stop"}

func anyEqual(got []any, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// The policy resource is part of the agent-facing surface: its full text is
// pinned like tools/list. Regenerate with -update when the change is intended.
func TestPolicyResourceSnapshot(t *testing.T) {
	for _, mode := range []struct {
		file    string
		control bool
	}{{"policy_control_off.golden.json", false}, {"policy_control_on.golden.json", true}} {
		t.Run(mode.file, func(t *testing.T) {
			cs := policyServer(t, func(r *registry.Registry) *safety.Policy { return testPolicy(r, mode.control) })
			res, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: safety.PolicyURI})
			if err != nil {
				t.Fatal(err)
			}
			got := []byte(res.Contents[0].Text + "\n")
			path := filepath.Join("testdata", mode.file)
			if *update {
				if err := os.WriteFile(path, got, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path) //nolint:gosec // fixed golden path under testdata
			if err != nil {
				t.Fatalf("read golden (run with -update to create): %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("policy resource differs from %s; review and rerun with -update if intended", path)
			}
		})
	}
}
