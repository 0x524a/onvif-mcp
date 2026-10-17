package mcpserver

import (
	"context"
	"encoding/json"
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
	cam := testcam.Start(t)
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a":     {ID: "cam-a", Endpoint: cam.Endpoint(), Username: cam.Username(), Password: cam.Password(), Control: true},
		"cam-fixed": {ID: "cam-fixed", Endpoint: cam.Endpoint(), Username: cam.Username(), Password: cam.Password()},
	}})
	return connect(t, New(reg, quietLog(), p(reg)))
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

// No production write tool is registered in this phase, with control on or off.
func TestNoWriteToolIsRegisteredYet(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cs := policyServer(t, func(r *registry.Registry) *safety.Policy { return testPolicy(r, enabled) })
		res, err := cs.ListTools(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, tool := range res.Tools {
			if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
				t.Errorf("control=%v: %s is not read-only", enabled, tool.Name)
			}
		}
		if m := readPolicy(t, cs); len(m["gated_write_tools"].([]any)) != 0 {
			t.Errorf("gated tools = %v", m["gated_write_tools"])
		}
	}
}
