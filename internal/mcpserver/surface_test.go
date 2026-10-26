package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
)

var update = flag.Bool("update", false, "rewrite the tools/list golden files")

var readTools = []string{
	"camera.list", "camera.discover", "camera.describe",
	"media.profiles", "media.stream_uri", "stream.inspect",
	"camera.snapshot", "ptz.status", "ptz.presets", "imaging.settings",
}

// gatedSurface are the tools a server registers only with control on.
var gatedSurface = []string{"ptz.goto_preset", "ptz.move_relative", "ptz.stop"}

const writeTool = "ptz.goto_preset"

// continuousTool is registered only when a camera attests ptz_honours_timeout.
const continuousTool = "ptz.move_continuous"

func listTools(t *testing.T, control bool) []*mcp.Tool {
	t.Helper()
	return listToolsOf(t, policyServer(t, func(r *registry.Registry) *safety.Policy { return testPolicy(r, control) }))
}

// listToolsAttested is listTools over a config whose cam-a also sets
// ptz_honours_timeout.
func listToolsAttested(t *testing.T, control bool) []*mcp.Tool {
	t.Helper()
	return listToolsOf(t, attestedPolicyServer(t, func(r *registry.Registry) *safety.Policy { return testPolicy(r, control) }))
}

func listToolsOf(t *testing.T, cs *mcp.ClientSession) []*mcp.Tool {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(res.Tools, func(i, j int) bool { return res.Tools[i].Name < res.Tools[j].Name })
	return res.Tools
}

func names(tools []*mcp.Tool) []string {
	out := make([]string, 0, len(tools))
	for _, tl := range tools {
		out = append(out, tl.Name)
	}
	sort.Strings(out)
	return out
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The counts are exact on purpose: a fourteenth tool must force a decision.
func TestAllThirteenToolsListedWhenControlEnabled(t *testing.T) {
	got := names(listTools(t, true))
	want := sorted(append(append([]string(nil), readTools...), gatedSurface...))
	if len(got) != 13 || !equal(got, want) {
		t.Fatalf("control on: tools = %v, want exactly %v", got, want)
	}
}

// ptz.move_continuous needs a camera that attests ptz_honours_timeout as well as
// control: then there are fourteen tools, and without control still ten.
func TestFourteenToolsListedWhenACameraAttestsTheTimeout(t *testing.T) {
	got := names(listToolsAttested(t, true))
	want := sorted(append(append(append([]string(nil), readTools...), gatedSurface...), continuousTool))
	if len(got) != 14 || !equal(got, want) {
		t.Fatalf("control on, attested: tools = %v, want exactly %v", got, want)
	}
	if got := names(listToolsAttested(t, false)); !equal(got, sorted(readTools)) {
		t.Fatalf("control off, attested: tools = %v", got)
	}
}

func TestTenReadToolsListedWhenControlDisabled(t *testing.T) {
	got := names(listTools(t, false))
	if len(got) != 10 || !equal(got, sorted(readTools)) {
		t.Fatalf("control off: tools = %v, want exactly %v", got, sorted(readTools))
	}
}

// The control-off surface is exactly the v0.1 read surface: the new motion tools
// add nothing an agent can see without the operator's opt-in.
func TestControlOffSurfaceIsUnchangedFromV01AndMotionToolsAreNamedByThePolicy(t *testing.T) {
	got := names(listTools(t, false))
	if !equal(got, sorted(readTools)) {
		t.Fatalf("control-off tools = %v", got)
	}
	cs := policyServer(t, func(r *registry.Registry) *safety.Policy { return testPolicy(r, false) })
	res, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: safety.PolicyURI})
	if err != nil {
		t.Fatal(err)
	}
	body := res.Contents[0].Text
	for _, name := range []string{"ptz.move_relative", "ptz.stop", continuousTool, "ptz_honours_timeout"} {
		if !bytes.Contains([]byte(body), []byte(name)) {
			t.Errorf("the policy resource must name %s: %s", name, body)
		}
	}
}

func TestMotionToolAnnotationsAreExplicit(t *testing.T) {
	want := map[string]struct{ destructive, idempotent bool }{
		"ptz.goto_preset":   {true, true},
		"ptz.move_relative": {true, false},
		"ptz.stop":          {false, true},
		continuousTool:      {true, false},
	}
	seen := 0
	for _, tl := range listToolsAttested(t, true) {
		w, ok := want[tl.Name]
		if !ok {
			continue
		}
		seen++
		a := tl.Annotations
		if a == nil || a.ReadOnlyHint || a.DestructiveHint == nil || *a.DestructiveHint != w.destructive ||
			a.IdempotentHint != w.idempotent || a.OpenWorldHint == nil || *a.OpenWorldHint || a.Title == "" {
			t.Errorf("%s annotations = %+v", tl.Name, a)
		}
	}
	if seen != len(want) {
		t.Errorf("saw %d of %d motion tools", seen, len(want))
	}
}

func TestWriteToolAnnotationsAreExplicit(t *testing.T) {
	for _, tl := range listTools(t, true) {
		if tl.Name != writeTool {
			continue
		}
		a := tl.Annotations
		if a == nil || a.ReadOnlyHint || a.DestructiveHint == nil || !*a.DestructiveHint ||
			a.OpenWorldHint == nil || *a.OpenWorldHint || a.Title == "" {
			t.Fatalf("%s annotations = %+v", writeTool, a)
		}
		return
	}
	t.Fatalf("%s not listed with control on", writeTool)
}

// TestToolsListSnapshot pins the whole advertised surface (names,
// descriptions, annotations and schemas) for both modes. Run
// `go test ./internal/mcpserver -run ToolsListSnapshot -update` after a
// deliberate change and review the diff.
func TestToolsListSnapshot(t *testing.T) {
	for _, mode := range []struct {
		file            string
		control, attest bool
	}{
		{"tools_list_control_off.golden.json", false, false},
		{"tools_list_control_on.golden.json", true, false},
		{"tools_list_control_on_attested.golden.json", true, true},
	} {
		t.Run(mode.file, func(t *testing.T) {
			list := listTools
			if mode.attest {
				list = listToolsAttested
			}
			got, err := json.MarshalIndent(list(t, mode.control), "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			path := filepath.Join("testdata", mode.file)
			if *update {
				if err := os.MkdirAll("testdata", 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path) //nolint:gosec // fixed golden path under testdata
			if err != nil {
				t.Fatalf("read golden (run with -update to create): %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("tools/list differs from %s; review and rerun with -update if intended", path)
			}
		})
	}
}
