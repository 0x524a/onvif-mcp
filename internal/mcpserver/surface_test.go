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

const writeTool = "ptz.goto_preset"

func listTools(t *testing.T, control bool) []*mcp.Tool {
	t.Helper()
	cs := policyServer(t, func(r *registry.Registry) *safety.Policy { return testPolicy(r, control) })
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

// The counts are exact on purpose: a twelfth tool must force a decision.
func TestAllElevenToolsListedWhenControlEnabled(t *testing.T) {
	got := names(listTools(t, true))
	want := sorted(append(append([]string(nil), readTools...), writeTool))
	if len(got) != 11 || !equal(got, want) {
		t.Fatalf("control on: tools = %v, want exactly %v", got, want)
	}
}

func TestTenReadToolsListedWhenControlDisabled(t *testing.T) {
	got := names(listTools(t, false))
	if len(got) != 10 || !equal(got, sorted(readTools)) {
		t.Fatalf("control off: tools = %v, want exactly %v", got, sorted(readTools))
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
		file    string
		control bool
	}{{"tools_list_control_off.golden.json", false}, {"tools_list_control_on.golden.json", true}} {
		t.Run(mode.file, func(t *testing.T) {
			got, err := json.MarshalIndent(listTools(t, mode.control), "", "  ")
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
