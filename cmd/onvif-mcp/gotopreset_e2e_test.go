package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0x524a/onvif-mcp/internal/testcam"
)

// toolNamesOver returns the names in tools/list on an initialised session.
func (s *session) toolNamesOver(id int) map[string]bool {
	s.t.Helper()
	s.send(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/list"})
	tl, _ := s.recv()["result"].(map[string]any)["tools"].([]any)
	names := map[string]bool{}
	for _, x := range tl {
		names[x.(map[string]any)["name"].(string)] = true
	}
	return names
}

// callOver calls a tool and returns its result object.
func (s *session) callOver(id int, name string, args map[string]any) map[string]any {
	s.t.Helper()
	s.send(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{
		"name": name, "arguments": args}})
	res, _ := s.recv()["result"].(map[string]any)
	if res == nil {
		s.t.Fatalf("%s: no result", name)
	}
	return res
}

func controlConfig(t *testing.T, cam *testcam.Cam) string {
	t.Helper()
	body := fmt.Sprintf(`{"cameras":{"cam1":{"endpoint":%q,"username":%q,"password":%q,"control":true}}}`,
		cam.Endpoint(), cam.Username(), cam.Password())
	p := filepath.Join(t.TempDir(), "cameras.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The whole safety model over the real binary and real stdio: a dry run leaves
// the virtual camera where it was, only dry_run false moves it, and the audit
// trail on stderr records both without leaking the password.
func TestGotoPresetOverStdioDryRunThenRealMove(t *testing.T) {
	cam := testcam.Start(t)
	s, se := startSession(t, controlConfig(t, cam), "-enable-control")
	s.initialize()
	if !s.toolNamesOver(2)["ptz.goto_preset"] {
		t.Fatal("ptz.goto_preset must be listed with -enable-control")
	}
	start := cam.PTZPosition()
	args := map[string]any{"camera": "cam1", "profile": cam.ProfileToken(), "preset": cam.PresetToken()}

	dry := s.callOver(3, "ptz.goto_preset", args)
	if dry["isError"] == true {
		t.Fatalf("dry run failed: %v", dry)
	}
	dd, _ := dry["structuredContent"].(map[string]any)["data"].(map[string]any)
	if dd["executed"] != false || dd["dry_run"] != true {
		t.Fatalf("dry run data = %v", dd)
	}
	if got := cam.PTZPosition(); got != start {
		t.Fatalf("the dry run moved the camera: %+v -> %+v", start, got)
	}

	args["dry_run"] = false
	moved := s.callOver(4, "ptz.goto_preset", args)
	if moved["isError"] == true {
		t.Fatalf("real move failed: %v", moved)
	}
	rd, _ := moved["structuredContent"].(map[string]any)["data"].(map[string]any)
	if rd["executed"] != true {
		t.Fatalf("real move data = %v", rd)
	}
	if got := cam.PTZPosition(); got == start {
		t.Fatal("the real call did not move the camera")
	}

	_ = s.stdin.Close()
	if code, ok := s.wait(15 * time.Second); !ok || code != 0 {
		t.Fatalf("ok=%v code=%d stderr=%s", ok, code, se)
	}

	var attempts []string
	for _, l := range strings.Split(se.String(), "\n") {
		if strings.Contains(l, `msg="write attempt"`) {
			attempts = append(attempts, l)
		}
	}
	if len(attempts) != 2 {
		t.Fatalf("want 2 audit lines, got %d:\n%s", len(attempts), se.String())
	}
	for i, want := range [][]string{
		{"tool=ptz.goto_preset", "camera=cam1", "dry_run=true", "executed=false", "outcome=dry_run", "target=" + cam.PresetToken()},
		{"tool=ptz.goto_preset", "camera=cam1", "dry_run=false", "executed=true", "outcome=ok", "target=" + cam.PresetToken()},
	} {
		for _, w := range want {
			if !strings.Contains(attempts[i], w) {
				t.Errorf("audit line %d lacks %q: %s", i, w, attempts[i])
			}
		}
	}
	if strings.Contains(se.String(), cam.Password()) {
		t.Error("password present on stderr")
	}
	for _, l := range s.all {
		if strings.Contains(l, cam.Password()) {
			t.Fatal("password present on stdout")
		}
	}
}

func TestGotoPresetOverStdioIsAbsentWithoutTheFlag(t *testing.T) {
	cam := testcam.Start(t)
	s, se := startSession(t, controlConfig(t, cam))
	s.initialize()
	if s.toolNamesOver(2)["ptz.goto_preset"] {
		t.Fatal("ptz.goto_preset must not be listed without -enable-control, even for a camera that opted in")
	}
	_ = s.stdin.Close()
	if code, ok := s.wait(15 * time.Second); !ok || code != 0 {
		t.Fatalf("ok=%v code=%d stderr=%s", ok, code, se)
	}
}
