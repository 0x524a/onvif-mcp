package main

import (
	"math"
	"strings"
	"testing"

	"github.com/0x524a/onvif-mcp/internal/testcam"
)

// The motion tools over the real binary and real stdio: with control off neither
// is listed; with control on a relative move is a dry run by default, only
// dry_run false moves the virtual camera, and ptz.stop answers.
func TestMotionToolsOverStdio(t *testing.T) {
	cam := testcam.Start(t)

	off, _ := startSession(t, controlConfig(t, cam))
	off.initialize()
	names := off.toolNamesOver(2)
	if names["ptz.move_relative"] || names["ptz.stop"] {
		t.Fatalf("motion tools listed with control off: %v", names)
	}

	s, se := startSession(t, controlConfig(t, cam), "-enable-control")
	s.initialize()
	names = s.toolNamesOver(2)
	if !names["ptz.move_relative"] || !names["ptz.stop"] {
		t.Fatalf("motion tools missing with -enable-control: %v", names)
	}
	start := cam.PTZPosition()
	args := map[string]any{"camera": "cam1", "profile": cam.ProfileToken(), "pan": 0.1}

	dry := s.callOver(3, "ptz.move_relative", args)
	dd, _ := dry["structuredContent"].(map[string]any)["data"].(map[string]any)
	if dry["isError"] == true || dd["executed"] != false || dd["dry_run"] != true {
		t.Fatalf("dry run = %v", dry)
	}
	if cam.PTZPosition() != start {
		t.Fatal("the dry run moved the camera")
	}

	args["dry_run"] = false
	moved := s.callOver(4, "ptz.move_relative", args)
	if moved["isError"] == true {
		t.Fatalf("real move failed: %v", moved)
	}
	if got := cam.PTZPosition(); math.Abs(got.Pan-start.Pan-0.1) > 1e-6 {
		t.Errorf("pan %v -> %v, want +0.1", start.Pan, got.Pan)
	}

	stopped := s.callOver(5, "ptz.stop", map[string]any{"camera": "cam1", "profile": cam.ProfileToken()})
	sd, _ := stopped["structuredContent"].(map[string]any)["data"].(map[string]any)
	if stopped["isError"] == true || sd["executed"] != true || sd["stop_status"] == "" {
		t.Fatalf("ptz.stop = %v", stopped)
	}

	// The audit trail names the tools and never carries the password.
	_ = s.stdin.Close()
	if _, ok := s.wait(15e9); !ok {
		t.Fatal("did not exit")
	}
	log := se.String()
	for _, want := range []string{"ptz.move_relative", "ptz.stop", "motion_pan=0.1"} {
		if !strings.Contains(log, want) {
			t.Errorf("audit trail lacks %q:\n%s", want, log)
		}
	}
	if strings.Contains(log, cam.Password()) {
		t.Error("password in the log")
	}
}
