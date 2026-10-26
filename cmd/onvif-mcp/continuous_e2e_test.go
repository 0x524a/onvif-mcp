package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	onvif "github.com/0x524a/onvif-go"

	"github.com/0x524a/onvif-mcp/internal/testcam"
)

// The virtual camera ignores the ONVIF Timeout and reports MOVING until a Stop,
// so in these tests only the server's own stop can end a continuous move.

func attestedConfig(t *testing.T, cam *testcam.Cam) string {
	t.Helper()
	body := fmt.Sprintf(`{"cameras":{"cam1":{"endpoint":%q,"username":%q,"password":%q,"control":true,"ptz_honours_timeout":true}}}`,
		cam.Endpoint(), cam.Username(), cam.Password())
	p := filepath.Join(t.TempDir(), "cameras.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// startContinuous starts a continuous move of secs without waiting for its reply and
// returns once the virtual camera reports MOVING.
func startContinuous(t *testing.T, s *session, cam *testcam.Cam, secs float64) {
	t.Helper()
	s.send(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{
		"name": "ptz.move_continuous", "arguments": map[string]any{"camera": "cam1", "profile": cam.ProfileToken(),
			"pan": 0.1, "duration_seconds": secs, "dry_run": false}}})
	deadline := time.Now().Add(10 * time.Second)
	for {
		if pt, _ := cam.PTZMoveState(); pt == "MOVING" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the virtual camera never started moving")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestContinuousMoveIsListedOnlyForAnAttestedCamera(t *testing.T) {
	cam := testcam.Start(t)
	plain, _ := startSession(t, controlConfig(t, cam), "-enable-control")
	plain.initialize()
	if plain.toolNamesOver(2)["ptz.move_continuous"] {
		t.Fatal("listed although no camera sets ptz_honours_timeout")
	}
	s, _ := startSession(t, attestedConfig(t, cam), "-enable-control")
	s.initialize()
	if !s.toolNamesOver(2)["ptz.move_continuous"] {
		t.Fatal("not listed for an attested camera with -enable-control")
	}
}

// A shutdown signal mid-move: the handler's own stop goes out on a detached
// context, Run waits for the handler, and the process exits 0 with the camera
// idle.
func TestSIGTERMMidContinuousMoveStopsTheCameraThenExits(t *testing.T) {
	cam := testcam.Start(t)
	s, se := startSession(t, attestedConfig(t, cam), "-enable-control")
	s.initialize()
	startContinuous(t, s, cam, 5)
	start := time.Now()
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	code, ok := s.wait(12 * time.Second)
	if !ok || code != 0 {
		t.Fatalf("ok=%v code=%d after %v:\n%s", ok, code, time.Since(start), se)
	}
	if pt, _ := cam.PTZMoveState(); pt != "IDLE" {
		t.Errorf("after the shutdown the camera is %q, want IDLE:\n%s", pt, se)
	}
	if log := se.String(); !strings.Contains(log, "motion stopped") || !strings.Contains(log, "stopped_by=shutdown") {
		t.Errorf("audit trail lacks the shutdown stop:\n%s", log)
	}
}

// The client going away (stdin EOF) mid-move cancels the handler, which stops
// the camera before the process exits.
func TestStdinEOFMidContinuousMoveStopsTheCameraThenExits(t *testing.T) {
	cam := testcam.Start(t)
	s, se := startSession(t, attestedConfig(t, cam), "-enable-control")
	s.initialize()
	startContinuous(t, s, cam, 5)
	_ = s.stdin.Close()
	code, ok := s.wait(12 * time.Second)
	if !ok || code != 0 {
		t.Fatalf("ok=%v code=%d:\n%s", ok, code, se)
	}
	if pt, _ := cam.PTZMoveState(); pt != "IDLE" {
		t.Errorf("after stdin closed the camera is %q, want IDLE:\n%s", pt, se)
	}
	if log := se.String(); !strings.Contains(log, "stopped_by=cancelled") {
		t.Errorf("audit trail lacks the cancelled stop:\n%s", log)
	}
}

// SIGKILL cannot be caught, so nothing in the server can stop the camera: only
// the camera's own ONVIF Timeout is left. The virtual camera ignores it, so it
// is still moving well after the requested duration. This test exists to keep
// the README's claim honest; it then stops the camera itself.
func TestSIGKILLMidContinuousMoveLeavesOnlyTheCamerasTimeout(t *testing.T) {
	cam := testcam.Start(t)
	s, _ := startSession(t, attestedConfig(t, cam), "-enable-control")
	s.initialize()
	// 2 s, so the kill lands well before the server's own deadline stop could.
	startContinuous(t, s, cam, 2)
	if err := s.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_, _ = s.wait(5 * time.Second)
	time.Sleep(2500 * time.Millisecond) // past the 2 s duration and the Timeout sent with it
	pt, _ := cam.PTZMoveState()

	c, err := onvif.NewClient(cam.Endpoint(), onvif.WithCredentials(cam.Username(), cam.Password()))
	if err == nil {
		err = c.Initialize(context.Background())
	}
	if err == nil {
		err = c.Stop(context.Background(), cam.ProfileToken(), true, true)
	}
	if err != nil {
		t.Fatalf("harness stop: %v", err)
	}
	if pt != "MOVING" {
		t.Fatalf("a camera that ignores the Timeout reported %q after the server was killed; the README's SIGKILL caveat assumes MOVING", pt)
	}
}
