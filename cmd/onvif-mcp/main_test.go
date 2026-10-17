package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/testcam"
)

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

// binary builds the real command once per test run.
func binary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "onvif-mcp-bin")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "onvif-mcp")
		out, err := exec.Command( //nolint:gosec // test builds the package under test
			"go", "build", "-o", binPath, ".").CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("go build: %w\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return binPath
}

func TestMain(m *testing.M) {
	code := m.Run()
	if binPath != "" {
		_ = os.RemoveAll(filepath.Dir(binPath))
	}
	os.Exit(code)
}

func writeConfig(t *testing.T, mode os.FileMode, endpoint, user, pass string) string {
	t.Helper()
	body := fmt.Sprintf(`{"cameras":{"cam1":{"endpoint":%q,"username":%q,"password":%q}}}`,
		endpoint, user, pass)
	p := filepath.Join(t.TempDir(), "cameras.json")
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile is subject to umask; set the mode explicitly.
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// runBin runs the binary to completion with no stdin and returns its streams.
func runBin(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(binary(t), args...) //nolint:gosec // test-built binary
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	cmd.Stdin = strings.NewReader("")
	err := cmd.Run()
	code = 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run: %v", err)
		}
		code = ee.ExitCode()
	}
	return so.String(), se.String(), code
}

func TestVersionGoesToStdout(t *testing.T) {
	so, se, code := runBin(t, "-version")
	if code != 0 || strings.TrimSpace(so) != "v0.1.0" || se != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, so, se)
	}
}

func TestUnknownFlagExits2(t *testing.T) {
	so, se, code := runBin(t, "-nope")
	if code != 2 || so != "" || se == "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, so, se)
	}
}

func TestMissingConfigFlagExits2(t *testing.T) {
	so, se, code := runBin(t)
	if code != 2 || so != "" || !strings.Contains(se, "-config") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, so, se)
	}
}

func TestLoosePermissionsExit1(t *testing.T) {
	p := writeConfig(t, 0o644, "http://192.0.2.10/onvif/device_service", "u", "hunter2-secret")
	so, se, code := runBin(t, "-config", p)
	if code != 1 || so != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, so, se)
	}
	if !strings.Contains(se, "group- or world-readable") {
		t.Fatalf("stderr lacks a clear permissions message: %q", se)
	}
	if strings.Contains(se, "hunter2-secret") {
		t.Fatal("password leaked to stderr")
	}
}

func TestMissingConfigFileExits1(t *testing.T) {
	so, se, code := runBin(t, "-config", filepath.Join(t.TempDir(), "absent.json"))
	if code != 1 || so != "" || se == "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, so, se)
	}
}

// TestExampleConfigStaysValid keeps the documentation file loadable once its
// permissions are tightened, as the README instructs.
func TestExampleConfigStaysValid(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "cameras.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "cameras.json")
	if err := os.WriteFile(p, b, 0o600); err != nil { //nolint:gosec // temp dir path
		t.Fatal(err)
	}
	if _, err := config.Load(p); err != nil {
		t.Fatalf("example config does not load: %v", err)
	}
}

// session is a running server with line-oriented JSON-RPC access.
type session struct {
	t     *testing.T
	cmd   *exec.Cmd
	stdin interface {
		Write([]byte) (int, error)
		Close() error
	}
	lines chan string
	all   []string // every stdout line, in order
	done  chan error
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func startSession(t *testing.T, cfgPath string) (*session, *syncBuf) {
	t.Helper()
	cmd := exec.Command(binary(t), "-config", cfgPath) //nolint:gosec // test-built binary
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	se := &syncBuf{}
	cmd.Stderr = se
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	s := &session{t: t, cmd: cmd, stdin: stdin, lines: make(chan string, 64), done: make(chan error, 1)}
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			s.lines <- sc.Text()
		}
		close(s.lines)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
	})
	return s, se
}

func (s *session) send(v any) {
	s.t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		s.t.Fatal(err)
	}
	if _, err := s.stdin.Write(append(b, '\n')); err != nil {
		s.t.Fatalf("write stdin: %v", err)
	}
}

// recv returns the next stdout line, asserting it is a JSON-RPC 2.0 message.
func (s *session) recv() map[string]any {
	s.t.Helper()
	select {
	case line, ok := <-s.lines:
		if !ok {
			s.t.Fatal("stdout closed while waiting for a response")
		}
		s.all = append(s.all, line)
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			s.t.Fatalf("stdout line is not JSON (log text on the RPC channel?): %q", line)
		}
		if m["jsonrpc"] != "2.0" {
			s.t.Fatalf("stdout line is not JSON-RPC 2.0: %q", line)
		}
		return m
	case <-time.After(20 * time.Second):
		s.t.Fatal("timed out waiting for a response")
	}
	return nil
}

func (s *session) wait(d time.Duration) (int, bool) {
	go func() { s.done <- s.cmd.Wait() }()
	select {
	case err := <-s.done:
		if err == nil {
			return 0, true
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), true
		}
		s.t.Fatalf("wait: %v", err)
	case <-time.After(d):
	}
	return -1, false
}

// handshake performs initialize, initialized, tools/list and camera.list, and
// checks that stdout carried only JSON-RPC.
func (s *session) handshake(pass string) {
	s.t.Helper()
	s.send(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "probe", "version": "0"}}})
	init := s.recv()
	res, _ := init["result"].(map[string]any)
	if res == nil {
		s.t.Fatalf("initialize failed: %v", init)
	}
	info, _ := res["serverInfo"].(map[string]any)
	if info["name"] != "onvif-mcp" {
		s.t.Fatalf("serverInfo = %v", info)
	}
	s.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})

	s.send(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
	list := s.recv()
	tools, _ := list["result"].(map[string]any)["tools"].([]any)
	found := false
	for _, x := range tools {
		if x.(map[string]any)["name"] == "camera.list" {
			found = true
		}
	}
	if !found {
		s.t.Fatalf("camera.list not in tools/list: %v", list)
	}

	s.send(map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": map[string]any{
		"name": "camera.list", "arguments": map[string]any{"probe": true}}})
	call := s.recv()
	cr, _ := call["result"].(map[string]any)
	if cr == nil || cr["isError"] == true {
		s.t.Fatalf("camera.list failed: %v", call)
	}
	sc, _ := cr["structuredContent"].(map[string]any)
	data, _ := sc["data"].(map[string]any)
	cams, _ := data["cameras"].([]any)
	if len(cams) != 1 || cams[0].(map[string]any)["id"] != "cam1" || cams[0].(map[string]any)["state"] != "reachable" {
		s.t.Fatalf("structuredContent = %v", sc)
	}
	for _, l := range s.all {
		if strings.Contains(l, pass) {
			s.t.Fatal("password present on stdout")
		}
	}
}

func newConfig(t *testing.T) (cfgPath, pass string) {
	cam := testcam.Start(t)
	return writeConfig(t, 0o600, cam.Endpoint(), cam.Username(), cam.Password()), cam.Password()
}

func checkStderr(t *testing.T, se, pass string) {
	t.Helper()
	for _, want := range []string{"camera", "id=cam1", "starting", "transport=stdio"} {
		if !strings.Contains(se, want) {
			t.Errorf("stderr lacks %q:\n%s", want, se)
		}
	}
	if strings.Contains(se, pass) {
		t.Error("password present on stderr")
	}
}

func TestStdioSessionExitsCleanlyOnStdinClose(t *testing.T) {
	cfg, pass := newConfig(t)
	s, se := startSession(t, cfg)
	s.handshake(pass)
	_ = s.stdin.Close()
	code, ok := s.wait(15 * time.Second)
	if !ok || code != 0 {
		t.Fatalf("did not exit cleanly on stdin close: ok=%v code=%d stderr=%s", ok, code, se)
	}
	// Anything flushed during shutdown must also be JSON-RPC only.
	for l := range s.lines {
		t.Errorf("unexpected stdout line after close: %q", l)
	}
	checkStderr(t, se.String(), pass)
}

func TestStdioSessionExitsCleanlyOnSIGINT(t *testing.T) {
	cfg, pass := newConfig(t)
	s, se := startSession(t, cfg)
	s.handshake(pass)
	if err := s.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	code, ok := s.wait(15 * time.Second)
	if !ok || code != 0 {
		t.Fatalf("did not exit cleanly on SIGINT: ok=%v code=%d stderr=%s", ok, code, se)
	}
	for l := range s.lines {
		t.Errorf("unexpected stdout line after SIGINT: %q", l)
	}
	checkStderr(t, se.String(), pass)
}
