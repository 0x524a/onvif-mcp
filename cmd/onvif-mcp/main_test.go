package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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

func TestMissingConfigFlagPrintsAOneLineUsage(t *testing.T) {
	_, se, _ := runBin(t)
	if !strings.Contains(se, "usage: onvif-mcp -config <path> [-enable-control]") {
		t.Errorf("stderr = %q, want a usage line", se)
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

func startSession(t *testing.T, cfgPath string, extraArgs ...string) (*session, *syncBuf) {
	t.Helper()
	args := append([]string{"-config", cfgPath}, extraArgs...)
	cmd := exec.Command(binary(t), args...) //nolint:gosec // test-built binary
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

// hangEndpoint accepts TCP connections and never answers, like a wedged camera.
func hangEndpoint(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return "http://" + l.Addr().String() + "/onvif/device_service"
}

func writeHungConfig(t *testing.T) string {
	t.Helper()
	return writeConfig(t, 0o600, hangEndpoint(t), "u", "hung-camera-pw")
}

func (s *session) initialize() {
	s.t.Helper()
	s.send(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "probe", "version": "0"}}})
	if res, _ := s.recv()["result"].(map[string]any); res == nil {
		s.t.Fatal("initialize failed")
	}
	s.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
}

func (s *session) sendProbe(id int) {
	s.send(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{
		"name": "camera.list", "arguments": map[string]any{"probe": true}}})
}

// SIGTERM while a probe of a hung camera is in flight must not wait out the
// 15s probe budget.
func TestShutdownSignalDoesNotWaitForHungProbe(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		t.Run(sig.String(), func(t *testing.T) {
			s, se := startSession(t, writeHungConfig(t))
			s.initialize()
			s.sendProbe(2)
			time.Sleep(500 * time.Millisecond) // let the probe reach the camera
			start := time.Now()
			if err := s.cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			code, ok := s.wait(10 * time.Second)
			if !ok || code != 0 {
				t.Fatalf("ok=%v code=%d stderr=%s", ok, code, se)
			}
			if d := time.Since(start); d > 3*time.Second {
				t.Errorf("exit took %v after %v", d, sig)
			}
		})
	}
}

// Closing stdin is the normal MCP shutdown, even with a request in flight.
func TestStdinEOFWithRequestInFlightExitsZeroWithoutError(t *testing.T) {
	s, se := startSession(t, writeHungConfig(t))
	s.initialize()
	s.sendProbe(2)
	time.Sleep(300 * time.Millisecond)
	_ = s.stdin.Close()
	code, ok := s.wait(25 * time.Second)
	if !ok || code != 0 {
		t.Fatalf("ok=%v code=%d stderr=%s", ok, code, se)
	}
	if strings.Contains(se.String(), "level=ERROR") {
		t.Errorf("clean EOF logged an error:\n%s", se)
	}
}

func TestEnableControlFlag(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enable-control=%v", enabled), func(t *testing.T) {
			cam := testcam.Start(t)
			body := fmt.Sprintf(`{"cameras":{"cam1":{"endpoint":%q,"username":%q,"password":%q,"control":true}}}`,
				cam.Endpoint(), cam.Username(), cam.Password())
			p := filepath.Join(t.TempDir(), "cameras.json")
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			var extra []string
			if enabled {
				extra = []string{"-enable-control"}
			}
			s, se := startSession(t, p, extra...)
			s.initialize()
			s.send(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{
				"name": "camera.list", "arguments": map[string]any{}}})
			call := s.recv()
			sc, _ := call["result"].(map[string]any)["structuredContent"].(map[string]any)
			cams, _ := sc["data"].(map[string]any)["cameras"].([]any)
			if len(cams) != 1 {
				t.Fatalf("structuredContent = %v", sc)
			}
			// The process-wide flag is observable on the wire: the policy
			// resource reports it, and it is registered either way.
			s.send(map[string]any{"jsonrpc": "2.0", "id": 3, "method": "resources/read",
				"params": map[string]any{"uri": "onvif://server/policy"}})
			rr, _ := s.recv()["result"].(map[string]any)
			contents, _ := rr["contents"].([]any)
			if len(contents) != 1 {
				t.Fatalf("policy resource result = %v", rr)
			}
			var pol map[string]any
			if err := json.Unmarshal([]byte(contents[0].(map[string]any)["text"].(string)), &pol); err != nil {
				t.Fatal(err)
			}
			if pol["control_enabled"] != enabled {
				t.Errorf("policy control_enabled = %v, want %v", pol["control_enabled"], enabled)
			}
			wantMode := "read-only"
			if enabled {
				wantMode = "control-enabled"
			}
			if pol["mode"] != wantMode {
				t.Errorf("policy mode = %v, want %v", pol["mode"], wantMode)
			}
			grants, _ := pol["cameras"].([]any)
			if len(grants) != 1 || grants[0].(map[string]any)["control_allowed"] != true {
				t.Errorf("policy cameras = %v", pol["cameras"])
			}
			_ = s.stdin.Close()
			if code, ok := s.wait(15 * time.Second); !ok || code != 0 {
				t.Fatalf("ok=%v code=%d stderr=%s", ok, code, se)
			}
			log := se.String()
			for _, want := range []string{
				fmt.Sprintf("control_enabled=%v", enabled),
				fmt.Sprintf("write_tools_registered=%v", enabled),
			} {
				if !strings.Contains(log, want) {
					t.Errorf("stderr lacks %q:\n%s", want, log)
				}
			}
			if !strings.Contains(log, "control_allowed=true") {
				t.Errorf("stderr lacks control_allowed=true for the opted-in camera:\n%s", log)
			}
		})
	}
}

func TestMalformedLinesDoNotEndTheSession(t *testing.T) {
	cfg, pass := newConfig(t)
	s, se := startSession(t, cfg)
	s.initialize()
	for _, bad := range []string{"{not json", "\x00\xff", `{"jsonrpc":"1.0","id":5,"method":"ping"}`, `"str"`} {
		if _, err := s.stdin.Write([]byte(bad + "\n")); err != nil {
			t.Fatal(err)
		}
		reply := s.recv()
		e, _ := reply["error"].(map[string]any)
		if e == nil || (e["code"] != float64(-32700) && e["code"] != float64(-32600)) {
			t.Fatalf("bad line %q got %v", bad, reply)
		}
	}
	// A line over the cap is rejected without being buffered whole.
	big := `{"jsonrpc":"2.0","id":6,"method":"` + strings.Repeat("a", 5<<20) + `"}` + "\n"
	if _, err := s.stdin.Write([]byte(big)); err != nil {
		t.Fatal(err)
	}
	if e, _ := s.recv()["error"].(map[string]any); e == nil || e["code"] != float64(-32600) {
		t.Fatal("oversize line was not rejected with -32600")
	}
	s.handshakeCall(pass)
	_ = s.stdin.Close()
	if code, ok := s.wait(15 * time.Second); !ok || code != 0 {
		t.Fatalf("ok=%v code=%d stderr=%s", ok, code, se)
	}
}

// handshakeCall runs tools/list and camera.list on an initialised session.
func (s *session) handshakeCall(pass string) {
	s.t.Helper()
	s.send(map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": map[string]any{
		"name": "camera.list", "arguments": map[string]any{"probe": true}}})
	cr, _ := s.recv()["result"].(map[string]any)
	if cr == nil || cr["isError"] == true {
		s.t.Fatalf("camera.list failed after bad input: %v", cr)
	}
	for _, l := range s.all {
		if strings.Contains(l, pass) {
			s.t.Fatal("password present on stdout")
		}
	}
}

func TestSnapshotMaxBytesFlagIsValidated(t *testing.T) {
	cfg := writeConfig(t, 0o600, "http://192.0.2.10/onvif/device_service", "u", "hunter2-secret")
	for _, v := range []string{"0", "1023", "8388609", "-1", "abc", "1.5"} {
		so, se, code := runBin(t, "-config", cfg, "-snapshot-max-bytes", v)
		if code != 2 || so != "" || se == "" {
			t.Errorf("%s: code=%d stdout=%q stderr=%q, want exit 2", v, code, so, se)
		}
		if v != "abc" && v != "1.5" && !strings.Contains(se, "snapshot-max-bytes must be between 1024 and 8388608") {
			t.Errorf("%s: stderr = %q", v, se)
		}
	}
	// -version still works whatever the other flags say.
	if _, _, code := runBin(t, "-version", "-snapshot-max-bytes", "1"); code != 0 {
		t.Errorf("-version exited %d", code)
	}
}

func TestSnapshotMaxBytesFlagReachesTheTool(t *testing.T) {
	cam := testcam.Start(t)
	cfg := writeConfig(t, 0o600, cam.Endpoint(), cam.Username(), cam.Password())
	for _, tc := range []struct {
		args    []string
		wantErr bool
	}{{nil, false}, {[]string{"-snapshot-max-bytes", "2048"}, true}} {
		s, se := startSession(t, cfg, tc.args...)
		s.initialize()
		s.send(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{
			"name": "camera.snapshot", "arguments": map[string]any{"camera": "cam1", "profile": cam.ProfileToken()}}})
		line := s.recv()
		cr, _ := line["result"].(map[string]any)
		if cr == nil || (cr["isError"] == true) != tc.wantErr {
			t.Fatalf("args %v: result = %v", tc.args, line)
		}
		raw, _ := json.Marshal(cr)
		if tc.wantErr && !strings.Contains(string(raw), "over the 2048 byte limit") {
			t.Errorf("refusal lacks the limit: %s", raw)
		}
		if !tc.wantErr && !strings.Contains(string(raw), `"type":"image"`) {
			t.Errorf("no image content: %.300s", raw)
		}
		if strings.Contains(string(raw), cam.Password()) {
			t.Error("password on stdout")
		}
		_ = s.stdin.Close()
		if code, ok := s.wait(15 * time.Second); !ok || code != 0 {
			t.Fatalf("ok=%v code=%d stderr=%s", ok, code, se)
		}
		if !strings.Contains(se.String(), fmt.Sprintf("snapshot_max_bytes=%d", map[bool]int{false: 1048576, true: 2048}[tc.wantErr])) {
			t.Errorf("stderr does not report the cap:\n%s", se.String())
		}
	}
}
