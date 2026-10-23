package main

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/httpserver"
	"github.com/0x524a/onvif-mcp/internal/mcpserver"
	"github.com/0x524a/onvif-mcp/internal/safety"
	"github.com/0x524a/onvif-mcp/internal/testcam"
)

// ---- helpers ----

type tokenSpec struct {
	id    string
	grant []string
}

// makeTokens generates real tokens with httpserver.NewToken and writes a 0600
// token file. It returns the path and id -> token.
func makeTokens(t *testing.T, specs ...tokenSpec) (path string, tokens map[string]string) {
	t.Helper()
	tokens = map[string]string{}
	var entries []string
	for _, sp := range specs {
		tok, ent, err := httpserver.NewToken(sp.id)
		if err != nil {
			t.Fatal(err)
		}
		tokens[sp.id] = tok
		if len(sp.grant) > 0 {
			ent = strings.TrimSuffix(ent, "}") + `,"grant":["` + strings.Join(sp.grant, `","`) + `"]}`
		}
		entries = append(entries, ent)
	}
	path = filepath.Join(t.TempDir(), "tokens.json")
	if err := os.WriteFile(path, []byte(`{"tokens":[`+strings.Join(entries, ",")+`]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, tokens
}

type httpRun struct {
	addr   string
	stderr *syncBuf
	cancel context.CancelFunc
	done   chan int
}

var listenRe = regexp.MustCompile(`listen=(\S+)`)

// startHTTPInproc runs the real run() in this process (so -race sees it) on a
// loopback ephemeral port and waits for its startup line.
func startHTTPInproc(t *testing.T, cfgPath, tokensPath string, extra ...string) *httpRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &httpRun{stderr: &syncBuf{}, cancel: cancel, done: make(chan int, 1)}
	args := append([]string{"-config", cfgPath, "-transport", "http", "-listen", "127.0.0.1:0", "-http-tokens", tokensPath}, extra...)
	var so bytes.Buffer
	go func() { r.done <- run(ctx, args, strings.NewReader(""), &so, r.stderr) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if m := listenRe.FindStringSubmatch(r.stderr.String()); m != nil && strings.Contains(r.stderr.String(), "transport=http") {
			r.addr = m[1]
			break
		}
		select {
		case code := <-r.done:
			t.Fatalf("run exited %d before listening:\n%s", code, r.stderr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("no startup line:\n%s", r.stderr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.done:
		case <-time.After(15 * time.Second):
		}
		if so.Len() != 0 {
			t.Errorf("stdout is not empty in HTTP mode: %q", so.String())
		}
	})
	return r
}

func (r *httpRun) url() string { return "http://" + r.addr + "/mcp" }

type bearer struct {
	tok  string
	base http.RoundTripper
}

func (b bearer) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+b.tok)
	return b.base.RoundTrip(req)
}

func (r *httpRun) connect(t *testing.T, token string) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "0"}, nil)
	cs, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint: r.url(), HTTPClient: &http.Client{Transport: bearer{token, http.DefaultTransport}}, DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func toolSet(t *testing.T, cs *mcp.ClientSession) map[string]bool {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, tl := range res.Tools {
		out[tl.Name] = true
	}
	return out
}

func callTool(cs *mcp.ClientSession, name string, args map[string]any) (*mcp.CallToolResult, error) {
	return cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
}

func errorCode(res *mcp.CallToolResult) string {
	m, _ := res.StructuredContent.(map[string]any)
	e, _ := m["error"].(map[string]any)
	c, _ := e["code"].(string)
	return c
}

var writeTools = []string{"ptz.stop", "ptz.move_relative", "ptz.goto_preset"}

// ---- tests ----

func TestHTTPDefaultTokenReadsButHasNoWriteOrOptInTools(t *testing.T) {
	cam := testcam.Start(t)
	cfg := controlConfig(t, cam) // the camera opts in to control; HTTP must ignore that
	tp, toks := makeTokens(t, tokenSpec{id: "laptop-agent"})
	r := startHTTPInproc(t, cfg, tp)
	cs := r.connect(t, toks["laptop-agent"])

	names := toolSet(t, cs)
	for _, w := range writeTools {
		if names[w] {
			t.Errorf("write tool %s is listed over HTTP", w)
		}
	}
	for _, o := range safety.OptInTools() {
		if names[o] {
			t.Errorf("opt-in tool %s is listed for a token without grants", o)
		}
	}
	for _, want := range []string{"camera.list", "camera.describe", "media.profiles", "media.stream_uri", "imaging.settings", "ptz.status", "ptz.presets"} {
		if !names[want] {
			t.Errorf("default read tool %s missing: %v", want, names)
		}
	}

	if res, err := callTool(cs, "camera.list", map[string]any{}); err != nil || res.IsError {
		t.Fatalf("camera.list: %+v %v", res, err)
	}
	if res, err := callTool(cs, "media.profiles", map[string]any{"camera": "cam1"}); err != nil || res.IsError {
		t.Fatalf("media.profiles: %+v %v", res, err)
	}
	if res, err := callTool(cs, "ptz.presets", map[string]any{"camera": "cam1", "profile": cam.ProfileToken()}); err != nil || res.IsError {
		t.Fatalf("ptz.presets: %+v %v", res, err)
	}
	// Opt-in tools and write tools are refused, not merely hidden.
	for _, o := range safety.OptInTools() {
		res, err := callTool(cs, o, map[string]any{"camera": "cam1"})
		if err != nil || !res.IsError || errorCode(res) != "blocked_by_policy" {
			t.Errorf("%s without a grant: %+v %v", o, res, err)
		}
	}
	for _, w := range writeTools {
		// An unregistered tool is a protocol error and the SDK client drops its
		// session on it, so each probe gets a session of its own.
		probe := r.connect(t, toks["laptop-agent"])
		res, err := callTool(probe, w, map[string]any{"camera": "cam1", "dry_run": false})
		if err == nil && (res == nil || !res.IsError) {
			t.Errorf("%s ran over HTTP: %+v", w, res)
		}
	}
	if p := cam.PTZPosition(); p.Pan != 0 || p.Tilt != 0 {
		t.Errorf("the camera moved: %+v", p)
	}
	// The policy resource is read-only and gives no enable advice.
	rr, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: safety.PolicyURI})
	if err != nil {
		t.Fatal(err)
	}
	doc := rr.Contents[0].Text
	if !strings.Contains(doc, `"mode": "read-only"`) || strings.Contains(doc, "--enable-control") || strings.Contains(doc, "ptz.stop") {
		t.Errorf("policy over HTTP:\n%s", doc)
	}
	if strings.Contains(r.stderr.String(), toks["laptop-agent"]) || strings.Contains(r.stderr.String(), cam.Password()) {
		t.Error("a token or camera password reached stderr")
	}
}

func TestHTTPGrantedTokenGetsOnlyTheGrantedOptInTool(t *testing.T) {
	cam := testcam.Start(t)
	tp, toks := makeTokens(t, tokenSpec{id: "plain"}, tokenSpec{id: "snap", grant: []string{"camera.snapshot"}})
	r := startHTTPInproc(t, controlConfig(t, cam), tp)

	cs := r.connect(t, toks["snap"])
	names := toolSet(t, cs)
	if !names["camera.snapshot"] || names["camera.discover"] || names["stream.inspect"] {
		t.Fatalf("snap token sees %v", names)
	}
	res, err := callTool(cs, "camera.snapshot", map[string]any{"camera": "cam1", "profile": cam.ProfileToken()})
	if err != nil || res.IsError {
		t.Fatalf("granted snapshot: %+v %v", res, err)
	}
	if res, _ := callTool(cs, "camera.discover", map[string]any{}); res == nil || !res.IsError {
		t.Error("discover ran for a snapshot-only token")
	}
	// The other token, same server, still has no snapshot: grants are per token.
	other := r.connect(t, toks["plain"])
	if toolSet(t, other)["camera.snapshot"] {
		t.Error("grant leaked to another token")
	}
	// The audit names the callers.
	log := r.stderr.String()
	if !strings.Contains(log, "caller=snap") || !strings.Contains(log, `tool=camera.snapshot`) {
		t.Errorf("tool-call audit lacks the caller:\n%s", log)
	}
}

func TestHTTPAuthFailuresAreIdenticalAndNeverAudited(t *testing.T) {
	cam := testcam.Start(t)
	tp, _ := makeTokens(t, tokenSpec{id: "a"})
	r := startHTTPInproc(t, controlConfig(t, cam), tp)
	wellFormedUnknown := strings.Repeat("ab", 32)
	var ref string
	for name, hdr := range map[string]string{
		"none": "", "wrong": "Bearer " + wellFormedUnknown, "malformed": "Bearer nope", "basic": "Basic Zm9vOmJhcg==",
	} {
		req, _ := http.NewRequest("POST", r.url(), strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"camera.list","arguments":{}}}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if hdr != "" {
			req.Header.Set("Authorization", hdr)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		got := fmt.Sprintf("%d|%s|%s|%s|%s", resp.StatusCode, resp.Header.Get("WWW-Authenticate"), resp.Header.Get("Content-Type"), resp.Header.Get("Connection"), b)
		if resp.StatusCode != 401 {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
		if ref == "" {
			ref = got
		} else if got != ref {
			t.Errorf("%s differs: %q vs %q", name, got, ref)
		}
	}
	if strings.Contains(r.stderr.String(), "tool call") {
		t.Errorf("a rejected request produced a tool-call audit line:\n%s", r.stderr)
	}
}

func TestHTTPWithEnableControlExitsTwoAndStartsNothing(t *testing.T) {
	cam := testcam.Start(t)
	tp, _ := makeTokens(t, tokenSpec{id: "a"})
	so, se, code := runBin(t, "-config", controlConfig(t, cam), "-transport", "http", "-http-tokens", tp, "-enable-control")
	if code != 2 || so != "" || !strings.Contains(se, "write tools are not offered over HTTP") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, so, se)
	}
	if strings.Contains(se, "starting") {
		t.Error("the server started")
	}
}

func TestFlagCombinationsExitTwoBeforeTouchingFiles(t *testing.T) {
	for name, args := range map[string][]string{
		"http without tokens":       {"-transport", "http", "-config", "/nonexistent"},
		"listen under stdio":        {"-listen", "127.0.0.1:1", "-config", "/nonexistent"},
		"new-token with config":     {"-new-token", "x", "-config", "/nonexistent"},
		"remote without opt in":     {"-transport", "http", "-http-tokens", "/nonexistent", "-listen", "0.0.0.0:1", "-config", "/nonexistent"},
		"unknown transport":         {"-transport", "sse", "-config", "/nonexistent"},
		"http with large snapshots": {"-transport", "http", "-http-tokens", "/nonexistent", "-snapshot-max-bytes", "8388608", "-config", "/nonexistent"},
	} {
		so, se, code := runBin(t, args...)
		if code != 2 || so != "" {
			t.Errorf("%s: code=%d stdout=%q stderr=%q", name, code, so, se)
		}
	}
}

func TestNewTokenPrintsATokenAndAnEntryAndNothingElse(t *testing.T) {
	so, se, code := runBin(t, "-new-token", "ops-agent")
	lines := strings.Split(strings.TrimSpace(so), "\n")
	if code != 0 || se != "" || len(lines) != 2 {
		t.Fatalf("code=%d stderr=%q stdout=%q", code, se, so)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(lines[0]) {
		t.Errorf("token line %q", lines[0])
	}
	if strings.Contains(lines[1], lines[0]) || !strings.Contains(lines[1], `"id":"ops-agent"`) {
		t.Errorf("entry line %q", lines[1])
	}
	if _, _, code := runBin(t, "-new-token", "Bad Id"); code != 2 {
		t.Errorf("bad id exit %d", code)
	}
	// -version wins and prints only the version.
	if so, _, code := runBin(t, "-new-token", "x", "-version"); code != 0 || strings.TrimSpace(so) != mcpserver.Version() {
		t.Errorf("-version with -new-token: %q %d", so, code)
	}
}

func TestHTTPTwoTokensUnderLoadNoRaceAndCorrectAttribution(t *testing.T) {
	cam := testcam.Start(t)
	tp, toks := makeTokens(t, tokenSpec{id: "one"}, tokenSpec{id: "two"})
	r := startHTTPInproc(t, controlConfig(t, cam), tp)
	var wg sync.WaitGroup
	for _, id := range []string{"one", "two"} {
		cs := r.connect(t, toks[id])
		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 16; i++ {
					var res *mcp.CallToolResult
					var err error
					switch i % 4 {
					case 0:
						res, err = callTool(cs, "camera.list", map[string]any{})
					case 1:
						res, err = callTool(cs, "media.profiles", map[string]any{"camera": "cam1"})
					case 2:
						res, err = callTool(cs, "ptz.presets", map[string]any{"camera": "cam1", "profile": cam.ProfileToken()})
					default:
						res, err = callTool(cs, "camera.describe", map[string]any{"camera": "cam1"})
					}
					if err != nil || res.IsError {
						t.Errorf("%s call %d: %v %+v", id, i, err, res)
						return
					}
				}
			}()
		}
	}
	wg.Wait()
	log := r.stderr.String()
	for _, id := range []string{"one", "two"} {
		if n := strings.Count(log, "caller="+id+" "); n < 64 {
			t.Errorf("token %s: %d attributed tool-call lines, want at least 64", id, n)
		}
	}
}

// The tool-level slot is held after the client disconnects and freed only when the
// handler returns (the 13b.0 step 6 gate), against the real stack.
func TestHTTPCapSlotOutlivesTheClientAndIsFreedByTheHandler(t *testing.T) {
	cfg := hungConfig(t, 3) // bounds how long each hung handler runs
	tp, toks := makeTokens(t, tokenSpec{id: "tok"})
	r := startHTTPInproc(t, cfg, tp)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"camera.describe","arguments":{"camera":"cam1"}}}`
	for i := 0; i < mcpserver.HTTPMaxCallsPerToken; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		req, _ := http.NewRequestWithContext(ctx, "POST", r.url(), strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", "2025-06-18")
		req.Header.Set("Authorization", "Bearer "+toks["tok"])
		if resp, err := http.DefaultClient.Do(req); err == nil { // expected: client abort
			_ = resp.Body.Close()
		}
		cancel()
	}
	cs := r.connect(t, toks["tok"])
	// The clients are gone, but the 8 handlers are still talking to the hung camera.
	res, err := callTool(cs, "camera.list", map[string]any{})
	if err != nil || !res.IsError || errorCode(res) != "blocked_by_policy" {
		t.Fatalf("slots were freed by the disconnect: %+v %v", res, err)
	}
	// They end when the camera call times out; then the slots are free again.
	deadline := time.Now().Add(12 * time.Second)
	for {
		res, err = callTool(cs, "camera.list", map[string]any{})
		if err == nil && !res.IsError {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("slots never freed: %+v %v", res, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestHTTPCallerSourceCanNeverYieldControl(t *testing.T) {
	src := mcpserver.HTTPCallers()
	for _, id := range []string{"a", "laptop-agent", "ops.agent-1", strings.Repeat("z", 64)} {
		req := &mcp.ServerRequest[*mcp.CallToolParamsRaw]{
			Params: &mcp.CallToolParamsRaw{Name: "camera.list"},
			Extra:  &mcp.RequestExtra{TokenInfo: &auth.TokenInfo{UserID: id}},
		}
		c, ok := src(context.Background(), req)
		if !ok || !c.Valid() || c.Control() {
			t.Errorf("id %q: ok=%v valid=%v control=%v", id, ok, c.Valid(), c.Control())
		}
	}
	// A hostile id (including the stdio operator's own) never becomes a Caller.
	for _, id := range []string{"", "stdio ", "Stdio", "a b", strings.Repeat("z", 65)} {
		req := &mcp.ServerRequest[*mcp.CallToolParamsRaw]{
			Params: &mcp.CallToolParamsRaw{Name: "x"}, Extra: &mcp.RequestExtra{TokenInfo: &auth.TokenInfo{UserID: id}},
		}
		if c, ok := src(context.Background(), req); ok && c.Control() {
			t.Errorf("id %q yielded control", id)
		}
	}
}

// Only cmd/onvif-mcp and mcpserver may call StdioOperator: the one place control is minted.
func TestStdioOperatorIsCalledOnlyFromTheStdioWiring(t *testing.T) {
	root := filepath.Join("..", "..")
	allowed := map[string]bool{
		filepath.Join("internal", "mcpserver", "http.go"): true,
		filepath.Join("cmd", "onvif-mcp", "main.go"):      true,
	}
	fset := token.NewFileSet()
	var offenders []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			case *ast.Ident:
				name = fn.Name
			}
			if name == "StdioOperator" && !allowed[rel] {
				offenders = append(offenders, rel)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) != 0 {
		t.Errorf("StdioOperator called outside the stdio wiring: %v", offenders)
	}
}

// ---- process level ----

func startHTTPProcess(t *testing.T, cfgPath, tokensPath string) (*exec.Cmd, *syncBuf, *syncBuf, string) {
	t.Helper()
	cmd := exec.Command(binary(t), "-config", cfgPath, "-transport", "http", "-listen", "127.0.0.1:0", "-http-tokens", tokensPath) //nolint:gosec // test-built binary
	so, se := &syncBuf{}, &syncBuf{}
	cmd.Stdout, cmd.Stderr = so, se
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	deadline := time.Now().Add(15 * time.Second)
	for {
		if m := listenRe.FindStringSubmatch(se.String()); m != nil {
			return cmd, so, se, m[1]
		}
		if time.Now().After(deadline) {
			t.Fatalf("no startup line:\n%s", se)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestHTTPProcessSmokeInitializeThenSIGTERM(t *testing.T) {
	cam := testcam.Start(t)
	tp, toks := makeTokens(t, tokenSpec{id: "smoke"})
	cmd, so, se, addr := startHTTPProcess(t, controlConfig(t, cam), tp)

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}`
	req, _ := http.NewRequest("POST", "http://"+addr+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+toks["smoke"])
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"serverInfo"`) || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("initialize: %d %s %q", resp.StatusCode, resp.Header.Get("Content-Type"), b)
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SIGTERM exit: %v\n%s", err, se)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("did not exit on SIGTERM")
	}
	if so.String() != "" {
		t.Errorf("stdout not empty: %q", so.String())
	}
	if strings.Contains(se.String(), toks["smoke"]) || strings.Contains(se.String(), cam.Password()) {
		t.Error("secret on stderr")
	}
	if !strings.Contains(se.String(), "shutting down") || !strings.Contains(se.String(), "server stopped") {
		t.Errorf("drain log lines missing:\n%s", se)
	}
}

func TestHTTPSecondSignalTerminatesAStuckDrain(t *testing.T) {
	cfg := hungConfig(t, 60) // bounds how long each hung handler runs
	tp, toks := makeTokens(t, tokenSpec{id: "t"})
	cmd, _, se, addr := startHTTPProcess(t, cfg, tp)

	// Park a call on the hung camera so the drain has something to wait for.
	go func() {
		req, _ := http.NewRequest("POST", "http://"+addr+"/mcp", strings.NewReader(
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"camera.describe","arguments":{"camera":"cam1"}}}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+toks["t"])
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	time.Sleep(700 * time.Millisecond) // the call is in the handler (it logs only when it ends)

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	for !strings.Contains(se.String(), "shutting down") {
		if time.Now().After(deadline.Add(10 * time.Second)) {
			t.Fatalf("drain did not start:\n%s", se)
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("exited 0 on a second signal during a stuck drain; want the default fatal signal")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a second signal did not terminate the process promptly")
	}
}

// hungConfig is a config whose only camera accepts connections and never answers,
// with the given per-camera timeout.
func hungConfig(t *testing.T, timeoutSeconds int) string {
	t.Helper()
	body := fmt.Sprintf(`{"cameras":{"cam1":{"endpoint":%q,"username":"u","password":"hung-camera-pw","timeout_seconds":%d}}}`,
		hangEndpoint(t), timeoutSeconds)
	p := filepath.Join(t.TempDir(), "cameras.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
