package mcpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/probe"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/testcam"
)

// connect wires a client to a server over an in-memory transport pair. The
// server is connected first: the client initialises the session on connect.
func connect(t *testing.T, srv *mcp.Server) *mcp.ClientSession {
	t.Helper()
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	cs, err := c.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newTestServer returns a server with one live camera (cam-a) and, when
// withDead is set, one whose endpoint refuses connections (cam-dead).
func newTestServer(t *testing.T, withDead bool) (*mcp.Server, *testcam.Cam) {
	t.Helper()
	cam := testcam.Start(t)
	cfg := &config.Config{Cameras: map[string]*config.Camera{
		"cam-a": {
			ID: "cam-a", Endpoint: cam.Endpoint(),
			Username: cam.Username(), Password: cam.Password(),
		},
	}}
	if withDead {
		cfg.Cameras["cam-dead"] = &config.Camera{
			ID: "cam-dead", Endpoint: "http://127.0.0.1:1/onvif/device_service",
			Username: "u", Password: "dead-camera-secret", TimeoutSeconds: 2,
		}
	}
	reg := registry.New(cfg)
	return New(reg, quietLog(), testPolicy(reg, false)), cam
}

func findTool(t *testing.T, cs *mcp.ClientSession, name string) *mcp.Tool {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	for _, tool := range res.Tools {
		if tool.Name == name {
			return tool
		}
	}
	t.Fatalf("%s was not registered", name)
	return nil
}

func callList(t *testing.T, cs *mcp.ClientSession, args any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "camera.list", Arguments: args})
	if err != nil {
		t.Fatalf("CallTool returned a protocol error: %v", err)
	}
	return res
}

func TestSchemaInferenceHandlesGenericOutEnvelope(t *testing.T) {
	srv, _ := newTestServer(t, false)
	tool := findTool(t, connect(t, srv), "camera.list")
	// The assertion that matters: the SDK derived schemas, including one from
	// the generic instantiation mcperr.Out[ListData].
	if tool.InputSchema == nil {
		t.Error("InputSchema was not inferred")
	}
	if tool.OutputSchema == nil {
		t.Fatal("OutputSchema was not inferred from Out[T]")
	}
	b, _ := json.Marshal(tool.OutputSchema)
	for _, want := range []string{`"data"`, `"error"`, `"cameras"`, `"retryable"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("output schema lacks %s: %s", want, b)
		}
	}
}

// Every registered tool is pinned exactly: the set of names, and all four
// annotation hints. Two of the hints are pointers the protocol reads as true
// when absent, so each must be present, and camera.discover (whatever answers on
// the network) and stream.inspect (a stream endpoint that is not the ONVIF
// service) are open-world.
func TestEveryToolCarriesExactAnnotations(t *testing.T) {
	srv, _ := newTestServer(t, false)
	cs := connect(t, srv)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	wantOpen := map[string]bool{
		"camera.list": false, "camera.discover": true, "camera.describe": false,
		"media.profiles": false, "media.stream_uri": false, "stream.inspect": true,
		"camera.snapshot": true, "ptz.status": false, "ptz.presets": false, "imaging.settings": false,
	}
	if len(res.Tools) != len(wantOpen) {
		t.Errorf("registered %d tools, want %d", len(res.Tools), len(wantOpen))
	}
	for _, tool := range res.Tools {
		open, known := wantOpen[tool.Name]
		if !known {
			t.Errorf("unexpected tool %q", tool.Name)
			continue
		}
		delete(wantOpen, tool.Name)
		a := tool.Annotations
		if a == nil {
			t.Errorf("%s has no annotations", tool.Name)
			continue
		}
		if strings.TrimSpace(a.Title) == "" {
			t.Errorf("%s: Title must be set", tool.Name)
		}
		if !a.ReadOnlyHint {
			t.Errorf("%s: ReadOnlyHint must be true", tool.Name)
		}
		if a.DestructiveHint == nil || *a.DestructiveHint {
			t.Errorf("%s: DestructiveHint must be explicitly false, got %v", tool.Name, a.DestructiveHint)
		}
		if !a.IdempotentHint {
			t.Errorf("%s: IdempotentHint must be true", tool.Name)
		}
		if a.OpenWorldHint == nil || *a.OpenWorldHint != open {
			t.Errorf("%s: OpenWorldHint must be explicitly %v, got %v", tool.Name, open, a.OpenWorldHint)
		}
	}
	for missing := range wantOpen {
		t.Errorf("tool %q is not registered", missing)
	}
}

// camera.list only ever contacts the fixed, operator-configured set, even with
// probe=true, so its world is closed. Discovery (a later tool) is the open one.
func TestCameraListIsClosedWorld(t *testing.T) {
	srv, _ := newTestServer(t, false)
	a := findTool(t, connect(t, srv), "camera.list").Annotations
	if a == nil || a.OpenWorldHint == nil || *a.OpenWorldHint {
		t.Errorf("camera.list must declare openWorldHint=false, got %+v", a)
	}
	if !a.ReadOnlyHint || a.DestructiveHint == nil || *a.DestructiveHint {
		t.Errorf("camera.list must be read-only and non-destructive, got %+v", a)
	}
}

func TestCameraListReturnsConfiguredCamera(t *testing.T) {
	srv, _ := newTestServer(t, false)
	res := callList(t, connect(t, srv), map[string]any{})
	if res.IsError {
		t.Fatalf("camera.list reported an error: %+v", res.Content)
	}
	b, _ := json.Marshal(res.StructuredContent)
	if !strings.Contains(string(b), "cam-a") {
		t.Errorf("camera.list did not list cam-a: %s", b)
	}
}

func TestCameraListReturnsStructuredAndTextContent(t *testing.T) {
	srv, cam := newTestServer(t, true)
	res := callList(t, connect(t, srv), map[string]any{})
	if res.StructuredContent == nil {
		t.Fatal("no structured content")
	}
	if len(res.Content) != 1 {
		t.Fatalf("want exactly one text block, got %d", len(res.Content))
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content[0] is %T, want *mcp.TextContent", res.Content[0])
	}
	if !strings.Contains(tc.Text, "cam-a") || !strings.Contains(tc.Text, "cam-dead") {
		t.Errorf("text should name the cameras: %q", tc.Text)
	}
	if strings.HasPrefix(strings.TrimSpace(tc.Text), "{") {
		t.Errorf("text should be a short summary, not a JSON dump: %q", tc.Text)
	}
	for _, secret := range []string{cam.Password(), "dead-camera-secret"} {
		if strings.Contains(tc.Text, secret) {
			t.Errorf("text content leaks a password")
		}
	}
}

// Guards the generic mcp.AddTool property: arguments are validated against
// the input schema and a failure comes back as a tool error (IsError), not a
// protocol error. A tool registered with the srv.AddTool method would skip
// validation entirely and make this test fail.
func TestCameraListRejectsBadInput(t *testing.T) {
	srv, _ := newTestServer(t, false)
	cs := connect(t, srv)
	cases := map[string]any{
		"unknown field":      map[string]any{"bogus": 1},
		"probe wrong type":   map[string]any{"probe": "yes"},
		"probe number":       map[string]any{"probe": 1},
		"arguments not json": []any{1, 2},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			res := callList(t, cs, args)
			if !res.IsError {
				t.Fatalf("expected a tool error, got success: %+v", res.StructuredContent)
			}
			if len(res.Content) == 0 {
				t.Fatal("error result has no text content")
			}
			tc, ok := res.Content[0].(*mcp.TextContent)
			if !ok || tc.Text == "" {
				t.Fatalf("error content is not readable text: %#v", res.Content[0])
			}
		})
	}
}

func TestDefaultCallDoesNotProbe(t *testing.T) {
	srv, _ := newTestServer(t, true)
	cams := decodeCameras(t, callList(t, connect(t, srv), map[string]any{}))
	if len(cams) != 2 {
		t.Fatalf("want 2 cameras, got %d", len(cams))
	}
	for _, c := range cams {
		if c.State != "" || c.ErrorCode != "" || c.Error != "" {
			t.Errorf("%s: probe=false must not contact the camera, got %+v", c.ID, c)
		}
	}
}

func decodeCameras(t *testing.T, res *mcp.CallToolResult) []registry.Status {
	t.Helper()
	b, _ := json.Marshal(res.StructuredContent)
	var out struct {
		Data struct {
			Cameras []registry.Status `json:"cameras"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out.Data.Cameras
}

func TestSummarize(t *testing.T) {
	cases := []struct {
		name string
		in   []registry.Status
		want string
	}{
		{"empty", nil, "No cameras are configured."},
		{"not probed", []registry.Status{{ID: "a", Endpoint: "http://h/x"}},
			"1 camera(s): a. Full detail is in the structured result."},
		{"reachable", []registry.Status{{ID: "a", State: "reachable"}},
			"1 camera(s): a (reachable). Full detail is in the structured result."},
		{"unreachable with code", []registry.Status{
			{ID: "a", State: "reachable"},
			{ID: "b", State: "unreachable", ErrorCode: "timeout", Error: "Post http://h: slow", Endpoint: "http://h/x"}},
			"2 camera(s): a (reachable), b (unreachable: timeout). Full detail is in the structured result."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := summarize(c.in)
			if got != c.want {
				t.Errorf("summarize = %q, want %q", got, c.want)
			}
			if strings.Contains(got, "http") || strings.ContainsAny(got, "{[") {
				t.Errorf("summary must carry no endpoint text or JSON: %q", got)
			}
		})
	}
}

func TestEmptyConfigListsNothing(t *testing.T) {
	reg := registry.New(&config.Config{})
	srv := New(reg, quietLog(), testPolicy(reg, false))
	res := callList(t, connect(t, srv), map[string]any{"probe": true})
	if res.IsError {
		t.Fatalf("empty config must not be an error: %+v", res.Content)
	}
	tc := res.Content[0].(*mcp.TextContent)
	if tc.Text != "No cameras are configured." {
		t.Errorf("text = %q", tc.Text)
	}
}

func TestDescriptionExplainsFields(t *testing.T) {
	srv, _ := newTestServer(t, false)
	d := findTool(t, connect(t, srv), "camera.list").Description
	for _, want := range []string{"id", "endpoint", "credentials", "control_allowed", "state", "error_code", "probe", "never fails", "time budget"} {
		if !strings.Contains(d, want) {
			t.Errorf("description lacks %q: %s", want, d)
		}
	}
}

func TestProbeMarksUnreachableCameraWithoutFailingCall(t *testing.T) {
	srv, _ := newTestServer(t, true)
	res := callList(t, connect(t, srv), map[string]any{"probe": true})
	if res.IsError {
		t.Fatalf("a dead camera must not fail the call: %+v", res.Content)
	}
	b, _ := json.Marshal(res.StructuredContent)
	var out struct {
		Data struct {
			Cameras []registry.Status `json:"cameras"`
		} `json:"data"`
		Error any `json:"error"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Error != nil {
		t.Errorf("unexpected error payload: %v", out.Error)
	}
	got := map[string]registry.Status{}
	for _, c := range out.Data.Cameras {
		got[c.ID] = c
	}
	if got["cam-a"].State != registry.StateReachable {
		t.Errorf("cam-a state = %q, want reachable", got["cam-a"].State)
	}
	dead := got["cam-dead"]
	if dead.State != registry.StateUnreachable {
		t.Errorf("cam-dead state = %q, want unreachable", dead.State)
	}
	if dead.ErrorCode == "" {
		t.Error("cam-dead should carry an error code")
	}
}

func TestOutputValidatesAgainstOutputSchema(t *testing.T) {
	srv, _ := newTestServer(t, true)
	cs := connect(t, srv)
	tool := findTool(t, cs, "camera.list")
	raw, _ := json.Marshal(tool.OutputSchema)
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatalf("resolve schema: %v", err)
	}
	for _, args := range []map[string]any{{}, {"probe": true}} {
		res := callList(t, cs, args)
		b, _ := json.Marshal(res.StructuredContent)
		var inst any
		if err := json.Unmarshal(b, &inst); err != nil {
			t.Fatal(err)
		}
		if err := resolved.Validate(inst); err != nil {
			t.Errorf("args %v: result does not satisfy advertised schema: %v\n%s", args, err, b)
		}
	}
	// And the validator must actually reject a wrong shape.
	if err := resolved.Validate(map[string]any{"data": map[string]any{"cameras": "nope"}}); err == nil {
		t.Error("schema accepted a malformed result; validation check is vacuous")
	}
}

func TestResultsContainNoPassword(t *testing.T) {
	srv, cam := newTestServer(t, true)
	cs := connect(t, srv)
	for _, args := range []map[string]any{{}, {"probe": true}} {
		res := callList(t, cs, args)
		b, _ := json.Marshal(res)
		for _, secret := range []string{cam.Password(), "dead-camera-secret"} {
			if strings.Contains(string(b), secret) {
				t.Errorf("args %v: password appears in the result", args)
			}
		}
	}
}

func TestVersion(t *testing.T) {
	if Version() == "" {
		t.Error("empty version")
	}
}

// hangListener accepts connections and never answers, like a wedged camera.
func hangListener(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			conns = append(conns, c)
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		<-done
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return "http://" + l.Addr().String() + "/onvif/device_service"
}

func hungServer(t *testing.T, opts ...Option) *mcp.Server {
	t.Helper()
	cfg := &config.Config{Cameras: map[string]*config.Camera{
		"hung": {ID: "hung", Endpoint: hangListener(t), Username: "u", Password: "p", TimeoutSeconds: 60},
	}}
	reg := registry.New(cfg)
	return New(reg, quietLog(), testPolicy(reg, false), opts...)
}

func TestBaseContextCancelAbortsInFlightProbe(t *testing.T) {
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	cs := connect(t, hungServer(t, WithBaseContext(base)))
	type result struct {
		res *mcp.CallToolResult
		err error
	}
	ch := make(chan result, 1)
	go func() {
		res, err := cs.CallTool(context.Background(),
			&mcp.CallToolParams{Name: "camera.list", Arguments: map[string]any{"probe": true}})
		ch <- result{res, err}
	}()
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	cancel()
	select {
	case r := <-ch:
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("handler took %v to stop after shutdown", d)
		}
		if r.err == nil && !r.res.IsError {
			t.Errorf("a cancelled probe must not be a successful listing: %+v", r.res.StructuredContent)
		}
		if r.res != nil {
			b, _ := json.Marshal(r.res)
			for _, bad := range []string{"unreachable", "internal"} {
				if strings.Contains(string(b), bad) {
					t.Errorf("cancelled probe reported as %q: %s", bad, b)
				}
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("in-flight probe ignored the base context cancellation")
	}
}

// The agent-legible envelope for schema-validation failures. Checked against
// go-sdk v1.7.0, where these never reach the handler.
func TestArgumentErrorsUseTheEnvelope(t *testing.T) {
	srv, cam := newTestServer(t, false)
	cs := connect(t, srv)
	cases := []struct {
		name  string
		args  any
		field string
	}{
		{"unknown field", map[string]any{"bogus": 1}, "bogus"},
		{"wrong type", map[string]any{"probe": "yes"}, "probe"},
		{"not an object", []any{1, 2}, "arguments"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := callList(t, cs, c.args)
			if !res.IsError {
				t.Fatal("want IsError")
			}
			b, _ := json.Marshal(res.StructuredContent)
			var out struct {
				Data  any `json:"data"`
				Error *struct {
					Code      string `json:"code"`
					Retryable *bool  `json:"retryable"`
					Message   string `json:"message"`
					Hint      string `json:"hint"`
				} `json:"error"`
			}
			if err := json.Unmarshal(b, &out); err != nil || out.Error == nil {
				t.Fatalf("no error envelope in structuredContent: %s", b)
			}
			if out.Data != nil {
				t.Errorf("error envelope must not carry data: %s", b)
			}
			e := out.Error
			if e.Code != "invalid_argument" || e.Retryable == nil || *e.Retryable {
				t.Errorf("code/retryable = %q/%v", e.Code, e.Retryable)
			}
			if !strings.Contains(e.Message, c.field) {
				t.Errorf("message does not name %q: %q", c.field, e.Message)
			}
			if e.Hint == "" {
				t.Error("no hint")
			}
			tc, ok := res.Content[0].(*mcp.TextContent)
			if !ok || !strings.Contains(tc.Text, c.field) {
				t.Errorf("text content should carry the message: %#v", res.Content[0])
			}
			if strings.Contains(string(b), cam.Password()) {
				t.Error("password in error envelope")
			}
		})
	}
}

func TestArgumentErrorMessageIsScrubbed(t *testing.T) {
	srv, _ := newTestServer(t, false)
	res := callList(t, connect(t, srv),
		map[string]any{"probe": "http://admin:Hunter2Pass@10.0.0.1/x"}) //nolint:gosec // fake credential for a leak test
	b, _ := json.Marshal(res)
	if !res.IsError || strings.Contains(string(b), "Hunter2Pass") {
		t.Errorf("echoed value must be scrubbed: %s", b)
	}
}

// undescribed walks a JSON schema and returns the path of every property that
// has no description, following array items, composition keywords and $defs.
func undescribed(node any, path string, root map[string]any) []string {
	m, ok := node.(map[string]any)
	if !ok {
		return nil
	}
	var out []string
	if ref, _ := m["$ref"].(string); ref != "" {
		// Resolve "#/$defs/Name" against the root.
		if name, found := strings.CutPrefix(ref, "#/$defs/"); found {
			if defs, ok := root["$defs"].(map[string]any); ok {
				return undescribed(defs[name], path, root)
			}
		}
	}
	if props, ok := m["properties"].(map[string]any); ok {
		for name, p := range props {
			pm, _ := p.(map[string]any)
			if d, _ := pm["description"].(string); strings.TrimSpace(d) == "" {
				// A $ref'd definition may carry the description.
				described := false
				if ref, _ := pm["$ref"].(string); ref != "" {
					if def, _ := root["$defs"].(map[string]any)[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any); def != nil {
						d, _ := def["description"].(string)
						described = strings.TrimSpace(d) != ""
					}
				}
				if !described {
					out = append(out, path+"."+name)
				}
			}
			out = append(out, undescribed(p, path+"."+name, root)...)
		}
	}
	for _, k := range []string{"items", "additionalProperties"} {
		out = append(out, undescribed(m[k], path+"[]", root)...)
	}
	for _, k := range []string{"anyOf", "oneOf", "allOf"} {
		if arr, ok := m[k].([]any); ok {
			for _, e := range arr {
				out = append(out, undescribed(e, path, root)...)
			}
		}
	}
	return out
}

// Every field an agent can read or write is documented in the schema it is
// shown: units, ranges and the meaning of absence cannot be guessed.
func TestEveryToolSchemaFieldIsDescribed(t *testing.T) {
	srv, _ := newTestServer(t, false)
	cs := connect(t, srv)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) != 10 {
		t.Fatalf("expected 10 tools, got %d", len(res.Tools))
	}
	for _, tool := range res.Tools {
		for label, s := range map[string]any{"input": tool.InputSchema, "output": tool.OutputSchema} {
			b, _ := json.Marshal(s)
			var root map[string]any
			if err := json.Unmarshal(b, &root); err != nil {
				t.Fatal(err)
			}
			for _, p := range undescribed(root, tool.Name+"."+label, root) {
				t.Errorf("no description: %s", p)
			}
		}
	}
}

// Each description tells an agent when to reach for the tool, what to call
// first, and what the tool does not do.
func TestToolDescriptionsGuideUse(t *testing.T) {
	srv, _ := newTestServer(t, false)
	cs := connect(t, srv)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	mustHave := map[string][]string{
		"camera.list":      {"first", "camera.discover"},
		"camera.discover":  {"blocks", "10 seconds", "camera.list"},
		"camera.describe":  {"camera.list", "not verified"},
		"media.profiles":   {"camera.list", "has_ptz", "source_token"},
		"media.stream_uri": {"media.profiles", "never", "Does not open"},
		"ptz.status":       {"media.profiles", "has_ptz", "-1"},
		"ptz.presets":      {"media.profiles", "has_ptz", "-1"},
		"imaging.settings": {"media.profiles", "video_source_token", "scale"},
		"stream.inspect":   {"media.profiles", "media.stream_uri", "best-effort", "trust_advertised_hosts", "Does not fetch frames"},
		"camera.snapshot":  {"media.profiles", "1 MiB", "lower-resolution profile", "trust_advertised_hosts", "Does not record or stream video"},
	}
	for _, tool := range res.Tools {
		want, ok := mustHave[tool.Name]
		if !ok {
			t.Errorf("unexpected tool %s", tool.Name)
			continue
		}
		d := tool.Description
		if !strings.Contains(d, "Use ") && !strings.Contains(d, "Use this") {
			t.Errorf("%s: description does not say when to use it: %q", tool.Name, d)
		}
		if !strings.Contains(d, "Does not") {
			t.Errorf("%s: description does not say what it does not do: %q", tool.Name, d)
		}
		for _, w := range want {
			if !strings.Contains(d, w) {
				t.Errorf("%s: description lacks %q: %q", tool.Name, w, d)
			}
		}
	}
}

// stream.inspect is wired with the real prober by default and takes an
// injected one; the camera's credentials reach the prober and nothing else.
func TestStreamInspectIsWiredWithAnInjectedProber(t *testing.T) {
	cam := testcam.Start(t)
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a": {ID: "cam-a", Endpoint: cam.Endpoint(), Username: cam.Username(), Password: cam.Password()},
	}})
	fake := probe.FakeProber{Result: &probe.Result{Reachable: true, DescribeOK: true, Protocol: "rtsp",
		Tracks: []probe.Track{{Type: "video", Format: "H264", Width: 640, Height: 480}}}}
	cs := connect(t, New(reg, quietLog(), testPolicy(reg, false), WithProber(fake)))
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "stream.inspect", Arguments: map[string]any{"camera": "cam-a", "profile": cam.ProfileToken()},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	if res.IsError || !strings.Contains(string(b), "H264") || !strings.Contains(string(b), `"width":640`) {
		t.Errorf("unexpected result: %s", b)
	}
	if strings.Contains(string(b), cam.Password()) {
		t.Errorf("password in output: %s", b)
	}
}

// camera.snapshot is wired with the operator's size cap, returns the image
// inline, and rejects bad input in the shared error envelope.
func TestSnapshotIsWiredWithTheConfiguredCap(t *testing.T) {
	cam := testcam.Start(t)
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"cam-a": {ID: "cam-a", Endpoint: cam.Endpoint(), Username: cam.Username(), Password: cam.Password()},
	}})
	args := map[string]any{"camera": "cam-a", "profile": cam.ProfileToken()}
	callSnap := func(cs *mcp.ClientSession, a map[string]any) *mcp.CallToolResult {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "camera.snapshot", Arguments: a})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	res := callSnap(connect(t, New(reg, quietLog(), testPolicy(reg, false))), args)
	var img *mcp.ImageContent
	for _, c := range res.Content {
		if i, ok := c.(*mcp.ImageContent); ok {
			img = i
		}
	}
	if res.IsError || img == nil || img.MIMEType != "image/jpeg" || len(img.Data) == 0 {
		t.Fatalf("default cap: %v", res)
	}
	if b, _ := json.Marshal(res); strings.Contains(string(b), cam.Password()) {
		t.Error("password in output")
	}

	small := connect(t, New(reg, quietLog(), testPolicy(reg, false), WithSnapshotMaxBytes(2048)))
	res = callSnap(small, args)
	b, _ := json.Marshal(res)
	if !res.IsError || !strings.Contains(string(b), "over the 2048 byte limit") || !strings.Contains(string(b), "media.profiles") {
		t.Errorf("cap of 2048: %s", b)
	}

	// Schema failures use the same envelope as every other tool.
	res = callSnap(small, map[string]any{"camera": "cam-a"})
	sc, _ := res.StructuredContent.(map[string]any)
	e, _ := sc["error"].(map[string]any)
	if !res.IsError || e["code"] != "invalid_argument" {
		t.Errorf("missing profile: %v", res)
	}
}
