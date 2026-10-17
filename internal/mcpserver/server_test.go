package mcpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
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
	return New(registry.New(cfg), quietLog()), cam
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

func TestReadToolsCarryAllFourAnnotations(t *testing.T) {
	srv, _ := newTestServer(t, false)
	cs := connect(t, srv)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range res.Tools {
		a := tool.Annotations
		if a == nil {
			t.Errorf("%s has no annotations", tool.Name)
			continue
		}
		if !a.ReadOnlyHint {
			continue // write tools are covered in Phase 8
		}
		if a.DestructiveHint == nil {
			t.Errorf("%s: DestructiveHint must be set explicitly, not left nil", tool.Name)
		}
		if a.OpenWorldHint == nil {
			t.Errorf("%s: OpenWorldHint must be set explicitly, not left nil", tool.Name)
		}
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
