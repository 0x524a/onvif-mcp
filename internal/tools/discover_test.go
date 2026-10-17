package tools

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0x524a/onvif-go/discovery"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/registry"
)

type fakeDisc struct {
	mu      sync.Mutex
	devs    []*discovery.Device
	err     error
	timeout time.Duration
	calls   int
}

func (f *fakeDisc) discover(_ context.Context, d time.Duration) ([]*discovery.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.timeout = d
	return f.devs, f.err
}

func discoverSession(t *testing.T, f *fakeDisc) *mcp.ClientSession {
	t.Helper()
	return harnessDeps(t, Deps{
		Reg:      registry.New(&config.Config{Cameras: map[string]*config.Camera{}}),
		Log:      quietLog(),
		Discover: f.discover,
	})
}

func TestDiscoverEmptyIsSuccessNotError(t *testing.T) {
	f := &fakeDisc{}
	cs := discoverSession(t, f)
	res := call(t, cs, "camera.discover", map[string]any{})
	d := dataMap(t, res)
	c, ok := d["candidates"].([]any)
	if !ok || len(c) != 0 {
		t.Errorf("candidates must be an empty list, got %v", d["candidates"])
	}
}

func TestDiscoverDurationIsBounded(t *testing.T) {
	cases := []struct {
		arg  any
		want time.Duration
	}{
		{nil, 3 * time.Second},
		{0, 3 * time.Second},
		{5, 5 * time.Second},
		{10, 10 * time.Second},
		{999, 10 * time.Second},
	}
	for _, tc := range cases {
		f := &fakeDisc{}
		cs := discoverSession(t, f)
		args := map[string]any{}
		if tc.arg != nil {
			args["timeout_seconds"] = tc.arg
		}
		dataMap(t, call(t, cs, "camera.discover", args))
		if f.timeout != tc.want {
			t.Errorf("timeout_seconds=%v: discoverer got %v, want %v", tc.arg, f.timeout, tc.want)
		}
	}
}

func TestDiscoverNegativeTimeoutIsInvalidArgument(t *testing.T) {
	f := &fakeDisc{}
	cs := discoverSession(t, f)
	res := call(t, cs, "camera.discover", map[string]any{"timeout_seconds": -1})
	if !res.IsError {
		t.Fatalf("expected error: %s", wire(t, res))
	}
	if code, _ := errCode(t, res); code != "invalid_argument" {
		t.Errorf("code = %q", code)
	}
	if f.calls != 0 {
		t.Error("must not probe on invalid input")
	}
}

func TestDiscoverRejectsCredentialArguments(t *testing.T) {
	f := &fakeDisc{}
	cs := discoverSession(t, f)
	res := call(t, cs, "camera.discover", map[string]any{"username": "admin", "password": "hunter2"})
	if !res.IsError {
		t.Fatalf("credential arguments must be rejected: %s", wire(t, res))
	}
	if strings.Contains(wire(t, res), "hunter2") {
		t.Errorf("echoed a credential: %s", wire(t, res))
	}
	if f.calls != 0 {
		t.Error("must not probe")
	}
}

func TestDiscoverDedupesSortsAndRedactsHostileAnnouncements(t *testing.T) {
	f := &fakeDisc{devs: []*discovery.Device{
		{EndpointRef: "urn:uuid:b", XAddrs: []string{"http://admin:hunter2@10.0.0.9/onvif/device_service?token=qsecret"},
			Scopes: []string{"onvif://www.onvif.org/name/Bob"}},
		{EndpointRef: "urn:uuid:a", XAddrs: []string{"http://10.0.0.2/onvif/device_service"}},
		// Same address as the first, announced under another reference.
		{EndpointRef: "urn:uuid:c", XAddrs: []string{"http://10.0.0.9/onvif/device_service"}},
		// Unusable: no address, and a non-http scheme.
		{EndpointRef: "urn:uuid:d"},
		{EndpointRef: "urn:uuid:e", XAddrs: []string{"file:///etc/passwd", "javascript:alert(1)"}},
		nil,
	}}
	cs := discoverSession(t, f)
	res := call(t, cs, "camera.discover", map[string]any{})
	d := dataMap(t, res)
	w := wire(t, res)
	for _, secret := range []string{"hunter2", "admin:", "qsecret", "/etc/passwd", "javascript:"} {
		if strings.Contains(w, secret) {
			t.Errorf("output contains %q: %s", secret, w)
		}
	}
	cands, _ := d["candidates"].([]any)
	if len(cands) != 2 {
		t.Fatalf("want 2 candidates after dedupe and filtering, got %d: %s", len(cands), w)
	}
	first := cands[0].(map[string]any)["xaddrs"].([]any)[0].(string)
	if first != "http://10.0.0.2/onvif/device_service" {
		t.Errorf("not sorted, first = %q", first)
	}
	if ig, _ := d["ignored"].(float64); ig != 2 {
		t.Errorf("ignored = %v, want 2", d["ignored"])
	}
	snip := cands[0].(map[string]any)["config_snippet"].(string)
	if !strings.Contains(snip, `"endpoint"`) || strings.Contains(strings.ToLower(snip), "password") {
		t.Errorf("snippet must carry an endpoint and no credential fields: %s", snip)
	}
}

func TestDiscoverSnippetIsValidJSONForHostileEndpoint(t *testing.T) {
	f := &fakeDisc{devs: []*discovery.Device{
		{EndpointRef: "urn:uuid:x", XAddrs: []string{`http://10.0.0.5/a"b","password":"x`}},
	}}
	cs := discoverSession(t, f)
	d := dataMap(t, call(t, cs, "camera.discover", map[string]any{}))
	cands, _ := d["candidates"].([]any)
	for _, c := range cands {
		snip := c.(map[string]any)["config_snippet"].(string)
		if strings.Contains(snip, `"password"`) {
			t.Errorf("hostile endpoint injected a field into the snippet: %s", snip)
		}
	}
}

func TestDiscoverErrorBecomesToolError(t *testing.T) {
	f := &fakeDisc{err: errors.New("failed to open probe socket: boom")}
	cs := discoverSession(t, f)
	res := call(t, cs, "camera.discover", map[string]any{})
	if !res.IsError {
		t.Fatalf("expected error: %s", wire(t, res))
	}
	if code, _ := errCode(t, res); code == "" {
		t.Errorf("no error code: %s", wire(t, res))
	}
}

func TestDiscoverPartialResultsSurviveAProbeError(t *testing.T) {
	f := &fakeDisc{
		devs: []*discovery.Device{{EndpointRef: "urn:uuid:a", XAddrs: []string{"http://10.0.0.2/s"}}},
		err:  errors.New("failed to read UDP response: late"),
	}
	cs := discoverSession(t, f)
	d := dataMap(t, call(t, cs, "camera.discover", map[string]any{}))
	if c, _ := d["candidates"].([]any); len(c) != 1 {
		t.Errorf("devices found before the error must be kept: %v", d)
	}
}

func TestDiscoverIsOpenWorldAndReadOnly(t *testing.T) {
	cs := discoverSession(t, &fakeDisc{})
	lt, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range lt.Tools {
		if tl.Name != "camera.discover" {
			continue
		}
		a := tl.Annotations
		if a == nil || a.OpenWorldHint == nil || !*a.OpenWorldHint {
			t.Errorf("OpenWorldHint must be true: %+v", a)
		}
		if !a.ReadOnlyHint {
			t.Error("ReadOnlyHint must be true")
		}
		return
	}
	t.Fatal("camera.discover not registered")
}

func TestDiscoverDoesNotAddToRegistry(t *testing.T) {
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{}})
	f := &fakeDisc{devs: []*discovery.Device{{EndpointRef: "urn:uuid:a", XAddrs: []string{"http://10.0.0.2/s"}}}}
	cs := harnessDeps(t, Deps{Reg: reg, Log: quietLog(), Discover: f.discover})
	dataMap(t, call(t, cs, "camera.discover", map[string]any{}))
	if n := len(reg.List()); n != 0 {
		t.Errorf("discovery must never register a camera, registry has %d", n)
	}
}
