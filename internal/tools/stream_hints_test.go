package tools

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/0x524A/rtspeek/pkg/rtspeek"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/probe"
	"github.com/0x524a/onvif-mcp/internal/redact"
)

const hintPW = "zqxv-hint-pw" //nolint:gosec // fixed test secret, not a credential

func failWith(msg string) *captureProber {
	return &captureProber{err: func(string) error { return errors.New(msg) }}
}

// The text content block is what a text-only client shows the model. It must
// carry the tracks, and redact.Scrub must leave it alone.
func TestInspectTextContentCarriesTheTracks(t *testing.T) {
	for name, cam := range map[string]config.Camera{
		"authenticated":   {Username: "u", Password: hintPW},
		"unauthenticated": {TrustAdvertisedHosts: true},
	} {
		t.Run(name, func(t *testing.T) {
			uri := "rtsp://127.0.0.1:1/s"
			if cam.TrustAdvertisedHosts {
				uri = "rtsp://127.0.0.2:1/s"
			}
			env := streamSession(t, uri, cam, &captureProber{res: h264Result()})
			txt := inspect(t, env.cs, nil).Content[0].(*mcp.TextContent).Text
			for _, want := range []string{"H264", "1920x1080", "1 track(s)"} {
				if !strings.Contains(txt, want) {
					t.Errorf("text %q lacks %q", txt, want)
				}
			}
			if strings.Contains(txt, "REDACTED") {
				t.Errorf("text was redacted: %q", txt)
			}
			wantAuth := "probed without credentials"
			if !cam.TrustAdvertisedHosts {
				wantAuth = "probed with the camera's credentials"
			}
			if !strings.Contains(txt, wantAuth) {
				t.Errorf("text %q lacks %q", txt, wantAuth)
			}
		})
	}
}

func TestInspectSummaryIsUnchangedByScrub(t *testing.T) {
	tracks := []TrackInfo{{Type: "video", Format: "H264", Width: 1280, Height: 720}, {Type: "audio", Format: "PCMA"}}
	for _, auth := range []bool{true, false} {
		for name, d := range map[string]InspectData{
			"described":      {Stream: "rtsp://h:554/s", Authenticated: auth, DescribeOK: true, Tracks: tracks},
			"no tracks":      {Stream: "rtsp://h:554/s", Authenticated: auth, DescribeOK: true},
			"no description": {Stream: "rtsp://h:554/s", Authenticated: auth},
		} {
			got := inspectSummary(d)
			if s := redact.Scrub(got); s != got {
				t.Errorf("%s auth=%v: Scrub changed the summary\n  from %q\n  to   %q", name, auth, got, s)
			}
		}
	}
}

func TestInspectHints(t *testing.T) {
	trusted := config.Camera{TrustAdvertisedHosts: true}
	for _, tc := range []struct {
		name      string
		uri       string
		cam       config.Camera
		prober    *captureProber
		wantCode  string
		wantHints []string
		notHints  []string
	}{
		{"401 with no credentials offered", "rtsp://127.0.0.2:1/s", trusted, failWith("DESCRIBE failed: 401 Unauthorized"),
			"auth_failed", []string{"requires credentials", "none were offered", "another host", "never sends"},
			[]string{"rejected the camera's configured credentials"}},
		{"401 with credentials offered", "rtsp://127.0.0.1:1/s", config.Camera{Username: "u", Password: hintPW},
			failWith("DESCRIBE failed: 401 Unauthorized"), "auth_failed", []string{"rejected the camera's configured credentials"}, nil},
		{"timeout", "rtsp://127.0.0.1:1/s", config.Camera{}, failWith("stream probe timed out: context deadline exceeded"),
			"timeout", []string{"5 s", "capped at 10", "retry once", "larger timeout_seconds", "streaming"}, nil},
		{"not found", "rtsp://127.0.0.1:1/s", config.Camera{}, failWith("DESCRIBE failed: 404 Not Found"),
			"not_found", []string{"path may be wrong", "media.stream_uri", "media.profiles"}, nil},
		{"redirect", "rtsp://127.0.0.1:1/s", config.Camera{}, &captureProber{err: func(string) error {
			return fmt.Errorf("probe: %w", probe.ErrRedirected)
		}}, "device_fault", []string{"redirect", "never follows", "media.stream_uri"}, nil},
		{"EOF during describe with credentials", "rtsp://127.0.0.1:1/s", config.Camera{Username: "u", Password: hintPW},
			&captureProber{err: func(string) error { return fmt.Errorf("RTSP describe failed: %w", probe.ErrEndedDuringDescribe) }},
			"internal", []string{"credentials may be wrong", "closed the connection"}, nil},
		{"EOF during describe without credentials", "rtsp://127.0.0.2:1/s", trusted,
			&captureProber{err: func(string) error { return fmt.Errorf("RTSP describe failed: %w", probe.ErrEndedDuringDescribe) }},
			"internal", []string{"without credentials", "require them"}, []string{"credentials may be wrong"}},
		{"unusable uri", "http://127.0.0.1/s", config.Camera{}, &captureProber{res: h264Result()},
			"device_fault", []string{"media.stream_uri"}, []string{"profile tokens", "media.profiles"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := streamSession(t, tc.uri, tc.cam, tc.prober)
			code, hint := errCode(t, inspect(t, env.cs, nil))
			if code != tc.wantCode {
				t.Errorf("code = %q, want %q (hint %q)", code, tc.wantCode, hint)
			}
			for _, w := range tc.wantHints {
				if !strings.Contains(hint, w) {
					t.Errorf("hint %q lacks %q", hint, w)
				}
			}
			for _, w := range tc.notHints {
				if strings.Contains(hint, w) {
					t.Errorf("hint %q must not contain %q", hint, w)
				}
			}
			if strings.Contains(hint, "REDACTED") {
				t.Errorf("hint was redacted: %q", hint)
			}
		})
	}
}

func TestInspectTimeoutHintNamesTheTimeoutInForce(t *testing.T) {
	env := streamSession(t, "rtsp://127.0.0.1:1/s", config.Camera{}, failWith("stream probe timed out: context deadline exceeded"))
	_, hint := errCode(t, inspect(t, env.cs, map[string]any{"timeout_seconds": 2}))
	if !strings.Contains(hint, "within 2 s") {
		t.Errorf("hint = %q", hint)
	}
}

func TestInspectDescriptionSaysTheTimeoutIsIndependent(t *testing.T) {
	env := streamSession(t, "rtsp://127.0.0.1:1/s", config.Camera{}, &captureProber{res: h264Result()})
	tools, err := env.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range tools.Tools {
		if tl.Name == "stream.inspect" {
			for _, w := range []string{"independent of the camera's own timeout_seconds", "redirect"} {
				if !strings.Contains(tl.Description, w) {
					t.Errorf("description lacks %q", w)
				}
			}
			return
		}
	}
	t.Fatal("stream.inspect not listed")
}

// Review proofs, kept as regression tests.

func TestInspectProberErrorChainSurvivesToClassification(t *testing.T) {
	env := streamSession(t, "rtsp://127.0.0.1:1/s", config.Camera{}, &captureProber{err: func(string) error {
		return fmt.Errorf("probe failed: %w", rtspeek.ErrInvalidURL)
	}})
	if code, _ := errCode(t, inspect(t, env.cs, nil)); code != "invalid_argument" {
		t.Errorf("code = %q", code)
	}
}

func TestInspectEmptyStreamURIIsSaidPlainly(t *testing.T) {
	env := streamSession(t, "", config.Camera{}, &captureProber{res: h264Result()})
	if w := wire(t, inspect(t, env.cs, nil)); !strings.Contains(w, "returned no stream URI") {
		t.Errorf("want the no-stream-URI message: %s", w)
	}
}

func TestInspectNilProbeResultSaysSo(t *testing.T) {
	env := streamSession(t, "rtsp://127.0.0.1:1/s", config.Camera{}, &captureProber{res: nil})
	if w := wire(t, inspect(t, env.cs, nil)); !strings.Contains(w, "returned no data") {
		t.Errorf("nil result must be reported as such: %s", w)
	}
}

func TestInspectNegativeTimeoutAtHandlerLevel(t *testing.T) {
	_, out, _ := inspectStream(context.Background(), Deps{}, probe.FakeProber{}, StreamInspectIn{Camera: "c", Profile: "p", TimeoutSeconds: -1})
	if out.Error == nil || out.Error.Code != "invalid_argument" {
		t.Errorf("out = %+v", out)
	}
}

func TestInspectStreamFieldHasNoQuery(t *testing.T) {
	env := streamSession(t, "rtsp://127.0.0.1:1/s?channel=1&amp;zzunknown=abcdef", config.Camera{}, &captureProber{res: h264Result()})
	if got := dataMap(t, inspect(t, env.cs, nil))["stream"]; got != "rtsp://127.0.0.1:1/s" {
		t.Errorf("stream = %v", got)
	}
}

func TestInspectNilProberDefaultsToTheRealOne(t *testing.T) {
	env := streamSession(t, "rtsp://127.0.0.1:1/s", config.Camera{}, nil)
	if code, _ := errCode(t, inspect(t, env.cs, nil)); code != "unreachable" {
		t.Errorf("code = %q", code)
	}
}

// The prober's own scrubbing is not the only defence: the tool removes the
// credentials in every form it knows, including a base64 echo of the Basic
// payload, which the general redactor does not recognise.
func TestInspectScrubsABase64EchoOfTheCredentials(t *testing.T) {
	echo := base64.StdEncoding.EncodeToString([]byte(canaryUser + ":" + canaryPass))
	env := streamSession(t, "rtsp://127.0.0.1:1/s", config.Camera{}, failWith("bad status code: 404 ("+echo+")"))
	if w := wire(t, inspect(t, env.cs, nil)); strings.Contains(w, echo) {
		t.Errorf("the base64 echo reached the wire: %s", w)
	}
}

func TestTrackInfosCleansWhatTheProberReturned(t *testing.T) {
	got := trackInfos(&probe.Result{Tracks: []probe.Track{{Index: 3, Type: "vi\x1bdeo", Format: "H2\u202e64", Width: 4, Height: 5}}})
	if len(got) != 1 || got[0].Type != "video" || got[0].Format != "H264" || got[0].Index != 3 || got[0].Width != 4 || got[0].Height != 5 {
		t.Errorf("trackInfos = %+v", got)
	}
}

// Shutdown must stop an in-flight stream.inspect: with the server context
// already done, nothing is probed.
func TestInspectIsScopedToTheServerContext(t *testing.T) {
	base, cancel := context.WithCancel(context.Background())
	cancel()
	p := &captureProber{res: h264Result()}
	env := streamSessionBase(base, t, "rtsp://127.0.0.1:1/s", config.Camera{}, p)
	res := inspect(t, env.cs, nil)
	if !res.IsError {
		t.Errorf("want an error once the server is shutting down: %s", wire(t, res))
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.urls) != 0 {
		t.Errorf("the prober was called %d time(s) after shutdown began", len(p.urls))
	}
}
