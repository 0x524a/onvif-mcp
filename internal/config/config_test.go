package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0x524a/onvif-mcp/internal/redact"
)

const sample = `{
  "cameras": {
    "front-door": {
      "endpoint": "http://192.0.2.10:80/onvif/device_service",
      "username": "operator",
      "password": "filepass",
      "control": true
    },
    "lobby": {
      "endpoint": "192.0.2.11",
      "username": "operator",
      "password": "filepass",
      "timeout_seconds": 4
    }
  }
}`

func writeBody(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cameras.json")
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func write(t *testing.T, mode os.FileMode) string {
	t.Helper()
	return writeBody(t, sample, mode)
}

func one(id, endpoint, password string) string {
	return fmt.Sprintf(`{"cameras":{%q:{"endpoint":%q,"password":%q}}}`, id, endpoint, password)
}

func TestLoadAssignsIDsFromMapKeys(t *testing.T) {
	cfg, err := Load(write(t, 0o600))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Cameras["front-door"].ID != "front-door" {
		t.Errorf("ID not backfilled from map key: %+v", cfg.Cameras["front-door"])
	}
}

func TestControlDefaultsOffPerCamera(t *testing.T) {
	cfg, err := Load(write(t, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Cameras["front-door"].Control {
		t.Error("front-door opted in and must have control true")
	}
	if cfg.Cameras["lobby"].Control {
		t.Error("a camera that did not opt in must default to control false")
	}
}

func TestTimeoutDefaultsToTenSeconds(t *testing.T) {
	cfg, err := Load(write(t, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Cameras["front-door"].Timeout(); got != 10*time.Second {
		t.Errorf("default timeout = %v, want 10s", got)
	}
	if got := cfg.Cameras["lobby"].Timeout(); got != 4*time.Second {
		t.Errorf("explicit timeout = %v, want 4s", got)
	}
}

func TestRefusesGroupOrWorldReadableFile(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o604, 0o666} {
		_, err := Load(write(t, mode))
		if !errors.Is(err, ErrConfigPermissions) {
			t.Errorf("mode %v: got %v, want ErrConfigPermissions", mode, err)
		}
	}
}

func TestEnvOverridesPassword(t *testing.T) {
	t.Setenv("ONVIF_MCP_FRONT_DOOR_PASSWORD", "envpass")
	cfg, err := Load(write(t, 0o600))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Cameras["front-door"].Password != "envpass" {
		t.Errorf("env override ignored: %q", cfg.Cameras["front-door"].Password)
	}
	if cfg.Cameras["lobby"].Password != "filepass" {
		t.Error("override leaked onto the wrong camera")
	}
}

func TestRejectsEmptyEndpoint(t *testing.T) {
	p := writeBody(t, `{"cameras":{"x":{"endpoint":""}}}`, 0o600)
	if _, err := Load(p); err == nil {
		t.Error("an empty endpoint must be rejected at load time")
	}
}

func TestLoadRegistersFilePasswordWithRedact(t *testing.T) {
	const pw = "file-secret-Zq81" //nolint:gosec // test fixture
	if _, err := Load(writeBody(t, one("cam", "192.0.2.1", pw), 0o600)); err != nil {
		t.Fatal(err)
	}
	got := redact.Scrub("camera said: bad credential " + pw + " rejected")
	if strings.Contains(got, pw) || !strings.Contains(got, "REDACTED") {
		t.Errorf("file password not scrubbed: %q", got)
	}
}

func TestLoadRegistersEnvOverrideAfterOverride(t *testing.T) {
	const envpw = "env-secret-Kp42" //nolint:gosec // test fixture
	t.Setenv("ONVIF_MCP_CAM_PASSWORD", envpw)
	if _, err := Load(writeBody(t, one("cam", "192.0.2.1", "file-secret-Hh73"), 0o600)); err != nil {
		t.Fatal(err)
	}
	got := redact.Scrub("denied " + envpw)
	if strings.Contains(got, envpw) || !strings.Contains(got, "REDACTED") {
		t.Errorf("env password not scrubbed: %q", got)
	}
}

func TestRejectsUnprotectablePassword(t *testing.T) {
	_, err := Load(writeBody(t, one("shorty", "192.0.2.1", "ab"), 0o600))
	if err == nil {
		t.Fatal("a password too short to scrub must be rejected")
	}
	if !strings.Contains(err.Error(), "shorty") {
		t.Errorf("error must name the camera ID: %v", err)
	}
	if strings.Contains(err.Error(), `"ab"`) {
		t.Errorf("error must not echo the password: %v", err)
	}
	if !strings.Contains(err.Error(), "log leakage") {
		t.Errorf("error should explain log leakage: %v", err)
	}
}

func TestRejectsShortEnvPassword(t *testing.T) {
	t.Setenv("ONVIF_MCP_CAM_PASSWORD", "xy")
	_, err := Load(writeBody(t, one("cam", "192.0.2.1", "file-secret-Aa11"), 0o600))
	if err == nil || !strings.Contains(err.Error(), "cam") {
		t.Errorf("short env password must be rejected naming the camera, got %v", err)
	}
}

func TestEmptyPasswordIsAllowed(t *testing.T) {
	if _, err := Load(writeBody(t, `{"cameras":{"open":{"endpoint":"192.0.2.9"}}}`, 0o600)); err != nil {
		t.Errorf("a camera with no password must load: %v", err)
	}
}

func TestRejectsEndpointWithUserinfo(t *testing.T) {
	for _, ep := range []string{
		"http://admin:hunter2pw@192.0.2.5/onvif/device_service",
		"admin:hunter2pw@192.0.2.5",
		"http://admin@192.0.2.5/",
	} {
		_, err := Load(writeBody(t, one("cam", ep, "file-secret-Bb22"), 0o600))
		if err == nil {
			t.Errorf("endpoint %q with userinfo must be rejected", ep)
			continue
		}
		if strings.Contains(err.Error(), "hunter2pw") || strings.Contains(err.Error(), ep) {
			t.Errorf("error echoes the endpoint: %v", err)
		}
		if !strings.Contains(err.Error(), "cam") {
			t.Errorf("error should name the camera: %v", err)
		}
	}
}

func TestAtSignAfterAuthorityIsNotUserinfo(t *testing.T) {
	ep := "http://192.0.2.5/onvif?x=a@b"
	if _, err := Load(writeBody(t, one("cam", ep, "file-secret-Cc33"), 0o600)); err != nil {
		t.Errorf("'@' outside the authority must be accepted: %v", err)
	}
}

func TestRefusesNonRegularFile(t *testing.T) {
	if _, err := Load(t.TempDir()); err == nil {
		t.Error("a directory must be refused")
	}
}

func TestSymlinkedConfigAllowedWhenTargetOK(t *testing.T) {
	target := write(t, 0o600)
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := Load(link); err != nil {
		t.Errorf("symlink to a 0600 file must load: %v", err)
	}
	loose := write(t, 0o644)
	link2 := filepath.Join(t.TempDir(), "link2.json")
	if err := os.Symlink(loose, link2); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := Load(link2); !errors.Is(err, ErrConfigPermissions) {
		t.Errorf("symlink to a loose file: got %v, want ErrConfigPermissions", err)
	}
}

func TestParseErrorsNeverEchoPassword(t *testing.T) {
	const pw = "leaky-secret-Vv55" //nolint:gosec // test fixture
	bodies := []string{
		// type mismatch: timeout is a string; password sits next to it
		`{"cameras":{"x":{"endpoint":"h","password":"` + pw + `","timeout_seconds":"` + pw + `"}}}`,
		// syntax error right after the password
		`{"cameras":{"x":{"endpoint":"h","password":"` + pw + `" "oops"}}}`,
		// wrong type for the password itself
		`{"cameras":{"x":{"endpoint":"h","password":{"v":"` + pw + `"}}}}`,
		// unterminated
		`{"cameras":{"x":{"endpoint":"h","password":"` + pw,
		// camera not an object
		`{"cameras":{"x":"` + pw + `"}}`,
	}
	for _, b := range bodies {
		_, err := Load(writeBody(t, b, 0o600))
		if err == nil {
			t.Errorf("body %q should fail to parse", b)
			continue
		}
		if strings.Contains(err.Error(), pw) {
			t.Errorf("parse error echoes password: %v", err)
		}
	}
}

func TestRejectsDuplicateEnvKeys(t *testing.T) {
	body := `{"cameras":{"a-b":{"endpoint":"h1"},"a_b":{"endpoint":"h2"}}}`
	_, err := Load(writeBody(t, body, 0o600))
	if err == nil {
		t.Fatal("camera IDs that map to the same env key must be rejected")
	}
	if !strings.Contains(err.Error(), "ONVIF_MCP_A_B_PASSWORD") {
		t.Errorf("error should name the colliding variable: %v", err)
	}
}

func TestRejectsBadCameraIDs(t *testing.T) {
	for _, id := range []string{"", "has space", "slash/id", "emojié", "a=b", strings.Repeat("x", 65)} {
		body := fmt.Sprintf(`{"cameras":{%q:{"endpoint":"h"}}}`, id)
		if _, err := Load(writeBody(t, body, 0o600)); err == nil {
			t.Errorf("camera ID %q must be rejected", id)
		}
	}
	for _, id := range []string{"a", "A.b_c-9", strings.Repeat("x", 64)} {
		body := fmt.Sprintf(`{"cameras":{%q:{"endpoint":"h"}}}`, id)
		if _, err := Load(writeBody(t, body, 0o600)); err != nil {
			t.Errorf("camera ID %q must be accepted: %v", id, err)
		}
	}
}

func TestCameraAndConfigNeverPrintPassword(t *testing.T) {
	const pw = "printme-secret-Ww66" //nolint:gosec // test fixture
	cam := &Camera{ID: "c", Endpoint: "h", Username: "u", Password: pw}
	cfg := &Config{Cameras: map[string]*Camera{"c": cam}}

	var outs []string
	for _, v := range []any{cam, *cam, cfg, *cfg} {
		outs = append(outs,
			fmt.Sprintf("%v", v), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v),
			fmt.Sprintf("%s", v), fmt.Sprintf("%q", v), fmt.Sprintf("%x", v), fmt.Sprintf("%d", v)) //nolint:revive
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		outs = append(outs, string(b))
		b, err = json.MarshalIndent(v, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		outs = append(outs, string(b))
	}
	for _, o := range outs {
		if strings.Contains(o, pw) {
			t.Errorf("password leaked: %s", o)
		}
	}
	if !strings.Contains(fmt.Sprintf("%+v", cam), "[REDACTED]") {
		t.Error("expected [REDACTED] marker in verbose output")
	}
	b, _ := json.Marshal(cam)
	if !strings.Contains(string(b), "[REDACTED]") || !strings.Contains(string(b), `"endpoint":"h"`) {
		t.Errorf("json output should keep other fields and mark password: %s", b)
	}
}

func TestCameraJSONStillUnmarshals(t *testing.T) {
	var c Camera
	if err := json.Unmarshal([]byte(`{"endpoint":"h","password":"realpw"}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.Password != "realpw" {
		t.Errorf("unmarshal must keep the real password, got %q", c.Password)
	}
}
