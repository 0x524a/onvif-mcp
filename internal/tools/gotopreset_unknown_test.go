package tools

import (
	"net/http"
	"strings"
	"testing"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/testcam"
)

func plainReply(status int, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// Whatever the camera answers after the command was sent, short of a policy
// refusal, the outcome is unknown: the error says so, once, and is not retryable.
func TestAnyFailureAfterASendIsUnknownStateAndNotRetryable(t *testing.T) {
	replies := map[string]func(http.ResponseWriter, *http.Request){
		"html 500":  plainReply(500, "<html>boom</html>"),
		"text 500":  plainReply(500, "boom"),
		"empty 500": plainReply(500, ""),
		"empty 200": plainReply(200, ""),
	}
	for name, h := range replies {
		t.Run(name, func(t *testing.T) {
			fx := newPresetFixture(t, presetFixtureOpts{gotoHandler: h})
			cs := fx.rig(t, true)
			res := call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": "prof", "preset": "p1", "dry_run": false})
			code, hint := errCode(t, res)
			if code == "" {
				t.Fatalf("expected an error: %s", wire(t, res))
			}
			if !strings.Contains(hint, "may or may not") || !strings.Contains(hint, "ptz.status") {
				t.Errorf("code=%q hint=%q: want the unknown-state hint", code, hint)
			}
			if strings.Count(hint, "may or may not") != 1 {
				t.Errorf("hint repeats the warning: %q", hint)
			}
			if errField(res, "retryable") != false {
				t.Errorf("retryable = %v, want false", errField(res, "retryable"))
			}
			if a := lastAudit(t, fx.audit); a["executed"] != true {
				t.Errorf("audit = %v, want executed:true", a)
			}
			if fx.gotoCalls.Load() != 1 {
				t.Errorf("GotoPreset sent %d times", fx.gotoCalls.Load())
			}
		})
	}
}

// A policy refusal never reaches the camera, so it never claims an unknown state.
func TestPolicyRefusalCarriesNoUnknownStateHint(t *testing.T) {
	fx := newPresetFixture(t, presetFixtureOpts{})
	cs := fx.rig(t, true)
	args := map[string]any{"camera": "fx", "profile": "prof", "preset": "p1", "dry_run": false}
	call(t, cs, gotoTool, args)
	res := call(t, cs, gotoTool, args) // rate limited
	code, hint := errCode(t, res)
	if code != "blocked_by_policy" || containsUnknown(hint) {
		t.Errorf("code=%q hint=%q", code, hint)
	}
}

// The warning is added exactly once even if the tool already included it.
func TestUnknownStateHintIsAppendedExactlyOnce(t *testing.T) {
	cs, _ := sentRig(t, &mcperr.ToolError{Code: mcperr.CodeDeviceFault, Message: "m", Hint: "h " + sentUnknownHint}, "p1")
	res := call(t, cs, "test.sent", map[string]any{"camera": "cam-a", "dry_run": false})
	_, hint := errCode(t, res)
	if n := strings.Count(hint, sentUnknownHint); n != 1 {
		t.Errorf("warning appears %d times: %q", n, hint)
	}
}

// A camera id that reads like a secret's key does not hide the cause.
func TestSensitiveLookingCameraIDKeepsAuthFailedOnRealPaths(t *testing.T) {
	cam := testcam.Start(t)
	cams := map[string]*config.Camera{"pass-cam": {ID: "pass-cam", Endpoint: cam.Endpoint(), Username: cam.Username(),
		Password: "definitely-wrong", Control: true}}
	cs := harnessWith(t, cams)
	res := call(t, cs, "media.profiles", map[string]any{"camera": "pass-cam"})
	if code, hint := errCode(t, res); code != "auth_failed" || !strings.Contains(hint, "username and password") {
		t.Errorf("read: code=%q hint=%q: %s", code, hint, wire(t, res))
	}
}
