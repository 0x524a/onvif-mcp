package tools

import (
	"net/http"
	"strings"
	"testing"

	"github.com/0x524a/onvif-mcp/internal/config"
)

// A camera that moved and then answers 500 with a body that merely contains a
// word must not steer the classification: the body is the camera's, not evidence.
func TestReplyBodyCannotSteerClassification(t *testing.T) {
	bodies := []string{
		"<html>unauthorized</html>", "unauthorized", "<html>motor controller not found, retrying</html>", "not found",
		"<html>401 forbidden</html>", "no such motor",
	}
	for _, body := range bodies {
		t.Run(body, func(t *testing.T) {
			fx := newPresetFixture(t, presetFixtureOpts{gotoHandler: plainReply(500, body)})
			cs := fx.rig(t, true)
			res := call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": "prof", "preset": "p1", "dry_run": false})
			code, hint := errCode(t, res)
			if code != "internal" {
				t.Errorf("write path: code = %q, want internal: %s", code, wire(t, res))
			}
			if !strings.Contains(hint, "may or may not") {
				t.Errorf("hint = %q", hint)
			}
		})
	}
	// The same on a read tool.
	for _, body := range bodies {
		t.Run("read "+body, func(t *testing.T) {
			fx := newPresetFixture(t, presetFixtureOpts{override: map[string]func(http.ResponseWriter, string){
				"GetProfiles": func(w http.ResponseWriter, _ string) { plainReply(500, body)(w, nil) },
			}})
			cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx.srv)})
			res := call(t, cs, "media.profiles", map[string]any{"camera": "fx"})
			if code, _ := errCode(t, res); code != "internal" {
				t.Errorf("read path: code = %q, want internal: %s", code, wire(t, res))
			}
		})
	}
}
