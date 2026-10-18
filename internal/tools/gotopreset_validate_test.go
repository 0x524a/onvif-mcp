package tools

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
)

// The input schema requires non-empty tokens, so an agent sees the rule up front.
func TestGotoPresetSchemaRequiresNonEmptyTokens(t *testing.T) {
	r := newPresetRig(t, true)
	res, err := r.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range res.Tools {
		if x.Name != gotoTool {
			continue
		}
		b := wireOf(t, x.InputSchema)
		if n := strings.Count(b, `"minLength":1`); n < 2 {
			t.Errorf("want minLength 1 on profile and preset, found %d in %s", n, b)
		}
		return
	}
	t.Fatal("tool not listed")
}

func TestGotoPresetEmptyTokensAreRefusedAndNothingIsSent(t *testing.T) {
	fx := newPresetFixture(t, presetFixtureOpts{})
	cs := fx.rig(t, true)
	for _, args := range []map[string]any{
		{"camera": "fx", "profile": "", "preset": "p1", "dry_run": false},
		{"camera": "fx", "profile": "prof", "preset": "", "dry_run": false},
	} {
		if res := call(t, cs, gotoTool, args); !res.IsError {
			t.Errorf("%v: expected an error", args)
		}
	}
	if fx.gotoCalls.Load() != 0 {
		t.Error("GotoPreset was sent for an empty token")
	}
}

// Past the schema, the handler itself refuses an empty token, before any request.
func TestGotoPresetHandlerRefusesEmptyTokensWithAHint(t *testing.T) {
	fx := newPresetFixture(t, presetFixtureOpts{})
	d := fx.deps(t)
	for _, in := range []GotoPresetIn{{Profile: "", Preset: "p1"}, {Profile: "prof", Preset: ""}} {
		in.Camera = "fx"
		_, out, _ := gotoPresetRun(d)(context.Background(), nil, in)
		te := out.Error
		if te == nil || te.Code != mcperr.CodeInvalidArgument || !te.NotSent || te.Hint == "" {
			t.Errorf("%+v: error = %+v", in, te)
		}
	}
	if fx.gotoCalls.Load() != 0 {
		t.Error("GotoPreset was sent")
	}
}

const dupDifferent = `<tptz:Preset token="p1"><tt:Name>A</tt:Name><tt:PTZPosition><tt:PanTilt x="0.1" y="0.1"/></tt:PTZPosition></tptz:Preset>` +
	`<tptz:Preset token="p1"><tt:Name>B</tt:Name><tt:PTZPosition><tt:PanTilt x="0.9" y="0.9"/></tt:PTZPosition></tptz:Preset>`

const dupSame = `<tptz:Preset token="p1"><tt:Name>A</tt:Name><tt:PTZPosition><tt:PanTilt x="0.1" y="0.1"/></tt:PTZPosition></tptz:Preset>` +
	`<tptz:Preset token="p1"><tt:Name>A</tt:Name><tt:PTZPosition><tt:PanTilt x="0.1" y="0.1"/></tt:PTZPosition></tptz:Preset>`

func TestGotoPresetDuplicateTokenWithDifferentPositionsIsNeverMoved(t *testing.T) {
	fx := newPresetFixture(t, presetFixtureOpts{presets: dupDifferent})
	cs := fx.rig(t, true)
	for _, dry := range []bool{true, false} {
		res := call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": "prof", "preset": "p1", "dry_run": dry})
		code, _ := errCode(t, res)
		if code != "device_fault" || !strings.Contains(wire(t, res),
			"camera lists this preset token more than once with different positions; it will not be moved") {
			t.Errorf("dry=%v code=%q: %s", dry, code, wire(t, res))
		}
		if errField(res, "retryable") != false {
			t.Errorf("dry=%v retryable = %v: the camera table must change first", dry, errField(res, "retryable"))
		}
	}
	if fx.gotoCalls.Load() != 0 {
		t.Error("GotoPreset was sent for an ambiguous preset")
	}
	if a := lastAudit(t, fx.audit); a["executed"] != false {
		t.Errorf("audit = %v", a)
	}
}

func TestGotoPresetDuplicateTokenWithTheSamePositionMovesAndSaysSo(t *testing.T) {
	fx := newPresetFixture(t, presetFixtureOpts{presets: dupSame})
	cs := fx.rig(t, true)
	dry := dataMap(t, call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": "prof", "preset": "p1"}))
	if n, _ := dry["note"].(string); !strings.Contains(n, "more than once") {
		t.Errorf("dry-run note lacks the duplicate remark: %q", n)
	}
	sent := dataMap(t, call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": "prof", "preset": "p1", "dry_run": false}))
	if n, _ := sent["note"].(string); !strings.Contains(n, "more than once") {
		t.Errorf("note lacks the duplicate remark: %q", n)
	}
	if fx.gotoCalls.Load() != 1 {
		t.Errorf("GotoPreset sent %d times", fx.gotoCalls.Load())
	}
}

// Every validation stage answers inside the per-request timeout, but together
// they outlast twice that budget: the call must stop before sending, with a
// retryable timeout and no unknown-state claim.
func TestGotoPresetWholeCallDeadlineStopsSlowValidationBeforeTheSend(t *testing.T) {
	fx := newPresetFixture(t, presetFixtureOpts{slowReads: 700 * time.Millisecond})
	cs := fx.rig(t, true) // timeout_seconds 1, so the whole call may take about 2s
	for _, dry := range []bool{false, true} {
		start := time.Now()
		res := call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": "prof", "preset": "p1", "dry_run": dry})
		code, hint := errCode(t, res)
		if code != "timeout" || containsUnknown(hint) || errField(res, "retryable") != true {
			t.Errorf("dry=%v code=%q hint=%q retryable=%v: %s", dry, code, hint, errField(res, "retryable"), wire(t, res))
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("dry=%v took %v, want about 2s", dry, d)
		}
		if !dry {
			if a := lastAudit(t, fx.audit); a["executed"] != false {
				t.Errorf("audit = %v", a)
			}
		}
	}
	if fx.gotoCalls.Load() != 0 {
		t.Error("GotoPreset was sent after the deadline")
	}
}

// The success note must not overstate: onvif-go does not parse the reply, so
// HTTP success is all that is known.
func TestGotoPresetSuccessNoteSaysHTTPSuccessAndPointsAtStatus(t *testing.T) {
	fx := newPresetFixture(t, presetFixtureOpts{})
	cs := fx.rig(t, true)
	d := dataMap(t, call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": "prof", "preset": "p1", "dry_run": false}))
	n, _ := d["note"].(string)
	if !strings.Contains(n, "HTTP success") || !strings.Contains(n, "ptz.status") || strings.Contains(n, "accepted the move") {
		t.Errorf("note = %q", n)
	}
}

// Each axis counts: presets that differ in only one of pan, tilt or zoom are
// still ambiguous.
func TestGotoPresetDuplicateTokenDifferingInOneAxisIsRefused(t *testing.T) {
	pos := func(x, y, z string) string {
		return `<tptz:Preset token="p1"><tt:Name>A</tt:Name><tt:PTZPosition><tt:PanTilt x="` + x + `" y="` + y +
			`"/><tt:Zoom x="` + z + `"/></tt:PTZPosition></tptz:Preset>`
	}
	for name, presets := range map[string]string{
		"pan":  pos("0.1", "0.2", "0.3") + pos("0.9", "0.2", "0.3"),
		"tilt": pos("0.1", "0.2", "0.3") + pos("0.1", "0.9", "0.3"),
		"zoom": pos("0.1", "0.2", "0.3") + pos("0.1", "0.2", "0.9"),
	} {
		t.Run(name, func(t *testing.T) {
			fx := newPresetFixture(t, presetFixtureOpts{presets: presets})
			cs := fx.rig(t, true)
			res := call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": "prof", "preset": "p1", "dry_run": false})
			if code, _ := errCode(t, res); code != "device_fault" {
				t.Errorf("code = %q: %s", code, wire(t, res))
			}
			if fx.gotoCalls.Load() != 0 {
				t.Error("GotoPreset was sent")
			}
		})
	}
}
