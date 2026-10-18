package tools

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
)

func lastAudit(t *testing.T, a *auditBuf) map[string]any {
	t.Helper()
	recs := a.records(t)
	if len(recs) == 0 {
		t.Fatal("no audit record")
	}
	return recs[len(recs)-1]
}

func soapFault(w http.ResponseWriter, status int, sub, reason string) {
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, envelope, `<s:Fault><s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>`+sub+`</s:Value></s:Subcode></s:Code>`+
		`<s:Reason><s:Text xml:lang="en">`+reason+`</s:Text></s:Reason></s:Fault>`)
}

// A real call that fails before the move command is sent audits executed:false.
func TestAuditSaysNotExecutedWhenNothingWasSent(t *testing.T) {
	cases := map[string]struct {
		opts    presetFixtureOpts
		profile string
		preset  string
		code    string
	}{
		"unknown preset":  {profile: "prof", preset: "nope", code: "not_found"},
		"unknown profile": {profile: "nope", preset: "p1", code: "not_found"},
		"no PTZ":          {opts: presetFixtureOpts{noPTZConfig: true}, profile: "prof", preset: "p1", code: "not_supported"},
		"GetProfiles fault": {opts: presetFixtureOpts{override: map[string]func(http.ResponseWriter, string){
			"GetProfiles": func(w http.ResponseWriter, _ string) { soapFault(w, 500, "ter:Action", "boom") },
		}}, profile: "prof", preset: "p1", code: "device_fault"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fx := newPresetFixture(t, c.opts)
			cs := fx.rig(t, true)
			res := call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": c.profile, "preset": c.preset, "dry_run": false})
			if code, _ := errCode(t, res); code != c.code {
				t.Fatalf("code = %q: %s", code, wire(t, res))
			}
			if a := lastAudit(t, fx.audit); a["executed"] != false || a["dry_run"] != false {
				t.Errorf("audit = %v, want executed:false", a)
			}
			if fx.gotoCalls.Load() != 0 {
				t.Error("GotoPreset was sent")
			}
		})
	}
}

func TestAuditSaysNotExecutedWhenTheCameraIsUnreachable(t *testing.T) {
	audit := &auditBuf{}
	reg := registry.New(&config.Config{Cameras: map[string]*config.Camera{
		"dead": {ID: "dead", Endpoint: "http://127.0.0.1:1/onvif/device_service", Control: true, TimeoutSeconds: 1},
	}})
	policy := safety.NewPolicy(safety.PolicyOptions{ControlEnabled: true, Cameras: reg, Interval: time.Hour,
		Log: slog.New(slog.NewJSONHandler(audit, nil))})
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterPTZWrites(srv, Deps{Reg: reg, Log: quietLog(), Policy: policy})
	cs := connectTo(t, srv)
	res := call(t, cs, gotoTool, map[string]any{"camera": "dead", "profile": "p", "preset": "q", "dry_run": false})
	code, hint := errCode(t, res)
	if code != "unreachable" {
		t.Fatalf("code = %q: %s", code, wire(t, res))
	}
	// Nothing was sent, so this is retryable and carries no unknown-state hint.
	if errField(res, "retryable") != true || containsUnknown(hint) {
		t.Errorf("retryable=%v hint=%q", errField(res, "retryable"), hint)
	}
	if a := lastAudit(t, audit); a["executed"] != false {
		t.Errorf("audit = %v", a)
	}
}

func containsUnknown(s string) bool { return strings.Contains(s, "may or may not") }

// A real send that then fails audits executed:true.
func TestAuditSaysExecutedWhenTheCommandWasSentAndFailed(t *testing.T) {
	fx := newPresetFixture(t, presetFixtureOpts{gotoHandler: func(w http.ResponseWriter, _ *http.Request) {
		soapFault(w, 500, "ter:ActionNotSupported", "motor busy")
	}})
	cs := fx.rig(t, true)
	call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": "prof", "preset": "p1", "dry_run": false})
	if a := lastAudit(t, fx.audit); a["executed"] != true || a["outcome"] != "device_fault" {
		t.Errorf("audit = %v", a)
	}
}

// A cancel that lands during validation stops the call before the command is
// sent: nothing is sent, the error says so, and the audit says executed:false.
func TestPreSendCancellationSendsNothingAndAuditsNotExecuted(t *testing.T) {
	base, shutdown := context.WithCancel(context.Background())
	defer shutdown()
	fx := newPresetFixture(t, presetFixtureOpts{override: map[string]func(http.ResponseWriter, string){
		// The limits read is the last validation step; shut down as it is served.
		"GetConfiguration": func(w http.ResponseWriter, _ string) {
			shutdown()
			time.Sleep(50 * time.Millisecond)
			w.WriteHeader(500)
		},
	}})
	fx.base = base
	cs := fx.rig(t, true)
	res := call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": "prof", "preset": "p1", "dry_run": false})
	code, hint := errCode(t, res)
	if code != "internal" || !strings.Contains(wire(t, res), "before the move command was sent") {
		t.Fatalf("code=%q: %s", code, wire(t, res))
	}
	if containsUnknown(hint) || errField(res, "retryable") == nil {
		t.Errorf("hint=%q", hint)
	}
	if fx.gotoCalls.Load() != 0 {
		t.Error("GotoPreset was sent after cancellation")
	}
	if a := lastAudit(t, fx.audit); a["executed"] != false {
		t.Errorf("audit = %v", a)
	}
}

// A NoEntity fault from GetPresets is not_found and names the tool that lists
// the valid preset tokens.
func TestGetPresetsNoEntityFaultCarriesThePresetsHint(t *testing.T) {
	fx := newPresetFixture(t, presetFixtureOpts{override: map[string]func(http.ResponseWriter, string){
		"GetPresets": func(w http.ResponseWriter, _ string) { soapFault(w, 500, "ter:NoEntity", "no such profile") },
	}})
	cs := fx.rig(t, true)
	for _, dry := range []bool{true, false} {
		res := call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": "prof", "preset": "p1", "dry_run": dry})
		code, hint := errCode(t, res)
		if code != "not_found" || !strings.Contains(hint, "ptz.presets") {
			t.Errorf("dry=%v code=%q hint=%q", dry, code, hint)
		}
	}
}

// An unknown profile on a dry run is a clean not_found, not a nil dereference.
func TestGotoPresetDryRunUnknownProfileIsNotFound(t *testing.T) {
	fx := newPresetFixture(t, presetFixtureOpts{})
	cs := fx.rig(t, true)
	res := call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": "nope", "preset": "p1"})
	code, hint := errCode(t, res)
	if code != "not_found" || !strings.Contains(hint, "media.profiles") {
		t.Errorf("code=%q hint=%q: %s", code, hint, wire(t, res))
	}
	if fx.gotoCalls.Load() != 0 {
		t.Error("a dry run sent GotoPreset")
	}
}

// Failures before the send stay retryable and never claim an unknown state.
func TestGetProfilesFailureBeforeSendIsRetryableWithoutTheUnknownHint(t *testing.T) {
	fx := newPresetFixture(t, presetFixtureOpts{override: map[string]func(http.ResponseWriter, string){
		"GetProfiles": func(_ http.ResponseWriter, _ string) { time.Sleep(1500 * time.Millisecond) },
	}})
	cs := fx.rig(t, true) // 1s timeout
	res := call(t, cs, gotoTool, map[string]any{"camera": "fx", "profile": "prof", "preset": "p1", "dry_run": false})
	code, hint := errCode(t, res)
	if code != "timeout" || containsUnknown(hint) || errField(res, "retryable") != true {
		t.Errorf("code=%q hint=%q retryable=%v", code, hint, errField(res, "retryable"))
	}
	if fx.gotoCalls.Load() != 0 {
		t.Error("GotoPreset was sent")
	}
}
