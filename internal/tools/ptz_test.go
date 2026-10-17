package tools

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0x524a/onvif-mcp/internal/config"
)

const ptzNS = `xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema"`

func TestPTZPresetsListsThePresetTheCameraHas(t *testing.T) {
	cs, cam := harness(t)
	out := call(t, cs, "ptz.presets", map[string]any{
		"camera": "cam-a", "profile": cam.ProfileToken(),
	})
	if out.IsError {
		t.Fatalf("ptz.presets errored: %s", wire(t, out))
	}
	b, _ := json.Marshal(out.StructuredContent)
	if !strings.Contains(string(b), cam.PresetToken()) {
		t.Errorf("preset %q missing from output: %s", cam.PresetToken(), b)
	}
	if len(out.Content) == 0 {
		t.Error("no text content")
	}
}

func TestPTZStatusFromTestcam(t *testing.T) {
	cs, cam := harness(t)
	out := call(t, cs, "ptz.status", map[string]any{"camera": "cam-a", "profile": cam.ProfileToken()})
	d := dataMap(t, out)
	if _, ok := d["pan"]; !ok {
		t.Errorf("testcam reports a position, pan missing: %s", wire(t, out))
	}
}

func TestPTZPresetsToleratesNilPositionsAndLimits(t *testing.T) {
	fx := fixtureWith(t, map[string]string{
		"GetPresets": `<tptz:GetPresetsResponse ` + ptzNS + `><tptz:Preset token="p1"><tt:Name>Door</tt:Name></tptz:Preset>` +
			`<tptz:Preset token="p2"><tt:Name>Gate</tt:Name><tptz:PTZPosition><tt:Zoom x="0.5"/></tptz:PTZPosition></tptz:Preset></tptz:GetPresetsResponse>`,
		"GetProfiles": `<trt:GetProfilesResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl" ` + ptzNS + `>` +
			`<trt:Profiles token="prof"><tt:Name>main</tt:Name><tt:PTZConfiguration token="c"><tt:Name>c</tt:Name></tt:PTZConfiguration></trt:Profiles></trt:GetProfilesResponse>`,
	}, true)
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	res := call(t, cs, "ptz.presets", map[string]any{"camera": "fx", "profile": "prof"})
	d := dataMap(t, res)
	ps, _ := d["presets"].([]any)
	if len(ps) != 2 {
		t.Fatalf("want 2 presets: %s", wire(t, res))
	}
	p1 := ps[0].(map[string]any)
	for _, k := range []string{"pan", "tilt", "zoom"} {
		if _, ok := p1[k]; ok {
			t.Errorf("preset with no position must not invent %q: %v", k, p1)
		}
	}
	p2 := ps[1].(map[string]any)
	if _, ok := p2["pan"]; ok {
		t.Errorf("pan was not reported: %v", p2)
	}
	if z, _ := p2["zoom"].(float64); z != 0.5 {
		t.Errorf("zoom = %v, want 0.5", p2["zoom"])
	}
	if _, ok := d["reported_limits"]; ok {
		t.Errorf("no limits were reported: %s", wire(t, res))
	}
	if !strings.Contains(wire(t, res), "not reported") {
		t.Errorf("text should say not reported: %s", wire(t, res))
	}
}

func TestPTZPresetsReportsLimitsOnlyWhenPresent(t *testing.T) {
	fx := fixtureWith(t, map[string]string{
		"GetPresets": `<tptz:GetPresetsResponse ` + ptzNS + `/>`,
		"GetProfiles": `<trt:GetProfilesResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl" ` + ptzNS + `>` +
			`<trt:Profiles token="prof"><tt:Name>main</tt:Name><tt:PTZConfiguration token="c"><tt:Name>c</tt:Name>` +
			`</tt:PTZConfiguration></trt:Profiles></trt:GetProfilesResponse>`,
		"GetConfiguration": `<tptz:GetConfigurationResponse ` + ptzNS + `><tptz:PTZConfiguration token="c"><tt:Name>c</tt:Name>` +
			`<tt:PanTiltLimits><tt:Range><tt:URI>u</tt:URI><tt:XRange><tt:Min>-1</tt:Min><tt:Max>1</tt:Max></tt:XRange>` +
			`<tt:YRange><tt:Min>-0.5</tt:Min><tt:Max>0.5</tt:Max></tt:YRange></tt:Range></tt:PanTiltLimits>` +
			`</tptz:PTZConfiguration></tptz:GetConfigurationResponse>`,
	}, true)
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	d := dataMap(t, call(t, cs, "ptz.presets", map[string]any{"camera": "fx", "profile": "prof"}))
	l, ok := d["reported_limits"].(map[string]any)
	if !ok {
		t.Fatalf("limits missing: %v", d)
	}
	if _, ok := l["pan"]; !ok {
		t.Errorf("pan limits missing: %v", l)
	}
	if _, ok := l["zoom"]; ok {
		t.Errorf("zoom limits were not reported and must be absent, got %v", l["zoom"])
	}
	if ps, _ := d["presets"].([]any); ps == nil || len(ps) != 0 {
		t.Errorf("presets must be an empty list, got %v", d["presets"])
	}
}

func TestPTZStatusToleratesNilPosition(t *testing.T) {
	fx := fixtureWith(t, map[string]string{
		"GetStatus": `<tptz:GetStatusResponse ` + ptzNS + `><tptz:PTZStatus>` +
			`<tt:MoveStatus><tt:PanTilt>IDLE</tt:PanTilt></tt:MoveStatus></tptz:PTZStatus></tptz:GetStatusResponse>`,
	}, true)
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	res := call(t, cs, "ptz.status", map[string]any{"camera": "fx", "profile": "prof"})
	d := dataMap(t, res)
	for _, k := range []string{"pan", "tilt", "zoom"} {
		if _, ok := d[k]; ok {
			t.Errorf("status with no position must not invent %q: %v", k, d)
		}
	}
	if d["pan_tilt_state"] != "IDLE" {
		t.Errorf("move status lost: %v", d)
	}
	if !strings.Contains(wire(t, res), "position not reported") {
		t.Errorf("text should say position not reported: %s", wire(t, res))
	}
}

func TestPTZStatusWithNoMoveStatusAtAll(t *testing.T) {
	fx := fixtureWith(t, map[string]string{
		"GetStatus": `<tptz:GetStatusResponse ` + ptzNS + `><tptz:PTZStatus/></tptz:GetStatusResponse>`,
	}, true)
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	res := call(t, cs, "ptz.status", map[string]any{"camera": "fx", "profile": "prof"})
	if res.IsError {
		t.Fatalf("empty status must not be an error: %s", wire(t, res))
	}
}

func TestPTZReadsWithoutPTZServiceAreNotSupported(t *testing.T) {
	fx := fixture(t, nil) // no PTZ service advertised
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	for _, tool := range []string{"ptz.status", "ptz.presets"} {
		res := call(t, cs, tool, map[string]any{"camera": "fx", "profile": "prof"})
		if !res.IsError {
			t.Fatalf("%s: expected an error: %s", tool, wire(t, res))
		}
		if code, _ := errCode(t, res); code != "not_supported" {
			t.Errorf("%s: code = %q, want not_supported: %s", tool, code, wire(t, res))
		}
	}
}

func TestDescribeLabelsCapabilitiesAsAdvertised(t *testing.T) {
	cs, _ := harness(t)
	out := call(t, cs, "camera.describe", map[string]any{"camera": "cam-a"})
	if out.IsError {
		t.Fatalf("camera.describe errored: %s", wire(t, out))
	}
	b, _ := json.Marshal(out.StructuredContent)
	// The field name itself carries the caveat, so an agent cannot read the
	// list as verified fact.
	if !strings.Contains(string(b), "advertised") {
		t.Errorf("capabilities must be labelled advertised: %s", b)
	}
	d := dataMap(t, out)
	if d["capabilities_verified"] != false {
		t.Errorf("capabilities_verified must be false: %v", d)
	}
}

func TestDescribeToleratesRefusedServiceList(t *testing.T) {
	fx := fixture(t, map[string]string{
		"GetDeviceInformation": `<tds:GetDeviceInformationResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl">` +
			`<tds:Manufacturer>Acme</tds:Manufacturer><tds:Model>M1</tds:Model></tds:GetDeviceInformationResponse>`,
	}) // GetServices answers 500
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	res := call(t, cs, "camera.describe", map[string]any{"camera": "fx"})
	d := dataMap(t, res)
	if d["model"] != "M1" {
		t.Errorf("identity lost: %v", d)
	}
	if !strings.Contains(wire(t, res), "not reported") {
		t.Errorf("a refused service list must read as not reported: %s", wire(t, res))
	}
}
