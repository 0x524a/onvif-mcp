package tools

import (
	"strings"
	"testing"

	"github.com/0x524a/onvif-mcp/internal/config"
)

func TestImagingSettingsFromTestcam(t *testing.T) {
	cs, cam := harness(t)
	res := call(t, cs, "imaging.settings", map[string]any{"camera": "cam-a", "source_token": cam.VideoSourceToken()})
	_ = dataMap(t, res)
}

func TestImagingWrongSourceTokenIsAnEnvelopeError(t *testing.T) {
	cs, _ := harness(t)
	res := call(t, cs, "imaging.settings", map[string]any{"camera": "cam-a", "source_token": "no-such-source"})
	if !res.IsError {
		t.Skipf("virtual camera accepts any source token: %s", wire(t, res))
	}
	code, hint := errCode(t, res)
	if code == "" {
		t.Fatalf("error without an envelope code: %s", wire(t, res))
	}
	if code == "not_found" && !strings.Contains(hint, "media.profiles") {
		t.Errorf("hint %q does not point to media.profiles", hint)
	}
}

func TestImagingToleratesUnreportedFields(t *testing.T) {
	fx := fixture(t, map[string]string{
		"GetImagingSettings": `<timg:GetImagingSettingsResponse xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl">` +
			`<timg:ImagingSettings><tt:Brightness xmlns:tt="http://www.onvif.org/ver10/schema">42</tt:Brightness></timg:ImagingSettings>` +
			`</timg:GetImagingSettingsResponse>`,
	})
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	res := call(t, cs, "imaging.settings", map[string]any{"camera": "fx", "source_token": "vs"})
	d := dataMap(t, res)
	if d["brightness"] != float64(42) {
		t.Errorf("brightness = %v", d["brightness"])
	}
	for _, k := range []string{"contrast", "color_saturation", "sharpness"} {
		if _, present := d[k]; present {
			t.Errorf("%s was invented: %v", k, d[k])
		}
	}
	if !strings.Contains(wire(t, res), "contrast not reported") {
		t.Errorf("text should say not reported: %s", wire(t, res))
	}
}
