package tools

import (
	"fmt"
	"strings"
	"testing"

	"github.com/0x524a/onvif-mcp/internal/config"
)

// srcProfilesXML builds n profiles with distinct source tokens VS1..VSn.
func srcProfilesXML(n int) string {
	var b strings.Builder
	b.WriteString(`<trt:GetProfilesResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema">`)
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, `<trt:Profiles token="prof%[1]d"><tt:Name>Profile %[1]d</tt:Name>`+
			`<tt:VideoSourceConfiguration token="vsc%[1]d"><tt:SourceToken>VS%[1]d</tt:SourceToken></tt:VideoSourceConfiguration>`+
			`<tt:VideoEncoderConfiguration token="e%[1]d"><tt:Encoding>H264</tt:Encoding>`+
			`<tt:Resolution><tt:Width>1920</tt:Width><tt:Height>1080</tt:Height></tt:Resolution></tt:VideoEncoderConfiguration>`+
			`</trt:Profiles>`, i)
	}
	b.WriteString(`</trt:GetProfilesResponse>`)
	return b.String()
}

// A client that surfaces only content[].text must still be able to chain
// media.profiles into imaging.settings, so the text carries the source token.
func TestProfilesTextCarriesVideoSourceToken(t *testing.T) {
	fx := fixture(t, map[string]string{"GetProfiles": srcProfilesXML(3)})
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	res := call(t, cs, "media.profiles", map[string]any{"camera": "fx"})
	txt := res.Content[0].(interface{ MarshalJSON() ([]byte, error) })
	b, _ := txt.MarshalJSON()
	for i := 1; i <= 3; i++ {
		if !strings.Contains(string(b), fmt.Sprintf("prof%d (H264 1920x1080, source=VS%d)", i, i)) {
			t.Errorf("text lacks profile %d with its source token: %s", i, b)
		}
	}
}

// When the text cannot hold every profile it says so, rather than cutting a
// token in half or ending in a bare ellipsis.
func TestProfilesTextSaysWhenItOmitsProfiles(t *testing.T) {
	fx := fixture(t, map[string]string{"GetProfiles": srcProfilesXML(40)})
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	res := call(t, cs, "media.profiles", map[string]any{"camera": "fx"})
	b, _ := res.Content[0].(interface{ MarshalJSON() ([]byte, error) }).MarshalJSON()
	txt := string(b)
	if !strings.Contains(txt, "more; see structured result)") {
		t.Errorf("text does not say profiles were omitted: %s", txt)
	}
	if strings.Contains(txt, "...") {
		t.Errorf("text ends in a bare cut: %s", txt)
	}
	if ps, _ := dataMap(t, res)["profiles"].([]any); len(ps) != 40 {
		t.Errorf("structured result lost profiles: %d", len(ps))
	}
}

// credentials_required asserted a fact the camera never reported, so it is gone.
func TestStreamURIDoesNotAssertCredentialsRequired(t *testing.T) {
	fx := fixture(t, map[string]string{
		"GetStreamUri": `<trt:GetStreamUriResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl"><trt:MediaUri>` +
			`<tt:Uri xmlns:tt="http://www.onvif.org/ver10/schema">rtsp://h/x</tt:Uri></trt:MediaUri></trt:GetStreamUriResponse>`,
	})
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	res := call(t, cs, "media.stream_uri", map[string]any{"camera": "fx", "profile": "p"})
	d := dataMap(t, res)
	if _, ok := d["credentials_required"]; ok {
		t.Errorf("credentials_required is back: %s", wire(t, res))
	}
	for _, k := range []string{"uri", "invalid_after_connect", "invalid_after_reboot"} {
		if _, ok := d[k]; !ok {
			t.Errorf("missing %s: %s", k, wire(t, res))
		}
	}
}

// A failure while connecting is reported against Initialize, not against the
// operation that was never reached, and the message is short.
func TestConnectFailureNamesInitializeAndIsShort(t *testing.T) {
	cs := harnessWith(t, map[string]*config.Camera{
		"dead": {ID: "dead", Endpoint: "http://127.0.0.1:1/onvif/device_service", Username: "u", Password: "pw", TimeoutSeconds: 2},
	})
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"media.profiles", map[string]any{"camera": "dead"}},
		{"ptz.status", map[string]any{"camera": "dead", "profile": "p"}},
		{"camera.describe", map[string]any{"camera": "dead"}},
	} {
		res := call(t, cs, tc.tool, tc.args)
		if !res.IsError {
			t.Fatalf("%s: expected error", tc.tool)
		}
		e := res.StructuredContent.(map[string]any)["error"].(map[string]any)
		if e["operation"] != "Initialize" {
			t.Errorf("%s: operation = %v", tc.tool, e["operation"])
		}
		msg, _ := e["message"].(string)
		if !strings.HasPrefix(msg, "Initialize failed: ") {
			t.Errorf("%s: message = %q", tc.tool, msg)
		}
		for _, noise := range []string{"failed to get capabilities", "GetCapabilities failed", "initialize dead"} {
			if strings.Contains(msg, noise) {
				t.Errorf("%s: message keeps wrapper %q: %q", tc.tool, noise, msg)
			}
		}
	}
}
