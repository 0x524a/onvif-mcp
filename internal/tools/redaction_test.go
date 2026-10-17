package tools

import (
	"encoding/json"
	"strings"
	"testing"

	onvif "github.com/0x524a/onvif-go"
	"github.com/0x524a/onvif-go/discovery"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/mcperr"
)

// secretForms are the shapes a secret takes in device-supplied text: a
// registered password, a key=value pair, and URL userinfo.
func secretForms(t *testing.T) []string {
	t.Helper()
	registerLeakSecret(t)
	return []string{leakPW, "password=hunter2xyz", "http://admin:pwd4321@h/"}
}

// secretFragments are the substrings that must never survive.
var secretFragments = []string{leakPW, "hunter2xyz", "pwd4321"}

func assertClean(t *testing.T, what string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	for _, f := range secretFragments {
		if strings.Contains(string(b), f) {
			t.Errorf("%s leaks %q: %s", what, f, b)
		}
	}
}

// Each builder scrubs on its own, so a regression in the shared choke point
// cannot silently expose a field, and a regression in one builder is caught
// even though the choke point would mask it.
func TestBuildersScrubEveryDeviceString(t *testing.T) {
	for _, s := range secretForms(t) {
		st := statusOf(&onvif.PTZStatus{Error: "e " + s, MoveStatus: &onvif.PTZMoveStatus{PanTilt: "p " + s, Zoom: "z " + s}})
		assertClean(t, "statusOf", st)

		pr, _ := presetsOf([]*onvif.PTZPreset{{Token: "t " + s, Name: "n " + s}})
		assertClean(t, "presetsOf", pr)

		var d DescribeData
		identityOf(&d, &onvif.DeviceInformation{Manufacturer: "a " + s, Model: "b " + s, FirmwareVersion: "c " + s, SerialNumber: "d " + s, HardwareID: "e " + s})
		assertClean(t, "identityOf", d)

		list, _, _ := servicesOf([]*onvif.Service{{Namespace: "urn:x " + s}})
		assertClean(t, "servicesOf", list)

		assertClean(t, "scrubField", scrubField("v "+s))
		assertClean(t, "text", text("t "+s).Content)
		res, out, _ := fail[StatusData](mcperr.FromError(errString("boom "+s), "cam", "Op"))
		assertClean(t, "fail text", res.Content)
		assertClean(t, "fail envelope", out)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestDiscoverBuilderScrubsEveryAnnouncedField(t *testing.T) {
	for _, s := range secretForms(t) {
		got := candidatesFrom([]*discovery.Device{{
			EndpointRef: "urn:uuid: " + s,
			XAddrs:      []string{"http://192.0.2.9/" + leakPW + "/device_service"},
			Scopes:      []string{"name " + s, "onvif://y"},
		}})
		assertClean(t, "candidatesFrom", got.cands)
		if len(got.cands) != 1 {
			t.Fatalf("candidate dropped for %q", s)
		}
	}
}

// Wire-level: a secret planted in every string of every tool's reply is gone
// from everything the agent receives, text content and structured content
// alike, and the planted field demonstrably reached the output.
func TestEveryToolRedactsTextAndStructuredContent(t *testing.T) {
	forms := secretForms(t)
	for _, s := range forms {
		ns := strings.NewReplacer("&", "&amp;", "<", "&lt;").Replace(s)
		fx := fixtureWith(t, map[string]string{
			"GetDeviceInformation": `<tds:GetDeviceInformationResponse ` + tdsNS + `><tds:Manufacturer>` + ns + `</tds:Manufacturer><tds:Model>m ` + ns +
				`</tds:Model><tds:FirmwareVersion>f ` + ns + `</tds:FirmwareVersion><tds:SerialNumber>s ` + ns + `</tds:SerialNumber><tds:HardwareId>h ` + ns + `</tds:HardwareId></tds:GetDeviceInformationResponse>`,
			"GetServices": `<tds:GetServicesResponse ` + tdsNS + `><tds:Service><tds:Namespace>urn:` + ns + `</tds:Namespace><tds:XAddr>http://h/</tds:XAddr></tds:Service></tds:GetServicesResponse>`,
			"GetStatus": `<tptz:GetStatusResponse ` + ptzNS + `><tptz:PTZStatus><tt:MoveStatus><tt:PanTilt>` + ns + `</tt:PanTilt><tt:Zoom>` + ns +
				`</tt:Zoom></tt:MoveStatus><tt:Error>` + ns + `</tt:Error></tptz:PTZStatus></tptz:GetStatusResponse>`,
			"GetPresets": `<tptz:GetPresetsResponse ` + ptzNS + `><tptz:Preset token="` + strings.ReplaceAll(ns, `"`, "") + `"><tt:Name>` + ns + `</tt:Name></tptz:Preset></tptz:GetPresetsResponse>`,
			"GetProfiles": `<trt:GetProfilesResponse ` + trtNS + ` ` + ptzNS + `><trt:Profiles token="t ` + strings.ReplaceAll(ns, `"`, "") + `"><tt:Name>` + ns + `</tt:Name>` +
				`<tt:VideoSourceConfiguration token="v"><tt:SourceToken>` + ns + `</tt:SourceToken></tt:VideoSourceConfiguration>` +
				`<tt:VideoEncoderConfiguration token="e"><tt:Encoding>` + ns + `</tt:Encoding></tt:VideoEncoderConfiguration></trt:Profiles></trt:GetProfilesResponse>`,
			"GetStreamUri": `<trt:GetStreamUriResponse ` + trtNS + `><trt:MediaUri><tt:Uri>rtsp://` + ns + `@h:554/s</tt:Uri></trt:MediaUri></trt:GetStreamUriResponse>`,
		}, true)
		cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
		for tool, args := range map[string]map[string]any{
			"camera.describe":  {"camera": "fx"},
			"ptz.status":       {"camera": "fx", "profile": "p"},
			"ptz.presets":      {"camera": "fx", "profile": "p"},
			"media.profiles":   {"camera": "fx"},
			"media.stream_uri": {"camera": "fx", "profile": "p"},
		} {
			res := call(t, cs, tool, args)
			whole := wire(t, res)
			for _, f := range secretFragments {
				if strings.Contains(whole, f) {
					t.Errorf("%s (%q): leaked %q: %s", tool, s, f, whole)
				}
			}
			// The text on its own, since it is scrubbed independently of the
			// structured content.
			for _, c := range res.Content {
				b, _ := json.Marshal(c)
				for _, f := range secretFragments {
					if strings.Contains(string(b), f) {
						t.Errorf("%s: text content leaks %q: %s", tool, f, b)
					}
				}
			}
		}
	}
}

// A SOAP fault whose reason carries a secret must not reach the text or the
// structured error.
func TestErrorPathRedactsFaultReason(t *testing.T) {
	for _, s := range secretForms(t) {
		reason := strings.NewReplacer("&", "&amp;", "<", "&lt;").Replace("bad token " + s)
		// A camera answering every operation with a fault carrying the secret.
		faulty := faultFixture(t, reason)
		cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(faulty)})
		for tool, args := range map[string]map[string]any{
			"media.profiles":   {"camera": "fx"},
			"media.stream_uri": {"camera": "fx", "profile": "p"},
			"imaging.settings": {"camera": "fx", "source_token": "v"},
			"camera.describe":  {"camera": "fx"},
		} {
			res := call(t, cs, tool, args)
			if !res.IsError {
				t.Fatalf("%s: expected an error", tool)
			}
			whole := wire(t, res)
			for _, f := range secretFragments {
				if strings.Contains(whole, f) {
					t.Errorf("%s (%q): error leaks %q: %s", tool, s, f, whole)
				}
			}
			if !strings.Contains(whole, "bad token") {
				t.Errorf("%s: the fault never reached the output, test is vacuous: %s", tool, whole)
			}
		}
	}
}
