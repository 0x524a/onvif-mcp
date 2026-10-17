package tools

import (
	"strings"
	"testing"

	"github.com/0x524a/onvif-mcp/internal/config"
)

func TestProfilesListsAtLeastOne(t *testing.T) {
	cs, cam := harness(t)
	res := call(t, cs, "media.profiles", map[string]any{"camera": "cam-a"})
	d := dataMap(t, res)
	ps, _ := d["profiles"].([]any)
	if len(ps) == 0 {
		t.Fatalf("no profiles: %s", wire(t, res))
	}
	if !strings.Contains(wire(t, res), cam.ProfileToken()) {
		t.Errorf("profile %q missing: %s", cam.ProfileToken(), wire(t, res))
	}
}

func TestStreamURIFromTestcamIsRedacted(t *testing.T) {
	cs, cam := harness(t)
	res := call(t, cs, "media.stream_uri", map[string]any{"camera": "cam-a", "profile": cam.ProfileToken()})
	d := dataMap(t, res)
	if uri, _ := d["uri"].(string); !strings.HasPrefix(uri, "rtsp") {
		t.Errorf("want an rtsp uri, got %q", uri)
	}
	if w := wire(t, res); strings.Contains(w, cam.Password()) {
		t.Errorf("leaked the camera password: %s", w)
	}
}

func TestStreamURIWithEmbeddedCredentialsIsRedactedEverywhere(t *testing.T) {
	fx := fixture(t, map[string]string{
		"GetStreamUri": `<trt:GetStreamUriResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl"><trt:MediaUri>` +
			`<tt:Uri xmlns:tt="http://www.onvif.org/ver10/schema">rtsp://u:p@h/x?token=qsecret</tt:Uri>` +
			`</trt:MediaUri></trt:GetStreamUriResponse>`,
	})
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	res := call(t, cs, "media.stream_uri", map[string]any{"camera": "fx", "profile": "p1"})
	d := dataMap(t, res)
	w := wire(t, res)
	for _, secret := range []string{"u:p@", ":p@", "qsecret"} {
		if strings.Contains(w, secret) {
			t.Errorf("result contains %q: %s", secret, w)
		}
	}
	if uri, _ := d["uri"].(string); !strings.Contains(uri, "rtsp://h/x") {
		t.Errorf("host and path lost: %q", uri)
	}
	if len(res.Content) == 0 {
		t.Fatal("no text content")
	}
}

func TestStreamURIWrongProfileIsNotFoundWithHint(t *testing.T) {
	cs, _ := harness(t)
	res := call(t, cs, "media.stream_uri", map[string]any{"camera": "cam-a", "profile": "no-such-profile"})
	if !res.IsError {
		t.Fatalf("expected an error: %s", wire(t, res))
	}
	code, hint := errCode(t, res)
	if code != "not_found" {
		t.Errorf("code = %q, want not_found: %s", code, wire(t, res))
	}
	if !strings.Contains(hint, "media.profiles") {
		t.Errorf("hint %q does not point to media.profiles", hint)
	}
}

func TestUnknownCameraIsNotFoundWithHint(t *testing.T) {
	cs, _ := harness(t)
	cases := map[string]map[string]any{
		"media.profiles":   {"camera": "ghost"},
		"media.stream_uri": {"camera": "ghost", "profile": "p"},
		"imaging.settings": {"camera": "ghost", "source_token": "s"},
	}
	for tool, args := range cases {
		res := call(t, cs, tool, args)
		if !res.IsError {
			t.Fatalf("%s: expected an error", tool)
		}
		code, hint := errCode(t, res)
		if code != "not_found" {
			t.Errorf("%s: code = %q, want not_found", tool, code)
		}
		if !strings.Contains(hint, "camera.list") {
			t.Errorf("%s: hint %q does not point to camera.list", tool, hint)
		}
		if len(res.Content) == 0 {
			t.Errorf("%s: no text content on error", tool)
		}
	}
}

func TestProfilesToleratesMissingEncoderAndResolution(t *testing.T) {
	fx := fixture(t, map[string]string{
		"GetProfiles": `<trt:GetProfilesResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl">` +
			`<trt:Profiles token="bare"><tt:Name xmlns:tt="http://www.onvif.org/ver10/schema">Bare</tt:Name></trt:Profiles>` +
			`<trt:Profiles token="half"><tt:Name xmlns:tt="http://www.onvif.org/ver10/schema">Half</tt:Name>` +
			`<tt:VideoEncoderConfiguration xmlns:tt="http://www.onvif.org/ver10/schema" token="e"><tt:Encoding>H264</tt:Encoding></tt:VideoEncoderConfiguration>` +
			`</trt:Profiles></trt:GetProfilesResponse>`,
	})
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	res := call(t, cs, "media.profiles", map[string]any{"camera": "fx"})
	d := dataMap(t, res)
	ps, _ := d["profiles"].([]any)
	if len(ps) != 2 {
		t.Fatalf("want 2 profiles: %s", wire(t, res))
	}
	for _, p := range ps {
		m := p.(map[string]any)
		for _, k := range []string{"width", "height", "framerate", "video_source_token"} {
			if _, present := m[k]; present {
				t.Errorf("%v: %s was invented: %v", m["token"], k, m[k])
			}
		}
		if m["has_ptz"] != false {
			t.Errorf("has_ptz = %v, want false", m["has_ptz"])
		}
	}
	if txt := res.Content[0]; !strings.Contains(wire(t, res), "not reported") {
		t.Errorf("text should say not reported: %v", txt)
	}
}

func TestProfilesEmptyListIsNotAnError(t *testing.T) {
	fx := fixture(t, map[string]string{
		"GetProfiles": `<trt:GetProfilesResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl"></trt:GetProfilesResponse>`,
	})
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	res := call(t, cs, "media.profiles", map[string]any{"camera": "fx"})
	d := dataMap(t, res)
	if ps, ok := d["profiles"].([]any); !ok || len(ps) != 0 {
		t.Errorf("want an empty profiles array: %s", wire(t, res))
	}
}

func TestStreamURIEmptyIsDeviceFault(t *testing.T) {
	fx := fixture(t, map[string]string{
		"GetStreamUri": `<trt:GetStreamUriResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl"><trt:MediaUri/></trt:GetStreamUriResponse>`,
	})
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	res := call(t, cs, "media.stream_uri", map[string]any{"camera": "fx", "profile": "p"})
	if code, _ := errCode(t, res); code != "device_fault" || !res.IsError {
		t.Errorf("want device_fault error: %s", wire(t, res))
	}
}
