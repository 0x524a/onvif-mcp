package tools

import (
	"fmt"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
)

func textOf(res *mcp.CallToolResult) string {
	if len(res.Content) == 0 {
		return ""
	}
	tc, _ := res.Content[0].(*mcp.TextContent)
	if tc == nil {
		return ""
	}
	return tc.Text
}

func profilesXML(n int, tokenOf func(i int) string) string {
	var b strings.Builder
	b.WriteString(`<trt:GetProfilesResponse ` + trtNS + ` ` + ptzNS + `>`)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, `<trt:Profiles token="%s"><tt:Name>n%d</tt:Name><tt:VideoSourceConfiguration token="v"><tt:Name>v</tt:Name><tt:SourceToken>VS%d</tt:SourceToken></tt:VideoSourceConfiguration></trt:Profiles>`, tokenOf(i), i, i)
	}
	b.WriteString(`</trt:GetProfilesResponse>`)
	return b.String()
}

func TestProfilesAreCappedWithATruncationSignal(t *testing.T) {
	fx := fixture(t, map[string]string{"GetProfiles": profilesXML(150, func(i int) string { return fmt.Sprintf("p%03d", i) })})
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	res := call(t, cs, "media.profiles", map[string]any{"camera": "fx"})
	d := dataMap(t, res)
	if n := len(d["profiles"].([]any)); n != 100 {
		t.Errorf("profiles = %d, want 100", n)
	}
	if d["truncated"] != true || d["total"] != float64(150) {
		t.Errorf("truncated=%v total=%v, want true/150", d["truncated"], d["total"])
	}
	if !strings.Contains(textOf(res), "more") {
		t.Errorf("text must say there is more: %s", wire(t, res))
	}
}

func TestProfilesUnderTheCapAreNotTruncated(t *testing.T) {
	fx := fixture(t, map[string]string{"GetProfiles": profilesXML(3, func(i int) string { return fmt.Sprintf("p%d", i) })})
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	d := dataMap(t, call(t, cs, "media.profiles", map[string]any{"camera": "fx"}))
	if d["truncated"] != false || d["total"] != float64(3) {
		t.Errorf("truncated=%v total=%v, want false/3", d["truncated"], d["total"])
	}
	if _, ok := d["duplicates_dropped"]; ok {
		t.Error("no duplicates, field must be absent")
	}
}

func TestDuplicateProfileTokensAreDedupedKeepingTheFirst(t *testing.T) {
	fx := fixture(t, map[string]string{"GetProfiles": profilesXML(3, func(i int) string {
		if i == 2 {
			return "p0"
		}
		return fmt.Sprintf("p%d", i)
	})})
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	res := call(t, cs, "media.profiles", map[string]any{"camera": "fx"})
	d := dataMap(t, res)
	ps := d["profiles"].([]any)
	if len(ps) != 2 {
		t.Fatalf("want 2 profiles, got %s", wire(t, res))
	}
	if ps[0].(map[string]any)["name"] != "n0" {
		t.Errorf("the first duplicate must win: %v", ps[0])
	}
	if d["duplicates_dropped"] != float64(1) || d["total"] != float64(2) {
		t.Errorf("duplicates_dropped=%v total=%v", d["duplicates_dropped"], d["total"])
	}
}

func TestProfileTextCarriesTheSourceTokenForChaining(t *testing.T) {
	fx := fixture(t, map[string]string{"GetProfiles": profilesXML(2, func(i int) string { return fmt.Sprintf("p%d", i) })})
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	res := call(t, cs, "media.profiles", map[string]any{"camera": "fx"})
	if txt := textOf(res); !strings.Contains(txt, "VS0") || !strings.Contains(txt, "VS1") {
		t.Errorf("text must carry video_source_token so text-only clients can chain: %q", txt)
	}
}

func TestPresetsAreCappedAndDeduped(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<tptz:GetPresetsResponse ` + ptzNS + `>`)
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&b, `<tptz:Preset token="t%03d"><tt:Name>n%d</tt:Name></tptz:Preset>`, i, i)
	}
	b.WriteString(`<tptz:Preset token="t000"><tt:Name>dup</tt:Name></tptz:Preset></tptz:GetPresetsResponse>`)
	fx := fixtureWith(t, map[string]string{"GetPresets": b.String()}, true)
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	d := dataMap(t, call(t, cs, "ptz.presets", map[string]any{"camera": "fx", "profile": "prof"}))
	ps := d["presets"].([]any)
	if len(ps) != 256 {
		t.Errorf("presets = %d, want 256", len(ps))
	}
	if ps[0].(map[string]any)["name"] != "n0" {
		t.Errorf("first duplicate must win: %v", ps[0])
	}
	if d["truncated"] != true || d["total"] != float64(300) || d["duplicates_dropped"] != float64(1) {
		t.Errorf("truncated=%v total=%v dup=%v", d["truncated"], d["total"], d["duplicates_dropped"])
	}
}

func TestFindProfileKeepsTheFirstOfDuplicateTokens(t *testing.T) {
	// ptz.presets takes limits from the profile findProfile returns; with a
	// duplicate token that must be the first, matching media.profiles.
	fx := fixtureWith(t, map[string]string{
		"GetPresets": `<tptz:GetPresetsResponse ` + ptzNS + `/>`,
		"GetProfiles": `<trt:GetProfilesResponse ` + trtNS + ` ` + ptzNS + `>` +
			`<trt:Profiles token="dup"><tt:Name>one</tt:Name><tt:PTZConfiguration token="c1"><tt:Name>c</tt:Name></tt:PTZConfiguration></trt:Profiles>` +
			`<trt:Profiles token="dup"><tt:Name>two</tt:Name></trt:Profiles></trt:GetProfilesResponse>`,
		"GetConfiguration": `<tptz:GetConfigurationResponse ` + ptzNS + `><tptz:PTZConfiguration token="c1"><tt:Name>c</tt:Name>` +
			`<tt:ZoomLimits><tt:Range><tt:URI>u</tt:URI><tt:XRange><tt:Min>0</tt:Min><tt:Max>1</tt:Max></tt:XRange></tt:Range></tt:ZoomLimits>` +
			`</tptz:PTZConfiguration></tptz:GetConfigurationResponse>`,
	}, true)
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	d := dataMap(t, call(t, cs, "ptz.presets", map[string]any{"camera": "fx", "profile": "dup"}))
	if _, ok := d["reported_limits"]; !ok {
		t.Errorf("limits must come from the first matching profile: %v", d)
	}
}

func TestDescribeServicesAreCapped(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<tds:GetServicesResponse ` + tdsNS + `>`)
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&b, `<tds:Service><tds:Namespace>http://ns/%03d</tds:Namespace><tds:XAddr>http://h/</tds:XAddr></tds:Service>`, i)
	}
	b.WriteString(`</tds:GetServicesResponse>`)
	fx := fixture(t, map[string]string{
		"GetDeviceInformation": `<tds:GetDeviceInformationResponse ` + tdsNS + `><tds:Manufacturer>A</tds:Manufacturer></tds:GetDeviceInformationResponse>`,
		"GetServices":          b.String(),
	})
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	d := dataMap(t, call(t, cs, "camera.describe", map[string]any{"camera": "fx"}))
	if n := len(d["advertised_services"].([]any)); n != 64 {
		t.Errorf("services = %d, want 64", n)
	}
	if d["truncated"] != true || d["total"] != float64(100) {
		t.Errorf("truncated=%v total=%v", d["truncated"], d["total"])
	}
}

func TestStreamURIDropsFragmentAndBoundsLength(t *testing.T) {
	long := "rtsp://h/" + strings.Repeat("a", 3000)
	fx := fixture(t, map[string]string{
		"GetStreamUri": `<trt:GetStreamUriResponse ` + trtNS + `><trt:MediaUri><tt:Uri>rtsp://h:554/s?x=1#SECRETFRAG</tt:Uri></trt:MediaUri></trt:GetStreamUriResponse>`,
	})
	cs := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx)})
	res := call(t, cs, "media.stream_uri", map[string]any{"camera": "fx", "profile": "p"})
	d := dataMap(t, res)
	if w := wire(t, res); strings.Contains(w, "SECRETFRAG") || strings.Contains(w, "#") {
		t.Errorf("fragment survived: %s", w)
	}
	if d["uri"] != "rtsp://h:554/s?x=1" {
		t.Errorf("uri = %v", d["uri"])
	}

	fx2 := fixture(t, map[string]string{
		"GetStreamUri": `<trt:GetStreamUriResponse ` + trtNS + `><trt:MediaUri><tt:Uri>` + long + `</tt:Uri></trt:MediaUri></trt:GetStreamUriResponse>`,
	})
	cs2 := harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(fx2)})
	res2 := call(t, cs2, "media.stream_uri", map[string]any{"camera": "fx", "profile": "p"})
	if code, _ := errCode(t, res2); code != "device_fault" {
		t.Errorf("an oversized URI must be a device_fault: %s", wire(t, res2))
	}
	if strings.Contains(wire(t, res2), strings.Repeat("a", 100)) {
		t.Error("the oversized URI was echoed")
	}
}
