package tools

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"

	onvif "github.com/0x524a/onvif-go"
	"github.com/0x524a/onvif-go/discovery"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
)

func TestClipBoundaryIsExact(t *testing.T) {
	if got := clip(strings.Repeat("a", maxTextChars+1)); len(got) != maxTextChars+3 || !strings.HasSuffix(got, "...") {
		t.Errorf("one byte over the limit must be clipped, got len %d", len(got))
	}
}

func TestScrubFieldTrimsScrubsAndClips(t *testing.T) {
	if got := scrubField(strings.Repeat("a", 700)); len(got) > maxTextChars+3 {
		t.Errorf("not clipped: %d", len(got))
	}
	if got := scrubField("  x  "); got != "x" {
		t.Errorf("not trimmed: %q", got)
	}
}

// fail builds its text through the scrubbing path itself, so a ToolError that
// somehow carries a secret still cannot reach the text.
func TestFailTextCarriesCodeMessageHintAndIsScrubbed(t *testing.T) {
	registerLeakSecret(t)
	res, _, _ := fail[StatusData](&mcperr.ToolError{Code: mcperr.CodeNotFound, Message: "no thing " + leakPW, Hint: "try " + leakPW})
	txt := textOf(res)
	if strings.Contains(txt, leakPW) {
		t.Errorf("secret in text: %q", txt)
	}
	if !strings.HasPrefix(txt, "not_found: no thing ") || !strings.Contains(txt, "(try ") {
		t.Errorf("text = %q", txt)
	}
	if !res.IsError {
		t.Error("IsError must be set")
	}
	noHint, _, _ := fail[StatusData](&mcperr.ToolError{Code: mcperr.CodeTimeout, Message: "slow"})
	if textOf(noHint) != "timeout: slow" {
		t.Errorf("text = %q", textOf(noHint))
	}
}

func TestJoinWithinCountsTheSeparatorAgainstTheBudget(t *testing.T) {
	// "aaaa; bbbb" is 10 bytes; with a budget of 9 only the first fits.
	if got := joinWithin([]string{"aaaa", "bbbb", "cccc"}, "; ", 9, 3); got != "aaaa; (+2 more; see structured result)" {
		t.Errorf("got %q", got)
	}
}

func TestCleanStringBoundsHowMuchItExamines(t *testing.T) {
	got := cleanString(strings.Repeat("a", scrubInputBytes+500), 0)
	if len(got) != scrubInputBytes {
		t.Errorf("examined %d bytes, want the bound %d", len(got), scrubInputBytes)
	}
}

func TestSummarizeProfilesWording(t *testing.T) {
	for name, tc := range map[string]struct {
		d    ProfilesData
		want string
	}{
		"empty": {ProfilesData{}, "The camera reported no media profiles."},
		"full": {ProfilesData{Total: 1, Profiles: []ProfileSummary{{Token: "a", Encoding: "H264", Width: 640, Height: 480, HasPTZ: true, SourceToken: "VS1"}}},
			"1 profile(s): a (H264 640x480, PTZ, source=VS1)."},
		"no resolution": {ProfilesData{Total: 1, Profiles: []ProfileSummary{{Token: "a", Encoding: "H264"}}},
			"1 profile(s): a (H264, resolution not reported)."},
		"width only": {ProfilesData{Total: 1, Profiles: []ProfileSummary{{Token: "a", Encoding: "H264", Width: 640}}},
			"1 profile(s): a (H264, resolution not reported)."},
		"height only": {ProfilesData{Total: 1, Profiles: []ProfileSummary{{Token: "a", Encoding: "H264", Height: 480}}},
			"1 profile(s): a (H264, resolution not reported)."},
		"no encoding": {ProfilesData{Total: 1, Profiles: []ProfileSummary{{Token: "a"}}},
			"1 profile(s): a (video encoding not reported)."},
		"capped list": {ProfilesData{Total: 150, Truncated: true, Profiles: []ProfileSummary{{Token: "a", Encoding: "H264", Width: 1, Height: 1}, {Token: "b", Encoding: "H264", Width: 1, Height: 1}}},
			"150 profile(s): a (H264 1x1); b (H264 1x1); (+148 more; see structured result)."},
	} {
		if got := summarizeProfiles(tc.d); got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", name, got, tc.want)
		}
	}
}

func TestProfilesOfCleansEveryStringBeforeTheTextIsBuilt(t *testing.T) {
	for _, s := range secretForms(t) {
		d := profilesOf([]*onvif.Profile{{
			Token: "t " + s, Name: "n " + s,
			VideoEncoderConfiguration: &onvif.VideoEncoderConfiguration{Encoding: "e " + s},
			VideoSourceConfiguration:  &onvif.VideoSourceConfiguration{SourceToken: "s " + s},
		}})
		assertClean(t, "profilesOf", d)
		assertClean(t, "summarizeProfiles", summarizeProfiles(d))
	}
}

// Two raw tokens that clean to the same string are one profile, as the agent
// would see them.
func TestProfilesOfDedupesOnTheCleanedToken(t *testing.T) {
	d := profilesOf([]*onvif.Profile{{Token: "dup"}, {Token: "d\u200bup"}})
	if d.Total != 1 || d.DuplicatesDropped != 1 || len(d.Profiles) != 1 {
		t.Errorf("total=%d dup=%d listed=%d", d.Total, d.DuplicatesDropped, len(d.Profiles))
	}
}

func TestDropFragment(t *testing.T) {
	for in, want := range map[string]string{
		"rtsp://h:554/s?x=1#frag": "rtsp://h:554/s?x=1",
		"rtsp://h/%zz#frag":       "rtsp://h/%zz", // does not parse: cut at the hash
		"rtsp://h/%zz":            "rtsp://h/%zz",
		"rtsp://h/s":              "rtsp://h/s",
	} {
		if got := dropFragment(in); got != want {
			t.Errorf("dropFragment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStreamURIAtTheLengthLimitIsAccepted(t *testing.T) {
	uri := "rtsp://h/" + strings.Repeat("a", maxURIChars-len("rtsp://h/"))
	if _, te := streamURIOf("c", &onvif.MediaURI{URI: uri}); te != nil {
		t.Errorf("a URI of exactly %d bytes must be accepted: %+v", maxURIChars, te)
	}
	if _, te := streamURIOf("c", &onvif.MediaURI{URI: uri + "a"}); te == nil {
		t.Error("one byte over must be refused")
	}
}

func TestStreamURIFlagsAreNotCrossed(t *testing.T) {
	a, _ := streamURIOf("c", &onvif.MediaURI{URI: "rtsp://h/x", InvalidAfterConnect: true})
	if !a.InvalidAfterConnect || a.InvalidAfterReboot {
		t.Errorf("connect only: %+v", a)
	}
	b, _ := streamURIOf("c", &onvif.MediaURI{URI: "rtsp://h/x", InvalidAfterReboot: true})
	if b.InvalidAfterConnect || !b.InvalidAfterReboot {
		t.Errorf("reboot only: %+v", b)
	}
}

func TestDiscoverOptionsPinTheProbeAddress(t *testing.T) {
	if wsDiscoveryGroup != "239.255.255.250:3702" {
		t.Errorf("WS-Discovery group = %q", wsDiscoveryGroup)
	}
	if got := discoverOptions().ProbeAddress; got != wsDiscoveryGroup {
		t.Errorf("ProbeAddress = %q: without it onvif-go binds UDP 3702 itself", got)
	}
}

func TestDiscoverHintOnlyForAnUnreachableProbe(t *testing.T) {
	_, hint := errCode(t, call(t, discoverSession(t, &fakeDisc{err: &net.OpError{Op: "write", Net: "udp", Err: errString("network is unreachable")}}), "camera.discover", nil))
	if !strings.HasPrefix(hint, "WS-Discovery could not send its probe") {
		t.Errorf("hint = %q", hint)
	}
	code, hint := errCode(t, call(t, discoverSession(t, &fakeDisc{err: context.DeadlineExceeded}), "camera.discover", nil))
	if code != "timeout" || strings.Contains(hint, "WS-Discovery") {
		t.Errorf("a timeout must keep its own hint: code=%q hint=%q", code, hint)
	}
}

func TestDiscoverNoteWarnsAboutUntrustedAnnouncements(t *testing.T) {
	f := &fakeDisc{devs: []*discovery.Device{{EndpointRef: "r", XAddrs: []string{"http://10.0.0.1/s"}}}}
	d := dataMap(t, call(t, discoverSession(t, f), "camera.discover", nil))
	note, _ := d["note"].(string)
	for _, want := range []string{"unauthenticated", "not addressable", "untrusted"} {
		if !strings.Contains(note, want) {
			t.Errorf("note lacks %q: %s", want, note)
		}
	}
}

func TestSafeXAddr(t *testing.T) {
	pinOffLink(t)
	accepted := map[string]string{ //nolint:gosec // fake test fixtures
		"https://10.0.0.1/onvif/device_service":          "https://10.0.0.1/onvif/device_service",
		"  http://10.0.0.1/s  ":                          "http://10.0.0.1/s",
		"http://10.0.0.1/s?token=abc#frag":               "http://10.0.0.1/s",
		"http://10.0.0.1/s?" + strings.Repeat("q", 2000): "http://10.0.0.1/s",
	}
	for in, want := range accepted {
		got, valid := safeXAddr(in)
		if !valid || got != want {
			t.Errorf("safeXAddr(%.40q) = %q,%v, want %q", in, got, valid, want)
		}
	}
	// The raw announcement is bounded before it is parsed, even when the part
	// that would survive is short.
	for name, in := range map[string]string{
		"2049 bytes":   "http://10.0.0.1/s?" + strings.Repeat("q", 2049-len("http://10.0.0.1/s?")),
		"3000 bytes":   "http://10.0.0.1/s?" + strings.Repeat("q", 3000),
		"ftp":          "ftp://10.0.0.1/s",
		"file":         "file:///etc/passwd",
		"javascript":   "javascript:alert(1)",
		"no host":      "http:///s",
		"empty":        "",
		"unparseable":  "http://[::1",
		"too long out": "http://10.0.0.1/" + strings.Repeat("p", maxFieldChars),
	} {
		if got, valid := safeXAddr(in); valid {
			t.Errorf("%s accepted as %q", name, got)
		}
	}
	exactly := "http://10.0.0.1/s?" + strings.Repeat("q", 2048-len("http://10.0.0.1/s?"))
	if _, valid := safeXAddr(exactly); !valid {
		t.Error("an announcement of exactly 2048 bytes is within the bound")
	}
}

func TestCandidatesRankHostnamesAboveSpecialAddresses(t *testing.T) {
	pinOffLink(t)
	for _, special := range []string{"http://127.0.0.1/x", "http://239.1.1.1/x", "http://localhost/x", "http://0.0.0.0/x", "http://169.254.169.254/x"} {
		got := candidatesFrom([]*discovery.Device{{EndpointRef: "r", XAddrs: []string{special, "http://zzz.example/x"}}})
		if got.cands[0].XAddrs[0] != "http://zzz.example/x" {
			t.Errorf("%s ranked ahead of a hostname: %v", special, got.cands[0].XAddrs)
		}
	}
}

// getServices must ask without capabilities; asking with them is a bigger and
// slower request the tool does not use.
func TestDescribeAsksForServicesWithoutCapabilities(t *testing.T) {
	fx, seen := routedFixtureLog(t, false, []route{
		{[]string{"GetDeviceInformation"}, `<tds:GetDeviceInformationResponse ` + tdsNS + `><tds:Manufacturer>Acme</tds:Manufacturer></tds:GetDeviceInformationResponse>`},
		{[]string{"GetServices", "IncludeCapability>false<"}, `<tds:GetServicesResponse ` + tdsNS + `><tds:Service><tds:Namespace>urn:x</tds:Namespace><tds:XAddr>http://h/</tds:XAddr></tds:Service></tds:GetServicesResponse>`},
	})
	d := dataMap(t, call(t, fxSession(t, fx), "camera.describe", map[string]any{"camera": "fx"}))
	if svcs, _ := d["advertised_services"].([]any); len(svcs) != 1 {
		t.Errorf("GetServices was not sent with IncludeCapability=false: %v (%d requests)", d, len(seen()))
	}
}

func TestDescribeIdentityTextWithPartialIdentity(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"manufacturer only": {`<tds:Manufacturer>Acme</tds:Manufacturer>`, "Acme ."},
		"model only":        {`<tds:Model>M1</tds:Model>`, "M1."},
	} {
		fx := fixture(t, map[string]string{"GetDeviceInformation": `<tds:GetDeviceInformationResponse ` + tdsNS + `>` + tc.body + `</tds:GetDeviceInformationResponse>`})
		res := call(t, fxSession(t, fx), "camera.describe", map[string]any{"camera": "fx"})
		if txt := textOf(res); !strings.HasPrefix(txt, tc.want) {
			t.Errorf("%s: text = %q, want prefix %q", name, txt, tc.want)
		}
	}
}

// No PTZ configuration on the profile means there is nothing to ask for, so
// GetConfiguration must not be sent at all.
func TestPresetsDoNotAskForConfigurationWithoutAToken(t *testing.T) {
	fx, seen := routedFixtureLog(t, true, []route{
		{[]string{"GetPresets"}, `<tptz:GetPresetsResponse ` + ptzNS + `/>`},
		{[]string{"GetProfiles"}, `<trt:GetProfilesResponse ` + trtNS + ` ` + ptzNS + `><trt:Profiles token="p"><tt:Name>n</tt:Name></trt:Profiles></trt:GetProfilesResponse>`},
	})
	dataMap(t, call(t, fxSession(t, fx), "ptz.presets", map[string]any{"camera": "fx", "profile": "p"}))
	for _, req := range seen() {
		if strings.Contains(req, "GetConfiguration") {
			t.Errorf("GetConfiguration was sent for a profile with no PTZ configuration: %.200s", req)
		}
	}
}

func TestPresetsTextWhenCappedAndWhenAllHavePositions(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<tptz:GetPresetsResponse ` + ptzNS + `>`)
	for i := 0; i < 300; i++ {
		b.WriteString(`<tptz:Preset token="p` + string(rune('A'+i/26/26)) + string(rune('a'+i/26%26)) + string(rune('a'+i%26)) +
			`"><tt:Name>n</tt:Name><tptz:PTZPosition><tt:Zoom x="0.5"/></tptz:PTZPosition></tptz:Preset>`)
	}
	b.WriteString(`</tptz:GetPresetsResponse>`)
	fx := fixtureWith(t, map[string]string{"GetPresets": b.String()}, true)
	res := call(t, fxSession(t, fx), "ptz.presets", map[string]any{"camera": "fx", "profile": "p"})
	txt := textOf(res)
	if !strings.Contains(txt, "300 preset(s) (first 256 listed)") {
		t.Errorf("text = %q", txt)
	}
	if strings.Contains(txt, "with position not reported") {
		t.Errorf("every preset has a position, the text must not say otherwise: %q", txt)
	}
}

// snippet encodes the endpoint itself, whatever the caller already did to it.
func TestSnippetIsAlwaysOneJSONField(t *testing.T) {
	for _, endpoint := range []string{`http://h/a"b","password":"x`, "http://h/\\\"", "http://h/s"} {
		s := snippet(endpoint)
		var m map[string]map[string]string
		if err := json.Unmarshal([]byte("{"+s+"}"), &m); err != nil {
			t.Errorf("snippet(%q) is not a JSON member: %v: %s", endpoint, err, s)
			continue
		}
		if got := m["<choose-an-id>"]["endpoint"]; got != endpoint || len(m["<choose-an-id>"]) != 1 {
			t.Errorf("snippet(%q) = %v", endpoint, m)
		}
	}
}

func TestHostRankOfAnUnparseableAddressIsSpecial(t *testing.T) {
	pinOffLink(t)
	if got := hostRank("http://[::1"); got != rankSpecial {
		t.Errorf("hostRank = %d, want rankSpecial", got)
	}
	if got := hostRank("http://10.0.0.1/s"); got != rankOther {
		t.Errorf("hostRank = %d, want rankOther", got)
	}
}
