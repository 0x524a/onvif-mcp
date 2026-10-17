package tools

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/registry"
)

// route answers a request containing every string in all with body.
type route struct {
	all  []string
	body string
}

// routedFixture is fixtureWith with ordered, multi-key routes, for replies that
// depend on a token in the request. The first matching route wins.
func routedFixture(t *testing.T, ptz bool, routes []route) *httptest.Server {
	t.Helper()
	srv, _ := routedFixtureLog(t, ptz, routes)
	return srv
}

// routedFixtureLog is routedFixture that also returns the request bodies seen
// so far, in order, so a test can assert which operations were (not) called.
func routedFixtureLog(t *testing.T, ptz bool, routes []route) (*httptest.Server, func() []string) {
	t.Helper()
	var (
		url  string
		mu   sync.Mutex
		seen []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := make([]byte, 1<<16)
		n, _ := r.Body.Read(raw)
		req := string(raw[:n])
		mu.Lock()
		seen = append(seen, req)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/soap+xml")
		if strings.Contains(req, "GetCapabilities") {
			ptzXML := ""
			if ptz {
				ptzXML = `<tt:PTZ xmlns:tt="http://www.onvif.org/ver10/schema"><tt:XAddr>` + url + `/ptz</tt:XAddr></tt:PTZ>`
			}
			_, _ = fmt.Fprintf(w, envelope, `<tds:GetCapabilitiesResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:Capabilities>`+ptzXML+
				`<tt:Media xmlns:tt="http://www.onvif.org/ver10/schema"><tt:XAddr>`+url+`/media</tt:XAddr></tt:Media>`+
				`</tds:Capabilities></tds:GetCapabilitiesResponse>`)
			return
		}
		for _, rt := range routes {
			ok := true
			for _, k := range rt.all {
				if !strings.Contains(req, k) {
					ok = false
				}
			}
			if ok {
				_, _ = fmt.Fprintf(w, envelope, rt.body)
				return
			}
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, envelope, `<s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code><s:Reason><s:Text xml:lang="en">unexpected operation</s:Text></s:Reason></s:Fault>`)
	}))
	url = srv.URL
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func fxSession(t *testing.T, srv *httptest.Server) *mcp.ClientSession {
	t.Helper()
	return harnessWith(t, map[string]*config.Camera{"fx": fixtureCamera(srv)})
}

func TestProfilesFieldsMapFromDistinctValues(t *testing.T) {
	fx := fixture(t, map[string]string{"GetProfiles": `<trt:GetProfilesResponse ` + trtNS + ` ` + ptzNS + `>` +
		`<trt:Profiles token="main"><tt:Name>Main Stream</tt:Name>` +
		`<tt:VideoSourceConfiguration token="vsc"><tt:SourceToken>VS7</tt:SourceToken></tt:VideoSourceConfiguration>` +
		`<tt:VideoEncoderConfiguration token="e"><tt:Encoding>H265</tt:Encoding><tt:Resolution><tt:Width>1920</tt:Width><tt:Height>1080</tt:Height></tt:Resolution>` +
		`<tt:RateControl><tt:FrameRateLimit>25</tt:FrameRateLimit></tt:RateControl></tt:VideoEncoderConfiguration>` +
		`<tt:PTZConfiguration token="ptz1"><tt:Name>c</tt:Name></tt:PTZConfiguration></trt:Profiles>` +
		`<trt:Profiles token="sub"><tt:Name>Sub</tt:Name></trt:Profiles></trt:GetProfilesResponse>`})
	res := call(t, fxSession(t, fx), "media.profiles", map[string]any{"camera": "fx"})
	ps := dataMap(t, res)["profiles"].([]any)
	if len(ps) != 2 {
		t.Fatalf("profiles: %s", wire(t, res))
	}
	main := ps[0].(map[string]any)
	want := map[string]any{"token": "main", "name": "Main Stream", "has_ptz": true, "encoding": "H265",
		"width": float64(1920), "height": float64(1080), "framerate": float64(25), "video_source_token": "VS7"}
	for k, v := range want {
		if main[k] != v {
			t.Errorf("main.%s = %v, want %v", k, main[k], v)
		}
	}
	if sub := ps[1].(map[string]any); sub["has_ptz"] != false || sub["name"] != "Sub" {
		t.Errorf("sub = %v", sub)
	}
	if txt := textOf(res); !strings.Contains(txt, "main (H265 1920x1080, PTZ, source=VS7)") {
		t.Errorf("text = %q", txt)
	}
}

func TestImagingFieldsMapFromDistinctValues(t *testing.T) {
	fx := fixture(t, map[string]string{"GetImagingSettings": `<timg:GetImagingSettingsResponse xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl">` +
		`<timg:ImagingSettings xmlns:tt="http://www.onvif.org/ver10/schema"><tt:Brightness>1</tt:Brightness><tt:ColorSaturation>3</tt:ColorSaturation>` +
		`<tt:Contrast>2</tt:Contrast><tt:Sharpness>4</tt:Sharpness></timg:ImagingSettings></timg:GetImagingSettingsResponse>`})
	res := call(t, fxSession(t, fx), "imaging.settings", map[string]any{"camera": "fx", "source_token": "vs"})
	d := dataMap(t, res)
	if d["brightness"] != float64(1) || d["contrast"] != float64(2) || d["color_saturation"] != float64(3) || d["sharpness"] != float64(4) {
		t.Errorf("fields crossed: %v", d)
	}
	if txt := textOf(res); txt != "Imaging: brightness 1, contrast 2, saturation 3, sharpness 4." {
		t.Errorf("text = %q", txt)
	}
}

func TestImagingEmptySettingsIsNotAnError(t *testing.T) {
	fx := fixture(t, map[string]string{"GetImagingSettings": `<timg:GetImagingSettingsResponse xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl"/>`})
	res := call(t, fxSession(t, fx), "imaging.settings", map[string]any{"camera": "fx", "source_token": "vs"})
	d := dataMap(t, res)
	for _, k := range []string{"brightness", "contrast", "color_saturation", "sharpness"} {
		if _, ok := d[k]; ok {
			t.Errorf("%s invented: %v", k, d)
		}
	}
}

func TestPTZStatusFieldsMapFromDistinctValues(t *testing.T) {
	fx := fixtureWith(t, map[string]string{"GetStatus": `<tptz:GetStatusResponse ` + ptzNS + `><tptz:PTZStatus>` +
		`<tt:Position><tt:PanTilt x="0.1" y="0.2"/><tt:Zoom x="0.3"/></tt:Position>` +
		`<tt:MoveStatus><tt:PanTilt>MOVING</tt:PanTilt><tt:Zoom>IDLE</tt:Zoom></tt:MoveStatus><tt:Error>lens stuck</tt:Error>` +
		`</tptz:PTZStatus></tptz:GetStatusResponse>`}, true)
	res := call(t, fxSession(t, fx), "ptz.status", map[string]any{"camera": "fx", "profile": "prof"})
	d := dataMap(t, res)
	want := map[string]any{"pan": 0.1, "tilt": 0.2, "zoom": 0.3, "pan_tilt_state": "MOVING", "zoom_state": "IDLE", "device_error": "lens stuck"}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("%s = %v, want %v", k, d[k], v)
		}
	}
	if txt := textOf(res); txt != "PTZ pan 0.1, tilt 0.2, zoom 0.3. Pan/tilt MOVING." {
		t.Errorf("text = %q", txt)
	}
}

func TestPTZStatusZoomOnlyPosition(t *testing.T) {
	fx := fixtureWith(t, map[string]string{"GetStatus": `<tptz:GetStatusResponse ` + ptzNS + `><tptz:PTZStatus>` +
		`<tt:Position><tt:Zoom x="0.6"/></tt:Position></tptz:PTZStatus></tptz:GetStatusResponse>`}, true)
	res := call(t, fxSession(t, fx), "ptz.status", map[string]any{"camera": "fx", "profile": "prof"})
	d := dataMap(t, res)
	if d["zoom"] != 0.6 {
		t.Errorf("zoom = %v", d["zoom"])
	}
	for _, k := range []string{"pan", "tilt", "pan_tilt_state", "zoom_state", "device_error"} {
		if _, ok := d[k]; ok {
			t.Errorf("%s invented: %v", k, d)
		}
	}
	if txt := textOf(res); txt != "PTZ pan not reported, tilt not reported, zoom 0.6." {
		t.Errorf("text = %q", txt)
	}
}

func TestPTZPresetsFieldsAndText(t *testing.T) {
	fx := fixtureWith(t, map[string]string{"GetPresets": `<tptz:GetPresetsResponse ` + ptzNS + `>` +
		`<tptz:Preset token="p1"><tt:Name>Door</tt:Name><tptz:PTZPosition xmlns:tptz="http://www.onvif.org/ver10/schema"><tt:PanTilt x="0.1" y="0.2"/><tt:Zoom x="0.3"/></tptz:PTZPosition></tptz:Preset>` +
		`<tptz:Preset token="p2"><tt:Name>Gate</tt:Name></tptz:Preset>` +
		`<tptz:Preset token="p3"><tt:Name>Yard</tt:Name></tptz:Preset></tptz:GetPresetsResponse>`}, true)
	res := call(t, fxSession(t, fx), "ptz.presets", map[string]any{"camera": "fx", "profile": "prof"})
	d := dataMap(t, res)
	ps := d["presets"].([]any)
	if len(ps) != 3 || ps[0].(map[string]any)["token"] != "p1" || ps[2].(map[string]any)["token"] != "p3" {
		t.Fatalf("order/length: %s", wire(t, res))
	}
	if txt := textOf(res); !strings.Contains(txt, "3 preset(s)") || !strings.Contains(txt, "2 with position not reported") ||
		!strings.Contains(txt, "movement limits not reported") {
		t.Errorf("text = %q", txt)
	}
}

// Limits come from the requested profile's own PTZ configuration, not from the
// first profile that has one.
func TestPTZPresetsLimitsComeFromTheRequestedProfile(t *testing.T) {
	cfg := func(token, lo, hi string) string {
		return `<tptz:GetConfigurationResponse ` + ptzNS + `><tptz:PTZConfiguration token="` + token + `"><tt:Name>c</tt:Name>` +
			`<tt:PanTiltLimits><tt:Range><tt:URI>u</tt:URI><tt:XRange><tt:Min>` + lo + `</tt:Min><tt:Max>` + hi + `</tt:Max></tt:XRange>` +
			`<tt:YRange><tt:Min>-0.5</tt:Min><tt:Max>0.25</tt:Max></tt:YRange></tt:Range></tt:PanTiltLimits>` +
			`<tt:ZoomLimits><tt:Range><tt:URI>u</tt:URI><tt:XRange><tt:Min>0</tt:Min><tt:Max>0.75</tt:Max></tt:XRange></tt:Range></tt:ZoomLimits>` +
			`</tptz:PTZConfiguration></tptz:GetConfigurationResponse>`
	}
	fx := routedFixture(t, true, []route{
		{[]string{"GetConfiguration", "cfg-two"}, cfg("cfg-two", "-2", "2")},
		{[]string{"GetConfiguration", "cfg-one"}, cfg("cfg-one", "-1", "1")},
		{[]string{"GetPresets"}, `<tptz:GetPresetsResponse ` + ptzNS + `/>`},
		{[]string{"GetProfiles"}, `<trt:GetProfilesResponse ` + trtNS + ` ` + ptzNS + `>` +
			`<trt:Profiles token="one"><tt:Name>1</tt:Name><tt:PTZConfiguration token="cfg-one"><tt:Name>c</tt:Name></tt:PTZConfiguration></trt:Profiles>` +
			`<trt:Profiles token="two"><tt:Name>2</tt:Name><tt:PTZConfiguration token="cfg-two"><tt:Name>c</tt:Name></tt:PTZConfiguration></trt:Profiles>` +
			`</trt:GetProfilesResponse>`},
	})
	res := call(t, fxSession(t, fx), "ptz.presets", map[string]any{"camera": "fx", "profile": "two"})
	l, _ := dataMap(t, res)["reported_limits"].(map[string]any)
	pan, _ := l["pan"].(map[string]any)
	tilt, _ := l["tilt"].(map[string]any)
	zoom, _ := l["zoom"].(map[string]any)
	if pan["min"] != float64(-2) || pan["max"] != float64(2) {
		t.Errorf("pan = %v (the first profile's limits were used?)", pan)
	}
	if tilt["min"] != -0.5 || tilt["max"] != 0.25 {
		t.Errorf("tilt = %v", tilt)
	}
	if zoom["min"] != float64(0) || zoom["max"] != 0.75 {
		t.Errorf("zoom = %v", zoom)
	}
	if strings.Contains(textOf(res), "movement limits not reported") {
		t.Errorf("text claims no limits: %q", textOf(res))
	}
}

// A configuration with nothing in it must not become "reported_limits": {}.
func TestPTZPresetsEmptyConfigurationReportsNoLimits(t *testing.T) {
	fx := routedFixture(t, true, []route{
		{[]string{"GetConfiguration"}, `<tptz:GetConfigurationResponse ` + ptzNS + `><tptz:PTZConfiguration token="c"><tt:Name>c</tt:Name>` +
			`<tt:PanTiltLimits/><tt:ZoomLimits/></tptz:PTZConfiguration></tptz:GetConfigurationResponse>`},
		{[]string{"GetPresets"}, `<tptz:GetPresetsResponse ` + ptzNS + `/>`},
		{[]string{"GetProfiles"}, `<trt:GetProfilesResponse ` + trtNS + ` ` + ptzNS + `>` +
			`<trt:Profiles token="p"><tt:Name>1</tt:Name><tt:PTZConfiguration token="c"><tt:Name>c</tt:Name></tt:PTZConfiguration></trt:Profiles></trt:GetProfilesResponse>`},
	})
	res := call(t, fxSession(t, fx), "ptz.presets", map[string]any{"camera": "fx", "profile": "p"})
	if _, ok := dataMap(t, res)["reported_limits"]; ok {
		t.Errorf("reported_limits must be absent: %s", wire(t, res))
	}
	if !strings.Contains(textOf(res), "movement limits not reported") {
		t.Errorf("text = %q", textOf(res))
	}
}

func TestDescribeLabelsAdvertisedNotVerified(t *testing.T) {
	fx := fixture(t, map[string]string{
		"GetDeviceInformation": `<tds:GetDeviceInformationResponse ` + tdsNS + `><tds:Manufacturer>Acme</tds:Manufacturer><tds:Model>M1</tds:Model>` +
			`<tds:FirmwareVersion>1.2</tds:FirmwareVersion><tds:SerialNumber>SN-9</tds:SerialNumber><tds:HardwareId>HW-3</tds:HardwareId></tds:GetDeviceInformationResponse>`,
		"GetServices": `<tds:GetServicesResponse ` + tdsNS + `>` +
			`<tds:Service><tds:Namespace>urn:zeta</tds:Namespace><tds:XAddr>http://h/</tds:XAddr></tds:Service>` +
			`<tds:Service><tds:Namespace></tds:Namespace><tds:XAddr>http://h/</tds:XAddr></tds:Service>` +
			`<tds:Service><tds:Namespace>urn:alpha</tds:Namespace><tds:XAddr>http://h/</tds:XAddr></tds:Service>` +
			`<tds:Service><tds:Namespace>urn:zeta</tds:Namespace><tds:XAddr>http://h/</tds:XAddr></tds:Service>` +
			`</tds:GetServicesResponse>`,
	})
	res := call(t, fxSession(t, fx), "camera.describe", map[string]any{"camera": "fx"})
	d := dataMap(t, res)
	svcs, ok := d["advertised_services"].([]any)
	if !ok || len(svcs) != 2 || svcs[0] != "urn:alpha" || svcs[1] != "urn:zeta" {
		t.Errorf("advertised_services = %v", d["advertised_services"])
	}
	if _, bad := d["services"]; bad {
		t.Error("the list must be called advertised_services, not services")
	}
	if d["capabilities_verified"] != false || d["total"] != float64(2) || d["truncated"] != false {
		t.Errorf("flags: %v", d)
	}
	if note, _ := d["capabilities_note"].(string); !strings.Contains(note, "advertised") || !strings.Contains(note, "not probed") {
		t.Errorf("capabilities_note = %q", note)
	}
	want := map[string]string{"manufacturer": "Acme", "model": "M1", "firmware_version": "1.2", "serial_number": "SN-9", "hardware_id": "HW-3"}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("%s = %v, want %v", k, d[k], v)
		}
	}
	if txt := textOf(res); txt != "Acme M1. 2 advertised service(s), not verified." {
		t.Errorf("text = %q", txt)
	}
}

func TestDescribeRefusedServiceListIsLabelledAndNotNull(t *testing.T) {
	fx := fixture(t, map[string]string{
		"GetDeviceInformation": `<tds:GetDeviceInformationResponse ` + tdsNS + `><tds:Manufacturer>Acme</tds:Manufacturer></tds:GetDeviceInformationResponse>`,
	})
	res := call(t, fxSession(t, fx), "camera.describe", map[string]any{"camera": "fx"})
	d := dataMap(t, res)
	if svcs, ok := d["advertised_services"].([]any); !ok || len(svcs) != 0 {
		t.Errorf("advertised_services must be an empty array, got %#v", d["advertised_services"])
	}
	if note, _ := d["capabilities_note"].(string); !strings.HasPrefix(note, "the camera did not report a service list; ") {
		t.Errorf("note = %q", note)
	}
	if txt := textOf(res); !strings.Contains(txt, "Service list not reported.") {
		t.Errorf("text = %q", txt)
	}
}

func TestDescribeEmptyDeviceInformation(t *testing.T) {
	fx := fixture(t, map[string]string{
		"GetDeviceInformation": `<tds:GetDeviceInformationResponse ` + tdsNS + `/>`,
		"GetServices":          `<tds:GetServicesResponse ` + tdsNS + `/>`,
	})
	res := call(t, fxSession(t, fx), "camera.describe", map[string]any{"camera": "fx"})
	d := dataMap(t, res)
	for _, k := range []string{"manufacturer", "model", "serial_number", "hardware_id", "firmware_version"} {
		if _, ok := d[k]; ok {
			t.Errorf("%s invented", k)
		}
	}
	if txt := textOf(res); !strings.HasPrefix(txt, "Identity not reported.") {
		t.Errorf("text = %q", txt)
	}
}

func TestToolDescriptionsStayHonestAboutAdvertisedServices(t *testing.T) {
	cs, _ := harness(t)
	got := map[string]*mcp.Tool{}
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range res.Tools {
		got[tool.Name] = tool
	}
	if d := got["camera.describe"].Description; !strings.Contains(d, "not verified") || !strings.Contains(d, "claims") {
		t.Errorf("camera.describe description = %q", d)
	}
}

func TestStreamURIUnparseableIsDeviceFaultAndNeverEchoed(t *testing.T) {
	fx := fixture(t, map[string]string{"GetStreamUri": `<trt:GetStreamUriResponse ` + trtNS +
		`><trt:MediaUri><tt:Uri>rtsp://admin:pw-hunter2@[::1</tt:Uri></trt:MediaUri></trt:GetStreamUriResponse>`})
	res := call(t, fxSession(t, fx), "media.stream_uri", map[string]any{"camera": "fx", "profile": "p"})
	if code, _ := errCode(t, res); code != "device_fault" || !res.IsError {
		t.Fatalf("want device_fault: %s", wire(t, res))
	}
	w := wire(t, res)
	if strings.Contains(w, "hunter2") || strings.Contains(w, "admin") || strings.Contains(w, "[::1") {
		t.Errorf("the unparseable URI was echoed: %s", w)
	}
	if !strings.Contains(w, "could not be parsed") {
		t.Errorf("fixed message missing: %s", w)
	}
}

func TestStreamURIFlagsAndNoUserinfoInText(t *testing.T) {
	fx := fixture(t, map[string]string{"GetStreamUri": `<trt:GetStreamUriResponse ` + trtNS + `><trt:MediaUri><tt:Uri>rtsp://admin:pw@h:554/s</tt:Uri>` +
		`<tt:InvalidAfterConnect>true</tt:InvalidAfterConnect><tt:InvalidAfterReboot>true</tt:InvalidAfterReboot></trt:MediaUri></trt:GetStreamUriResponse>`}) //nolint:gosec // fake test fixture
	res := call(t, fxSession(t, fx), "media.stream_uri", map[string]any{"camera": "fx", "profile": "p"})
	d := dataMap(t, res)
	if d["invalid_after_connect"] != true || d["invalid_after_reboot"] != true {
		t.Errorf("flags: %v", d)
	}
	if txt := textOf(res); strings.Contains(txt, "admin") || strings.Contains(txt, "pw@") || !strings.Contains(txt, "rtsp://h:554/s") {
		t.Errorf("text = %q", txt)
	}
}

// The profile hint is for a missing token only: any other failure keeps its
// own hint, and a not_found names the tool that lists valid values.
func TestHintsOnlyReplaceNotFound(t *testing.T) {
	notFound := fxSession(t, faultFixture(t, "ter:NoProfile profile not found"))
	for tool, args := range map[string]map[string]any{
		"media.stream_uri": {"camera": "fx", "profile": "ghost"},
		"ptz.status":       {"camera": "fx", "profile": "ghost"},
		"ptz.presets":      {"camera": "fx", "profile": "ghost"},
		"imaging.settings": {"camera": "fx", "source_token": "ghost"},
	} {
		res := call(t, notFound, tool, args)
		code, hint := errCode(t, res)
		if code != "not_found" {
			t.Errorf("%s: code = %q: %s", tool, code, wire(t, res))
			continue
		}
		if !strings.Contains(hint, "media.profiles") {
			t.Errorf("%s: hint = %q", tool, hint)
		}
	}
	if _, hint := errCode(t, call(t, notFound, "imaging.settings", map[string]any{"camera": "fx", "source_token": "g"})); !strings.Contains(hint, "video_source_token") {
		t.Errorf("imaging hint = %q", hint)
	}

	auth := fxSession(t, faultFixture(t, "Sender not authorized"))
	for tool, args := range map[string]map[string]any{
		"media.stream_uri": {"camera": "fx", "profile": "p"},
		"ptz.status":       {"camera": "fx", "profile": "p"},
		"ptz.presets":      {"camera": "fx", "profile": "p"},
		"imaging.settings": {"camera": "fx", "source_token": "p"},
	} {
		code, hint := errCode(t, call(t, auth, tool, args))
		if code != "auth_failed" {
			t.Errorf("%s: code = %q", tool, code)
		}
		if strings.Contains(hint, "media.profiles") || !strings.Contains(hint, "username and password") {
			t.Errorf("%s: an auth failure got hint %q", tool, hint)
		}
	}
}

// Cancelling the Base context aborts a call that is waiting on a slow camera.
func TestBaseCancellationAbortsASlowCall(t *testing.T) {
	var once sync.Once
	entered := make(chan struct{})
	release := make(chan struct{})
	var url string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := make([]byte, 1<<16)
		n, _ := r.Body.Read(raw)
		w.Header().Set("Content-Type", "application/soap+xml")
		if strings.Contains(string(raw[:n]), "GetCapabilities") {
			_, _ = fmt.Fprintf(w, envelope, `<tds:GetCapabilitiesResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:Capabilities>`+
				`<tt:Media xmlns:tt="http://www.onvif.org/ver10/schema"><tt:XAddr>`+url+`/media</tt:XAddr></tt:Media></tds:Capabilities></tds:GetCapabilitiesResponse>`)
			return
		}
		once.Do(func() { close(entered) })
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	url = srv.URL
	defer srv.Close()
	defer close(release)

	base, stop := context.WithCancel(context.Background())
	defer stop()
	cs := harnessDeps(t, Deps{
		Reg:  registry.New(&config.Config{Cameras: map[string]*config.Camera{"fx": {ID: "fx", Endpoint: srv.URL + "/device_service", Username: "u", Password: "pw", TimeoutSeconds: 30}}}),
		Log:  quietLog(),
		Base: base,
	})
	done := make(chan *mcp.CallToolResult, 1)
	go func() {
		res, _ := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "media.profiles", Arguments: map[string]any{"camera": "fx"}})
		done <- res
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the slow handler was never reached")
	}
	stop()
	select {
	case res := <-done:
		if res == nil || !res.IsError {
			t.Errorf("want an error result, got %+v", res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelling Base did not abort the slow call (it would wait out the 30s camera timeout)")
	}
}
