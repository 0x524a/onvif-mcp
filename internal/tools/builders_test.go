package tools

import (
	"context"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	onvif "github.com/0x524a/onvif-go"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
)

func fp(v float64) *float64 { return &v }

// The builders below take the library's types directly, so the paths a
// well-formed SOAP reply cannot reach (nil list entries, nil sub-structs) are
// exercised without a fixture.

func TestProfilesOfMapsEveryFieldFromDistinctValues(t *testing.T) {
	got := profilesOf([]*onvif.Profile{
		{
			Token: "tok-main", Name: "Main stream",
			VideoSourceConfiguration:  &onvif.VideoSourceConfiguration{SourceToken: "src-1"},
			VideoEncoderConfiguration: &onvif.VideoEncoderConfiguration{Encoding: "H265", Resolution: &onvif.VideoResolution{Width: 1920, Height: 1080}, RateControl: &onvif.VideoRateControl{FrameRateLimit: 25}},
			PTZConfiguration:          &onvif.PTZConfiguration{Token: "ptz-1"},
		},
		{Token: "tok-sub", Name: "Sub stream"},
	})
	want := ProfilesData{
		Profiles: []ProfileSummary{
			{Token: "tok-main", Name: "Main stream", HasPTZ: true, Encoding: "H265", Width: 1920, Height: 1080, Framerate: 25, SourceToken: "src-1"},
			{Token: "tok-sub", Name: "Sub stream"},
		},
		Total: 2,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestProfilesOfSurvivesNilAtEveryLevel(t *testing.T) {
	got := profilesOf([]*onvif.Profile{
		nil,
		{Token: "bare"},
		{Token: "enc-only", VideoEncoderConfiguration: &onvif.VideoEncoderConfiguration{Encoding: "H264"}},
		{Token: "rate-only", VideoEncoderConfiguration: &onvif.VideoEncoderConfiguration{RateControl: &onvif.VideoRateControl{FrameRateLimit: 12}}},
		{Token: "res-only", VideoEncoderConfiguration: &onvif.VideoEncoderConfiguration{Resolution: &onvif.VideoResolution{Width: 640, Height: 480}}},
		nil,
		{Token: "bare"},
	})
	if got.Total != 4 || got.DuplicatesDropped != 1 || len(got.Profiles) != 4 {
		t.Fatalf("total=%d dup=%d listed=%d", got.Total, got.DuplicatesDropped, len(got.Profiles))
	}
	byTok := map[string]ProfileSummary{}
	for _, p := range got.Profiles {
		byTok[p.Token] = p
	}
	if p := byTok["enc-only"]; p.Encoding != "H264" || p.Width != 0 || p.Framerate != 0 {
		t.Errorf("enc-only = %+v", p)
	}
	if p := byTok["rate-only"]; p.Framerate != 12 || p.Encoding != "" {
		t.Errorf("rate-only = %+v", p)
	}
	if p := byTok["res-only"]; p.Width != 640 || p.Height != 480 {
		t.Errorf("res-only = %+v", p)
	}
	if p := byTok["bare"]; p.HasPTZ || p.SourceToken != "" {
		t.Errorf("bare = %+v", p)
	}
	// Reported order is kept.
	var order []string
	for _, p := range got.Profiles {
		order = append(order, p.Token)
	}
	if strings.Join(order, ",") != "bare,enc-only,rate-only,res-only" {
		t.Errorf("order = %v", order)
	}
}

func TestImagingOfMapsEachSettingToItsOwnField(t *testing.T) {
	got := imagingOf(&onvif.ImagingSettings{Brightness: fp(1), Contrast: fp(2), ColorSaturation: fp(3), Sharpness: fp(4)})
	if *got.Brightness != 1 || *got.Contrast != 2 || *got.ColorSaturation != 3 || *got.Sharpness != 4 {
		t.Errorf("mapping crossed: b=%v c=%v sat=%v sh=%v", *got.Brightness, *got.Contrast, *got.ColorSaturation, *got.Sharpness)
	}
	if z := imagingOf(nil); z != (ImagingData{}) {
		t.Errorf("nil settings must report nothing: %+v", z)
	}
	nan := imagingOf(&onvif.ImagingSettings{Brightness: fp(math.NaN()), Contrast: fp(math.Inf(1))})
	if nan.Brightness != nil || nan.Contrast != nil {
		t.Errorf("non-finite must be absent: %+v", nan)
	}
	// The text summary labels each value with its own name.
	if s := summarizeImaging(got); s != "Imaging: brightness 1, contrast 2, saturation 3, sharpness 4." {
		t.Errorf("summary = %q", s)
	}
	if s := summarizeImaging(ImagingData{}); !strings.Contains(s, "brightness not reported") || !strings.Contains(s, "sharpness not reported") {
		t.Errorf("summary = %q", s)
	}
}

func TestStatusOfPositionAndStates(t *testing.T) {
	got := statusOf(&onvif.PTZStatus{
		Position:   &onvif.PTZVector{PanTilt: &onvif.Vector2D{X: 0.1, Y: 0.2}, Zoom: &onvif.Vector1D{X: 0.3}},
		MoveStatus: &onvif.PTZMoveStatus{PanTilt: "MOVING", Zoom: "IDLE"},
		Error:      "stalled",
	})
	if *got.Pan != 0.1 || *got.Tilt != 0.2 || *got.Zoom != 0.3 {
		t.Errorf("pan/tilt/zoom = %v/%v/%v", *got.Pan, *got.Tilt, *got.Zoom)
	}
	if got.PanTiltState != "MOVING" || got.ZoomState != "IDLE" || got.DeviceError != "stalled" {
		t.Errorf("states = %+v", got)
	}

	if z := statusOf(nil); !reflect.DeepEqual(z, StatusData{}) {
		t.Errorf("nil status = %+v", z)
	}
	zoomOnly := statusOf(&onvif.PTZStatus{Position: &onvif.PTZVector{Zoom: &onvif.Vector1D{X: 0.7}}})
	if zoomOnly.Pan != nil || zoomOnly.Tilt != nil || zoomOnly.Zoom == nil || *zoomOnly.Zoom != 0.7 {
		t.Errorf("zoom-only = %+v", zoomOnly)
	}
	panTiltOnly := statusOf(&onvif.PTZStatus{Position: &onvif.PTZVector{PanTilt: &onvif.Vector2D{X: -0.4, Y: 0.9}}})
	if panTiltOnly.Zoom != nil || *panTiltOnly.Pan != -0.4 || *panTiltOnly.Tilt != 0.9 {
		t.Errorf("pan/tilt-only = %+v", panTiltOnly)
	}
	noMove := statusOf(&onvif.PTZStatus{Position: &onvif.PTZVector{}})
	if noMove.PanTiltState != "" || noMove.ZoomState != "" || noMove.Pan != nil {
		t.Errorf("empty = %+v", noMove)
	}
}

func TestPositionOfDropsEachNonFiniteAxisIndependently(t *testing.T) {
	pan, tilt, zoom := positionOf(&onvif.PTZVector{PanTilt: &onvif.Vector2D{X: math.NaN(), Y: 0.5}, Zoom: &onvif.Vector1D{X: math.Inf(-1)}})
	if pan != nil || zoom != nil || tilt == nil || *tilt != 0.5 {
		t.Errorf("pan=%v tilt=%v zoom=%v", pan, tilt, zoom)
	}
	pan, tilt, zoom = positionOf(&onvif.PTZVector{PanTilt: &onvif.Vector2D{X: 0.5, Y: math.Inf(1)}, Zoom: &onvif.Vector1D{X: 0.25}})
	if tilt != nil || pan == nil || *pan != 0.5 || zoom == nil || *zoom != 0.25 {
		t.Errorf("pan=%v tilt=%v zoom=%v", pan, tilt, zoom)
	}
	if p, ti, z := positionOf(nil); p != nil || ti != nil || z != nil {
		t.Error("nil vector must report nothing")
	}
}

func TestFmtPosNamesEachAxis(t *testing.T) {
	if s := fmtPos(fp(0.1), fp(0.2), fp(0.3)); s != "pan 0.1, tilt 0.2, zoom 0.3" {
		t.Errorf("fmtPos = %q", s)
	}
	if s := fmtPos(nil, fp(0.2), nil); s != "pan not reported, tilt 0.2, zoom not reported" {
		t.Errorf("fmtPos = %q", s)
	}
	if s := fmtPos(nil, nil, nil); s != "position not reported" {
		t.Errorf("fmtPos = %q", s)
	}
}

func TestPresetsOfMapsAndCountsMissingPositions(t *testing.T) {
	got, noPos := presetsOf([]*onvif.PTZPreset{
		nil,
		{Token: "full", Name: "Door", PTZPosition: &onvif.PTZVector{PanTilt: &onvif.Vector2D{X: 0.1, Y: 0.2}, Zoom: &onvif.Vector1D{X: 0.3}}},
		{Token: "none", Name: "Nowhere"},
		{Token: "zoom", PTZPosition: &onvif.PTZVector{Zoom: &onvif.Vector1D{X: 0.5}}},
		{Token: "pan", PTZPosition: &onvif.PTZVector{PanTilt: &onvif.Vector2D{X: 0.9}}},
		{Token: "empty", PTZPosition: &onvif.PTZVector{}},
		{Token: "full", Name: "Duplicate"},
	})
	if got.Total != 5 || got.DuplicatesDropped != 1 || got.Truncated {
		t.Fatalf("total=%d dup=%d trunc=%v", got.Total, got.DuplicatesDropped, got.Truncated)
	}
	// "none" and "empty" have no axis at all; "zoom" and "pan" have one.
	if noPos != 2 {
		t.Errorf("noPos = %d, want 2", noPos)
	}
	f := got.Presets[0]
	if f.Token != "full" || f.Name != "Door" || *f.Pan != 0.1 || *f.Tilt != 0.2 || *f.Zoom != 0.3 {
		t.Errorf("full = %+v", f)
	}
	z := got.Presets[2]
	if z.Pan != nil || z.Tilt != nil || *z.Zoom != 0.5 {
		t.Errorf("zoom-only = %+v", z)
	}
	if len(got.Presets) != 5 || got.Presets[1].Token != "none" || got.Presets[4].Token != "empty" {
		t.Errorf("order/length wrong: %+v", got.Presets)
	}
}

func TestLimitsForHandlesEveryMissingHop(t *testing.T) {
	r := func(lo, hi float64) *onvif.FloatRange { return &onvif.FloatRange{Min: lo, Max: hi} }
	nilCases := map[string]*onvif.PTZConfiguration{
		"nil config":            nil,
		"empty config":          {},
		"pan/tilt, no range":    {PanTiltLimits: &onvif.PanTiltLimits{}},
		"zoom, no range":        {ZoomLimits: &onvif.ZoomLimits{}},
		"range, no axes":        {PanTiltLimits: &onvif.PanTiltLimits{Range: &onvif.Space2DDescription{}}, ZoomLimits: &onvif.ZoomLimits{Range: &onvif.Space1DDescription{}}},
		"non-finite everywhere": {PanTiltLimits: &onvif.PanTiltLimits{Range: &onvif.Space2DDescription{XRange: r(math.NaN(), 1), YRange: r(0, math.Inf(1))}}},
	}
	for name, cfg := range nilCases {
		if got := limitsFor(cfg); got != nil {
			t.Errorf("%s: got %+v, want nil (an empty Limits would serialise as {})", name, got)
		}
	}

	got := limitsFor(&onvif.PTZConfiguration{
		PanTiltLimits: &onvif.PanTiltLimits{Range: &onvif.Space2DDescription{XRange: r(-1, 1), YRange: r(-0.5, 0.25)}},
		ZoomLimits:    &onvif.ZoomLimits{Range: &onvif.Space1DDescription{XRange: r(0, 0.75)}},
	})
	want := &Limits{Pan: &Range{-1, 1}, Tilt: &Range{-0.5, 0.25}, Zoom: &Range{0, 0.75}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v %+v %+v", got.Pan, got.Tilt, got.Zoom)
	}

	// One reported axis does not invent the others.
	only := limitsFor(&onvif.PTZConfiguration{ZoomLimits: &onvif.ZoomLimits{Range: &onvif.Space1DDescription{XRange: r(0, 1)}}})
	if only == nil || only.Pan != nil || only.Tilt != nil || only.Zoom == nil {
		t.Errorf("zoom only = %+v", only)
	}
	panOnly := limitsFor(&onvif.PTZConfiguration{PanTiltLimits: &onvif.PanTiltLimits{Range: &onvif.Space2DDescription{XRange: r(-2, 2)}}})
	if panOnly == nil || panOnly.Tilt != nil || panOnly.Pan == nil || *panOnly.Pan != (Range{-2, 2}) {
		t.Errorf("pan only = %+v", panOnly)
	}

	if rangeOf(nil) != nil {
		t.Error("rangeOf(nil) must be nil")
	}
	if g := rangeOf(r(-3, 4)); g == nil || g.Min != -3 || g.Max != 4 {
		t.Errorf("rangeOf = %+v", g)
	}
}

func TestFindProfileAndConfigTokenFor(t *testing.T) {
	ps := []*onvif.Profile{
		nil,
		{Token: "a", PTZConfiguration: &onvif.PTZConfiguration{Token: "cfg-a"}},
		{Token: "b"},
		{Token: "c", PTZConfiguration: &onvif.PTZConfiguration{}},
		{Token: "d", PTZConfiguration: &onvif.PTZConfiguration{Token: "cfg-d"}},
	}
	if p := findProfile(ps, "d"); p == nil || p.Token != "d" {
		t.Errorf("findProfile(d) = %+v", p)
	}
	if findProfile(ps, "zz") != nil || findProfile(nil, "a") != nil {
		t.Error("a missing profile must be nil")
	}
	for tok, want := range map[string]string{"a": "cfg-a", "b": "", "c": "", "d": "cfg-d", "zz": ""} {
		if got := configTokenFor(ps, tok); got != want {
			t.Errorf("configTokenFor(%s) = %q, want %q", tok, got, want)
		}
	}
}

func TestServicesOfSortsDedupesAndSkipsEmpty(t *testing.T) {
	svc := func(ns string) *onvif.Service { return &onvif.Service{Namespace: ns} }
	list, total, trunc := servicesOf([]*onvif.Service{svc("urn:z"), nil, svc(""), svc("urn:a"), svc("urn:z"), svc("urn:m")})
	if !reflect.DeepEqual(list, []string{"urn:a", "urn:m", "urn:z"}) || total != 3 || trunc {
		t.Errorf("list=%v total=%d trunc=%v", list, total, trunc)
	}
	empty, total, _ := servicesOf(nil)
	if empty == nil || len(empty) != 0 || total != 0 {
		t.Errorf("nil input must give a non-nil empty list, got %#v", empty)
	}
	if b, _ := json.Marshal(empty); string(b) != "[]" {
		t.Errorf("empty list serialises as %s", b)
	}
	var many []*onvif.Service
	for i := 0; i < maxServices+5; i++ {
		many = append(many, svc("urn:s"+string(rune('A'+i/26))+string(rune('a'+i%26))))
	}
	list, total, trunc = servicesOf(many)
	if len(list) != maxServices || total != maxServices+5 || !trunc {
		t.Errorf("len=%d total=%d trunc=%v", len(list), total, trunc)
	}
}

func TestIdentityOfMapsEveryFieldAndToleratesNil(t *testing.T) {
	var out DescribeData
	identityOf(&out, nil)
	if !reflect.DeepEqual(out, DescribeData{}) {
		t.Errorf("nil info changed the result: %+v", out)
	}
	identityOf(&out, &onvif.DeviceInformation{Manufacturer: "Mf", Model: "Md", FirmwareVersion: "Fw", SerialNumber: "Sn", HardwareID: "Hw"})
	if out.Manufacturer != "Mf" || out.Model != "Md" || out.FirmwareVersion != "Fw" || out.SerialNumber != "Sn" || out.HardwareID != "Hw" {
		t.Errorf("identity = %+v", out)
	}
	identityOf(&out, &onvif.DeviceInformation{Model: "  padded  "})
	if out.Model != "padded" {
		t.Errorf("fields are trimmed: %q", out.Model)
	}
}

func TestStreamURIOfBranches(t *testing.T) {
	for name, tc := range map[string]struct {
		in      *onvif.MediaURI
		msg     string
		hint    string
		mustNot string
	}{
		"nil":         {in: nil, msg: "no stream URI", hint: profilesHint},
		"empty":       {in: &onvif.MediaURI{}, msg: "no stream URI", hint: profilesHint},
		"too long":    {in: &onvif.MediaURI{URI: "rtsp://h/" + strings.Repeat("a", maxURIChars)}, msg: "longer than onvif-mcp accepts"},
		"unparseable": {in: &onvif.MediaURI{URI: "rtsp://u:pw-hunter2@[::1"}, msg: "could not be parsed", mustNot: "hunter2"},
	} {
		data, te := streamURIOf("cam", tc.in)
		if te == nil {
			t.Errorf("%s: want a fault, got %+v", name, data)
			continue
		}
		if te.Code != mcperr.CodeDeviceFault || te.Camera != "cam" || te.Operation != "GetStreamURI" {
			t.Errorf("%s: te = %+v", name, te)
		}
		if !strings.Contains(te.Message, tc.msg) {
			t.Errorf("%s: message = %q", name, te.Message)
		}
		if te.Hint != tc.hint {
			t.Errorf("%s: hint = %q, want %q", name, te.Hint, tc.hint)
		}
		b, _ := json.Marshal(te)
		if tc.mustNot != "" && strings.Contains(string(b), tc.mustNot) {
			t.Errorf("%s: echoed the URI: %s", name, b)
		}
		if data != (StreamURIData{}) {
			t.Errorf("%s: data must be empty on a fault: %+v", name, data)
		}
	}

	data, te := streamURIOf("cam", &onvif.MediaURI{URI: "rtsp://admin:pw@host:554/s?x=1#frag", InvalidAfterConnect: true, InvalidAfterReboot: true}) //nolint:gosec // fake test fixture
	if te != nil {
		t.Fatalf("unexpected fault: %+v", te)
	}
	if strings.Contains(data.URI, "admin") || strings.Contains(data.URI, "pw") || strings.Contains(data.URI, "frag") || !strings.HasPrefix(data.URI, "rtsp://host:554/s") {
		t.Errorf("uri = %q", data.URI)
	}
	if !data.InvalidAfterConnect || !data.InvalidAfterReboot {
		t.Errorf("flags lost: %+v", data)
	}
	plain, _ := streamURIOf("cam", &onvif.MediaURI{URI: "rtsp://h/x"})
	if plain.InvalidAfterConnect || plain.InvalidAfterReboot {
		t.Errorf("flags invented: %+v", plain)
	}
}

func TestWithHintOnlyRewritesNotFound(t *testing.T) {
	if withHint(nil, "h") != nil {
		t.Error("nil must stay nil")
	}
	nf := withHint(&mcperr.ToolError{Code: mcperr.CodeNotFound, Hint: "generic"}, "specific")
	if nf.Hint != "specific" {
		t.Errorf("not_found hint = %q", nf.Hint)
	}
	for _, code := range []mcperr.Code{mcperr.CodeTimeout, mcperr.CodeAuthFailed, mcperr.CodeUnreachable, mcperr.CodeDeviceFault, mcperr.CodeInternal, mcperr.CodeNotSupported} {
		got := withHint(&mcperr.ToolError{Code: code, Hint: "original"}, "specific")
		if got.Hint != "original" {
			t.Errorf("%s: hint overwritten with %q", code, got.Hint)
		}
	}
}

func TestClipBoundsLengthAndKeepsUTF8(t *testing.T) {
	short := strings.Repeat("a", maxTextChars)
	if clip(short) != short {
		t.Error("a string at the limit must be untouched")
	}
	long := clip(strings.Repeat("a", 700))
	if len(long) != maxTextChars+3 || !strings.HasSuffix(long, "...") {
		t.Errorf("len=%d suffix=%q", len(long), long[len(long)-4:])
	}
	// Byte 600 falls inside a three-byte rune: 599 ASCII bytes, then euros.
	tricky := strings.Repeat("a", maxTextChars-1) + strings.Repeat("€", 5)
	got := clip(tricky)
	if !utf8.ValidString(got) {
		t.Errorf("clip split a rune: %q", got[len(got)-8:])
	}
	if len(got) > maxTextChars+3 {
		t.Errorf("len = %d", len(got))
	}
	// And the end-to-end shape: a result built by text() stays valid JSON text.
	if b, err := json.Marshal(text(tricky)); err != nil || !utf8.Valid(b) {
		t.Errorf("marshal: %v", err)
	}
}

func TestJoinWithinReportsWhatItOmits(t *testing.T) {
	parts := []string{"aaaa", "bbbb", "cccc"}
	if got := joinWithin(parts, "; ", 100, 3); got != "aaaa; bbbb; cccc" {
		t.Errorf("all fit: %q", got)
	}
	if got := joinWithin(parts, "; ", 10, 3); got != "aaaa; bbbb; (+1 more; see structured result)" {
		t.Errorf("one omitted: %q", got)
	}
	if got := joinWithin(parts, "; ", 3, 3); got != "(+3 more; see structured result)" {
		t.Errorf("none fit: %q", got)
	}
	// total larger than the parts given (the structured list was itself capped).
	if got := joinWithin(parts, "; ", 100, 10); got != "aaaa; bbbb; cccc; (+7 more; see structured result)" {
		t.Errorf("capped list: %q", got)
	}
}

// Deps.Scope exists so that shutdown does not wait out a slow camera.
func TestScopeFollowsBaseContext(t *testing.T) {
	base, stop := context.WithCancel(context.Background())
	d := Deps{Base: base}
	ctx, cancel := d.Scope(context.Background())
	defer cancel()
	select {
	case <-ctx.Done():
		t.Fatal("scope cancelled before Base")
	case <-time.After(20 * time.Millisecond):
	}
	stop()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("cancelling Base did not cancel the scope")
	}
}

func TestScopeFollowsRequestContextAndToleratesNoBase(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	ctx, cancel := Deps{}.Scope(parent)
	defer cancel()
	cancelParent()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("cancelling the request did not cancel the scope")
	}
	// A live Base never cancels an uncancelled request.
	ctx2, cancel2 := Deps{Base: context.Background()}.Scope(context.Background())
	if ctx2.Err() != nil {
		t.Error("scope cancelled with nothing cancelled")
	}
	cancel2()
	if ctx2.Err() == nil {
		t.Error("the returned cancel must cancel the scope")
	}
}
