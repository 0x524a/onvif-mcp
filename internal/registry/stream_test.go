package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/0x524a/onvif-mcp/internal/config"
)

//nolint:gosec // test fixture
const nastyPass = "p@ss:w/o?r#d x%41&+"

func streamEntry(cam config.Camera) Entry {
	if cam.Endpoint == "" {
		cam.Endpoint = "http://192.0.2.10:8080/onvif/device_service"
	}
	if cam.Username == "" {
		cam.Username = "operator"
	}
	if cam.Password == "" {
		cam.Password = nastyPass
	}
	r := New(&config.Config{Cameras: map[string]*config.Camera{"c": &cam}})
	e, _ := r.Get("c")
	return *e
}

func refusalKind(t *testing.T, err error) StreamRefusalKind {
	t.Helper()
	var r *StreamRefusal
	if !errors.As(err, &r) {
		t.Fatalf("want *StreamRefusal, got %v", err)
	}
	return r.Kind
}

func TestPrepareStreamInjectsOnlyForTheConfiguredHost(t *testing.T) {
	e := streamEntry(config.Camera{})
	sp, err := e.PrepareStream("rtsp://192.0.2.10:554/s1?x=1#frag")
	if err != nil {
		t.Fatal(err)
	}
	if !sp.Authenticated() {
		t.Error("credentials were not injected for the configured host")
	}
	got := sp.CredentialedURL()
	if !strings.HasPrefix(got, "rtsp://operator:") || !strings.Contains(got, "@192.0.2.10:554/s1?x=1") || strings.Contains(got, "frag") {
		t.Errorf("unexpected url shape: %s", got)
	}
	if d := sp.Display(); d != "rtsp://192.0.2.10:554/s1" {
		t.Errorf("display = %q, want host, port and path only", d)
	}
}

func TestPrepareStreamEncodesSpecialCharactersAndRoundTrips(t *testing.T) {
	for _, pass := range []string{"p@ss", "a:b", "a/b", "a?b", "a#b", "a b", "100%", nastyPass, "ünï"} {
		e := streamEntry(config.Camera{Password: pass})
		sp, err := e.PrepareStream("rtsp://192.0.2.10/s")
		if err != nil {
			t.Fatalf("%q: %v", pass, err)
		}
		u := sp.CredentialedURL()
		if i := strings.Index(u, "@"); i < 0 || strings.Count(u, "@") != 1 {
			t.Errorf("%q: want exactly one @ in %s", pass, u)
		}
		if strings.Count(u, "#")+strings.Count(u, "?") != 0 || strings.Contains(u, " ") {
			t.Errorf("%q: unescaped delimiter in %s", pass, u)
		}
	}
}

func TestPrepareStreamDropsCameraUserinfo(t *testing.T) {
	e := streamEntry(config.Camera{})
	sp, err := e.PrepareStream("rtsp://evil:hunter2@192.0.2.10/s")
	if err != nil {
		t.Fatal(err)
	}
	u := sp.CredentialedURL()
	if strings.Contains(u, "evil") || strings.Contains(u, "hunter2") {
		t.Errorf("camera userinfo survived: %s", u)
	}
	if !strings.HasPrefix(u, "rtsp://operator:") {
		t.Errorf("configured credentials missing: %s", u)
	}
}

func TestPrepareStreamForeignHostIsRefusedWithoutTrust(t *testing.T) {
	e := streamEntry(config.Camera{})
	for _, raw := range []string{
		"rtsp://192.0.2.11/s", "rtsp://evil.example/s", "rtsp://user@evil.example/s",
		"rtsp://192.0.2.10@evil.example/s", "rtsp://evil.example@192.0.2.10.evil.example/s",
		"rtsp://127.0.0.1/s", "rtsps://10.0.0.1:8554/s", "rtsp://[::1]/s",
	} {
		_, err := e.PrepareStream(raw)
		if err == nil {
			t.Errorf("%s: want a refusal", raw)
			continue
		}
		if k := refusalKind(t, err); k != RefusedForeignHost {
			t.Errorf("%s: kind = %v, want foreign host", raw, k)
		}
		if strings.Contains(err.Error(), "evil") || strings.Contains(err.Error(), "192.0.2") {
			t.Errorf("%s: refusal echoes the address: %v", raw, err)
		}
	}
}

func TestPrepareStreamHostComparisonMatchesTheAdvertisedHostGuard(t *testing.T) {
	e := streamEntry(config.Camera{Endpoint: "http://Cam.Example.:80/onvif"})
	for _, raw := range []string{"rtsp://cam.example/s", "rtsp://CAM.EXAMPLE:8554/s", "rtsp://cam.example./s"} {
		sp, err := e.PrepareStream(raw)
		if err != nil || !sp.Authenticated() {
			t.Errorf("%s: err=%v authenticated=%v", raw, err, sp.Authenticated())
		}
	}
	e6 := streamEntry(config.Camera{Endpoint: "http://[2001:db8::1]/d"})
	if _, err := e6.PrepareStream("rtsp://[2001:0db8:0:0:0:0:0:1]/s"); err != nil {
		t.Errorf("textual IPv6 variant refused: %v", err)
	}
}

func TestPrepareStreamTrustedForeignHostGetsNoCredentials(t *testing.T) {
	e := streamEntry(config.Camera{TrustAdvertisedHosts: true})
	sp, err := e.PrepareStream("rtsp://user:pw@198.51.100.7:8554/s")
	if err != nil {
		t.Fatal(err)
	}
	if sp.Authenticated() {
		t.Error("foreign host must never receive credentials")
	}
	u := sp.CredentialedURL()
	if strings.Contains(u, "@") || strings.Contains(u, "operator") || strings.Contains(u, "pw") {
		t.Errorf("foreign probe url carries userinfo: %s", u)
	}
}

func TestPrepareStreamNeverProbesDangerousTargetsEvenWithTrust(t *testing.T) {
	e := streamEntry(config.Camera{TrustAdvertisedHosts: true})
	for _, raw := range []string{
		"rtsp://169.254.169.254/latest", "rtsp://0.0.0.0/s", "rtsp://[::]/s", "rtsp://224.0.0.1/s",
		"rtsp://[ff02::1]/s", "rtsp://[fe80::1]/s", "rtsp://[fe80::1%25eth0]/s", "rtsp://[::ffff:169.254.169.254]/s",
		"rtsp://2852039166/s", "rtsp://0xa9fea9fe/s", "rtsp://169.254.169.254.:554/s", "rtsp://0251.0376.0251.0376/s",
	} {
		_, err := e.PrepareStream(raw)
		if err == nil {
			t.Errorf("%s: want a refusal even with trust_advertised_hosts", raw)
			continue
		}
		if k := refusalKind(t, err); k != RefusedBlockedAddress {
			t.Errorf("%s: kind = %v, want blocked address", raw, k)
		}
	}
}

func TestPrepareStreamMalformedTargets(t *testing.T) {
	e := streamEntry(config.Camera{TrustAdvertisedHosts: true})
	long := "rtsp://192.0.2.10/" + strings.Repeat("a", 3000)
	for _, raw := range []string{
		"", "http://192.0.2.10/s", "file:///etc/passwd", "rtsp:///s", "rtsp://", "192.0.2.10/s", "rtsp:192.0.2.10",
		"rtsp://192.0.2.10:0/s", "rtsp://192.0.2.10:65536/s", "rtsp://192.0.2.10:99999/s", "rtsp://192.0.2.10:-1/s",
		"rtsp://192.0.2.10:abc/s", "rtsp://[bad/s", "rtsp://a b/s", "rtsp://192.0.2.10/\x00", "rtsp://\x7f/s", long,
		"rtsp://evil\\@192.0.2.10/s",
	} {
		_, err := e.PrepareStream(raw)
		if err == nil {
			t.Errorf("%q: want a refusal", raw)
			continue
		}
		if k := refusalKind(t, err); k != RefusedMalformed {
			t.Errorf("%q: kind = %v, want malformed", raw, k)
		}
	}
	for _, port := range []string{"1", "554", "65535"} {
		if _, err := e.PrepareStream("rtsp://192.0.2.10:" + port + "/s"); err != nil {
			t.Errorf("port %s refused: %v", port, err)
		}
	}
}

func TestPrepareStreamNoUsernameMeansNoInjection(t *testing.T) {
	r := New(&config.Config{Cameras: map[string]*config.Camera{"a": {Endpoint: "http://192.0.2.10/d"}}})
	ea, _ := r.Get("a")
	sp, err := ea.PrepareStream("rtsp://192.0.2.10/s")
	if err != nil || sp.Authenticated() || strings.Contains(sp.CredentialedURL(), "@") {
		t.Errorf("anonymous camera: err=%v url=%s", err, sp.CredentialedURL())
	}
}

func TestStreamProbeIsNotPrintable(t *testing.T) {
	e := streamEntry(config.Camera{})
	sp, err := e.PrepareStream("rtsp://192.0.2.10/s")
	if err != nil {
		t.Fatal(err)
	}
	spp := &sp
	var outs []string
	for _, v := range []any{sp, spp, []StreamProbe{sp}, map[string]StreamProbe{"k": sp}, struct{ P StreamProbe }{sp}, struct{ P *StreamProbe }{spp}} {
		for _, f := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
			outs = append(outs, fmt.Sprintf(f, v))
		}
		b, _ := json.Marshal(v)
		outs = append(outs, string(b))
	}
	var sb strings.Builder
	slog.New(slog.NewJSONHandler(&sb, nil)).Info("m", "probe", sp, "ptr", spp)
	slog.New(slog.NewTextHandler(&sb, nil)).Info("m", "probe", sp, "ptr", spp)
	outs = append(outs, sb.String(), sp.String(), sp.GoString())
	if b, err := sp.MarshalText(); err == nil {
		outs = append(outs, string(b))
	}
	for _, o := range outs {
		for _, leak := range []string{nastyPass, "operator", "p%40ss", "192.0.2.10"} {
			if strings.Contains(o, leak) {
				t.Errorf("printed %q in %q", leak, o)
			}
		}
	}
}

func TestStreamProbeScrubRemovesEveryFormOfTheSecret(t *testing.T) {
	e := streamEntry(config.Camera{})
	sp, _ := e.PrepareStream("rtsp://192.0.2.10/s")
	u := sp.CredentialedURL()
	for _, s := range []string{
		"dial " + u + " failed", "bad pass " + nastyPass, "got operator:" + nastyPass + "@host",
		"enc " + u[len("rtsp://"):strings.Index(u, "@")],
	} {
		out := sp.Scrub(s)
		if strings.Contains(out, nastyPass) || strings.Contains(out, "p%40ss") || strings.Contains(out, u) {
			t.Errorf("Scrub(%q) = %q", s, out)
		}
	}
}
