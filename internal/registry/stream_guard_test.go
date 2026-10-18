package registry

import (
	"strings"
	"testing"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/redact"
)

func TestStreamDisplayDropsCameraUserinfo(t *testing.T) {
	e := streamEntry(config.Camera{})
	sp, err := e.PrepareStream("rtsp://attacker:their-pass@192.0.2.10:554/s1")
	if err != nil {
		t.Fatal(err)
	}
	if d := sp.Display(); d != "rtsp://192.0.2.10:554/s1" {
		t.Errorf("display = %q", d)
	}
}

func TestStreamZeroValuesDoNotPanic(t *testing.T) {
	if _, err := (Entry{}).PrepareStream("rtsp://h/s"); refusalKind(t, err) != RefusedMalformed {
		t.Error("zero Entry must refuse as malformed")
	}
	var sp StreamProbe
	if sp.CredentialedURL() != "" || sp.Display() != "" || sp.Authenticated() || sp.Scrub("x") != "x" {
		t.Error("zero StreamProbe must be inert")
	}
}

func TestStreamNeverProbedAddresses(t *testing.T) {
	e := streamEntry(config.Camera{TrustAdvertisedHosts: true})
	for _, h := range []string{
		"[::ffff:0.0.0.0]", "[::ffff:255.255.255.255]", "[::ffff:169.254.169.254]", "[::ffff:224.0.0.1]",
		"239.255.255.250", "255.255.255.255", "0.0.0.1", "[ff0e::1]", "169.254.169.254.",
	} {
		_, err := e.PrepareStream("rtsp://" + h + ":554/s")
		if err == nil || refusalKind(t, err) != RefusedBlockedAddress {
			t.Errorf("%s: err=%v, want RefusedBlockedAddress", h, err)
		}
	}
}

func TestPrepareStreamRegistersThePassword(t *testing.T) {
	const pw = "Zz-proof-pw-77" //nolint:gosec // fixed test secret, not a credential
	e := streamEntry(config.Camera{Password: pw})
	if _, err := e.PrepareStream("rtsp://192.0.2.10/s"); err != nil {
		t.Fatal(err)
	}
	if got := redact.Scrub("prose " + pw + " prose"); strings.Contains(got, pw) {
		t.Errorf("password not registered: %q", got)
	}
}

func TestStreamProbeScrubAlsoAppliesGeneralRedaction(t *testing.T) {
	e := streamEntry(config.Camera{})
	sp, _ := e.PrepareStream("rtsp://192.0.2.10/s")
	if got := sp.Scrub("dial rtsp://other:secretpw99@elsewhere/x failed"); strings.Contains(got, "secretpw99") {
		t.Errorf("foreign userinfo survives: %q", got)
	}
}
