package tools

import (
	"net/http"
	"strings"
	"testing"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/redact"
)

// keep-userinfo: user:pass@host in the camera-supplied address must never be sent.
func TestSnapshotUserinfoInAddressIsNotSent(t *testing.T) {
	var gotAuth, gotUser string
	srv := snapServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.User != nil {
			gotUser = r.URL.User.String()
		}
		_, _ = w.Write(jpegImage(t, 8, 8))
	})
	uri := strings.Replace(srv.URL, "http://", "http://evil:s3cret@", 1) + "/s"
	res := snap(t, snapSession(t, uri, config.Camera{}, nil).cs, nil)
	dataMap(t, res)
	if gotAuth != "" || gotUser != "" {
		t.Errorf("userinfo reached the server: Authorization=%q user=%q", gotAuth, gotUser)
	}
}

// side-bound-off-by-one: 16384 on a side is the largest allowed.
func TestSnapshotSideBoundaryIsInclusive(t *testing.T) {
	srv := snapServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jpegWithDims(t, 16384, 1)) })
	d := dataMap(t, snap(t, snapSession(t, srv.URL+"/s", config.Camera{}, nil).cs, nil))
	if d["width"] != float64(16384) {
		t.Errorf("data = %v", d)
	}
}

// authunsupported-code: a scheme we cannot answer is auth_failed at the tool.
func TestSnapshotUnsupportedAuthSchemeIsAuthFailed(t *testing.T) {
	srv := snapServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", "Negotiate")
		w.WriteHeader(401)
	})
	res := snap(t, snapSession(t, srv.URL+"/s", config.Camera{}, nil).cs, nil)
	hint := wantFault(t, res, "auth_failed", "")
	if !strings.Contains(hint, "Basic and Digest") {
		t.Errorf("hint = %q", hint)
	}
}

// no-register-secret: after credentials were sent, the password is covered by Scrub.
func TestSnapshotRegistersThePasswordWithTheRedactor(t *testing.T) {
	const pw = "Zq83-unique-pw-p10"
	srv := snapServer(t, func(w http.ResponseWriter, r *http.Request) {
		if _, p, ok := r.BasicAuth(); !ok || p != pw {
			w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write(jpegImage(t, 8, 8))
	})
	dataMap(t, snap(t, snapSession(t, srv.URL+"/s", config.Camera{Password: pw}, nil).cs, nil))
	if strings.Contains(redact.Scrub("x "+pw+" y"), pw) {
		t.Error("password is not covered by redact.Scrub after an authenticated fetch")
	}
}

// no-finishText + no-sanitise-profile-text: error text from the camera is sanitised.
func TestSnapshotErrorTextFromCameraIsSanitised(t *testing.T) {
	fx := faultFixture(t, "snapshot not supported ‮evil")
	res := snap(t, snapSessionOn(t, fx, config.Camera{}, nil).cs, nil)
	wantFault(t, res, "not_supported", "")
	if strings.Contains(wire(t, res), "\\u202e") || strings.Contains(wire(t, res), "‮") {
		t.Errorf("bidi override survived: %s", wire(t, res))
	}
}
