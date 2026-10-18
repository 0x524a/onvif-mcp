package registry

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"testing"

	"github.com/0x524a/onvif-mcp/internal/config"
)

func basicServer(t *testing.T, l *reqLog) string {
	t.Helper()
	addr, _ := listen127(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.note(r)
		if _, _, ok := r.BasicAuth(); !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write(testJPEG(t, 4, 4))
	}))
	return addr
}

// An https-configured camera that advertises an http snapshot address never
// gets its credentials: the request is refused before anything is sent.
func TestSnapshotSchemeDowngradeIsRefusedWithoutAnyRequest(t *testing.T) {
	var l reqLog
	addr := basicServer(t, &l)
	e := snapEntry(config.Camera{Endpoint: "https://127.0.0.1:443/onvif/device_service", AllowBasicOverHTTP: true})
	_, err := fetch(t, e, "http://"+addr+"/s", 1<<20)
	var ref *SnapshotRefusal
	if !errors.As(err, &ref) || ref.Kind != RefusedSnapshotSchemeDowngrade {
		t.Fatalf("err = %v, want a scheme-downgrade refusal", err)
	}
	if l.count() != 0 {
		t.Errorf("%d request(s) sent, want none", l.count())
	}
}

func TestSnapshotHTTPSEndpointHTTPSSnapshotStillAuthenticates(t *testing.T) {
	// https snapshot on a TLS server is covered by the tools tests; here only
	// the policy: https to https is not a downgrade.
	e := snapEntry(config.Camera{Endpoint: "https://127.0.0.1/onvif/device_service"})
	_, err := fetch(t, e, "https://127.0.0.1:1/s", 1<<20)
	var ref *SnapshotRefusal
	if errors.As(err, &ref) {
		t.Fatalf("https to https was refused: %v", err)
	}
}

func TestSnapshotBasicOverHTTPRefusedUnlessAllowed(t *testing.T) {
	var l reqLog
	addr := basicServer(t, &l)
	_, err := fetch(t, snapEntryStrict(config.Camera{}), "http://"+addr+"/s", 1<<20)
	if se := snapErr(t, err); se.Kind != SnapshotBasicOverHTTP {
		t.Fatalf("kind = %v, want SnapshotBasicOverHTTP", se.Kind)
	}
	if l.count() != 1 || l.anyAuth() {
		t.Errorf("requests=%d anyAuth=%v: the password must not be sent", l.count(), l.anyAuth())
	}

	var l2 reqLog
	addr2 := basicServer(t, &l2)
	got, err := fetch(t, snapEntryStrict(config.Camera{AllowBasicOverHTTP: true}), "http://"+addr2+"/s", 1<<20)
	if err != nil || !got.Authenticated {
		t.Fatalf("opted-in Basic over http: err=%v", err)
	}
}

func TestSnapshotDigestOverHTTPNeedsNoOptIn(t *testing.T) {
	var l reqLog
	addr := digestServer(t, &l, testJPEG(t, 8, 8), true)
	if _, err := fetch(t, snapEntryStrict(config.Camera{}), "http://"+addr+"/s", 1<<20); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotTrailingDotHostIsNotTheConfiguredHost(t *testing.T) {
	var l reqLog
	addr, _ := listen127(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.note(r)
		w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
		w.WriteHeader(401)
	}))
	_, port, _ := splitHP(addr)
	old := lookupHost
	lookupHost = func(_ context.Context, h string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	t.Cleanup(func() { lookupHost = old })
	e := snapEntry(config.Camera{Endpoint: "http://nvr/onvif/device_service", AllowBasicOverHTTP: true})
	_, err := fetch(t, e, "http://NVR.:"+port+"/s", 1<<20)
	var ref *SnapshotRefusal
	if !errors.As(err, &ref) || ref.Kind != RefusedSnapshotForeignHost {
		t.Fatalf("err = %v, want foreign-host refusal", err)
	}
	if l.count() != 0 {
		t.Errorf("%d request(s) sent", l.count())
	}
	// The same spelling on both sides is the same host.
	e = snapEntry(config.Camera{Endpoint: "http://nvr./onvif/device_service", AllowBasicOverHTTP: true})
	if _, err := fetch(t, e, "http://nvr.:"+port+"/s", 1<<20); snapErrKind(err) != SnapshotCredentialsRejected {
		t.Errorf("dotted on both sides: err = %v", err)
	}
}

func snapErrKind(err error) SnapshotFailure {
	var se *SnapshotError
	if errors.As(err, &se) {
		return se.Kind
	}
	return 0
}

func splitHP(a string) (string, string, error) {
	for i := len(a) - 1; i >= 0; i-- {
		if a[i] == ':' {
			return a[:i], a[i+1:], nil
		}
	}
	return a, "", errors.New("no port")
}
