package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/mcperr"
)

const soapEnv = `<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>%s</s:Body></s:Envelope>`

// advertising returns a device that answers GetCapabilities with a media
// service at mediaURL and GetProfiles with one empty-ish profile.
func advertising(t *testing.T, mediaURL func() string) *httptest.Server {
	t.Helper()
	return advertisingOn(t, "127.0.0.1:0", mediaURL)
}

func advertisingOn(t *testing.T, addr string, mediaURL func() string) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/soap+xml")
		if strings.Contains(string(raw), "GetCapabilities") {
			_, _ = fmt.Fprintf(w, soapEnv, `<tds:GetCapabilitiesResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:Capabilities>`+
				`<tt:Media xmlns:tt="http://www.onvif.org/ver10/schema"><tt:XAddr>`+mediaURL()+`</tt:XAddr></tt:Media>`+
				`</tds:Capabilities></tds:GetCapabilitiesResponse>`)
			return
		}
		_, _ = fmt.Fprintf(w, soapEnv, `<trt:GetProfilesResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl"><trt:Profiles token="p1"><tt:Name xmlns:tt="http://www.onvif.org/ver10/schema">main</tt:Name></trt:Profiles></trt:GetProfilesResponse>`)
	}))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func profilesVia(t *testing.T, cam *config.Camera) error {
	t.Helper()
	cam.ID = "fx"
	cam.Username, cam.Password = "u", "fixture-pw-1"
	e, err := New(&config.Config{Cameras: map[string]*config.Camera{"fx": cam}}).Get("fx")
	if err != nil {
		t.Fatal(err)
	}
	c, err := e.Client(context.Background())
	if err != nil {
		return err
	}
	_, err = c.GetProfiles(context.Background())
	return err
}

func TestAdvertisedForeignHostIsRefused(t *testing.T) {
	for _, adv := range []string{
		"http://169.254.169.254/latest/meta-data/?k=SECRETTOKEN",
		"http://127.0.0.2:9/x",
		"http://10.1.2.3/onvif/media_service",
		"http://metadata.internal/x",
	} {
		srv := advertising(t, func() string { return adv })
		err := profilesVia(t, &config.Camera{Endpoint: srv.URL + "/onvif/device_service"})
		if !errors.Is(err, mcperr.ErrForeignHost) {
			t.Errorf("%s: err = %v, want ErrForeignHost", adv, err)
			continue
		}
		te := mcperr.FromError(err, "fx", "GetProfiles")
		if te.Code != mcperr.CodeDeviceFault || te.Retryable {
			t.Errorf("%s: code = %s retryable=%v", adv, te.Code, te.Retryable)
		}
		if !strings.Contains(te.Message, "camera advertised a service address on another host") {
			t.Errorf("%s: message = %q", adv, te.Message)
		}
		if strings.Contains(te.Message+te.Hint, "SECRETTOKEN") {
			t.Errorf("%s: advertised query leaked into the payload: %+v", adv, te)
		}
	}
}

func TestAdvertisedSameHostOtherPortIsAllowed(t *testing.T) {
	media := advertising(t, func() string { return "" })
	dev := advertising(t, func() string { return media.URL + "/media" })
	if err := profilesVia(t, &config.Camera{Endpoint: dev.URL + "/onvif/device_service"}); err != nil {
		t.Fatalf("same host, different port must work: %v", err)
	}
}

func TestLoopbackAdvertisementIsRewrittenNotFollowed(t *testing.T) {
	// onvif-go rewrites a loopback XAddr to the configured host; it must keep
	// working and never reach a different host.
	dev := advertising(t, func() string { return "http://localhost:1/media" })
	err := profilesVia(t, &config.Camera{Endpoint: dev.URL + "/onvif/device_service"})
	if err != nil && !errors.Is(err, mcperr.ErrForeignHost) {
		t.Logf("rewritten address answered with %v (acceptable: nothing listens there)", err)
	}
}

func TestTrustAdvertisedHostsDisablesTheCheck(t *testing.T) {
	// The media service listens on a different loopback address: host differs.
	media := advertisingOn(t, "127.0.0.2:0", func() string { return "" })
	dev := advertising(t, func() string { return media.URL + "/media" })

	if err := profilesVia(t, &config.Camera{Endpoint: dev.URL + "/onvif/device_service"}); !errors.Is(err, mcperr.ErrForeignHost) {
		t.Fatalf("default must refuse: %v", err)
	}
	if err := profilesVia(t, &config.Camera{Endpoint: dev.URL + "/onvif/device_service", TrustAdvertisedHosts: true}); err != nil {
		t.Fatalf("trust_advertised_hosts must allow: %v", err)
	}
}

func TestEndpointHostForms(t *testing.T) {
	cases := map[string]string{
		"http://Cam.Example:8080/onvif/x": "cam.example",
		"192.0.2.10":                      "192.0.2.10",
		"192.0.2.10:8080":                 "192.0.2.10",
		"https://[2001:db8::1]:443/x":     "2001:db8::1",
		"[2001:db8::1]":                   "2001:db8::1",
	}
	for in, want := range cases {
		if got := endpointHost(in); got != want {
			t.Errorf("endpointHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func oversized(t *testing.T, chunked bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/soap+xml")
		const total = 20 << 20
		if !chunked {
			w.Header().Set("Content-Length", fmt.Sprint(total))
		}
		chunk := []byte(strings.Repeat("A", 32<<10))
		for sent := 0; sent < total; sent += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestOversizedResponseIsBounded(t *testing.T) {
	for _, chunked := range []bool{true, false} {
		srv := oversized(t, chunked)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		err := profilesVia(t, &config.Camera{Endpoint: srv.URL + "/onvif/device_service"})
		runtime.ReadMemStats(&after)
		if !errors.Is(err, mcperr.ErrResponseTooLarge) {
			t.Fatalf("chunked=%v: err = %v, want ErrResponseTooLarge", chunked, err)
		}
		te := mcperr.FromError(err, "fx", "Initialize")
		if te.Code != mcperr.CodeDeviceFault || !strings.Contains(te.Message, "camera response too large") {
			t.Errorf("chunked=%v: %+v", chunked, te)
		}
		if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
			t.Errorf("chunked=%v: allocated %d MiB for a 20 MiB body", chunked, grew>>20)
		}
	}
}

func TestResponseJustUnderTheLimitPasses(t *testing.T) {
	old := MaxResponseBytes
	MaxResponseBytes = 1 << 20
	t.Cleanup(func() { MaxResponseBytes = old })
	media := advertising(t, func() string { return "" })
	dev := advertising(t, func() string { return media.URL + "/media" })
	if err := profilesVia(t, &config.Camera{Endpoint: dev.URL + "/onvif/device_service"}); err != nil {
		t.Fatalf("small replies must pass: %v", err)
	}
}
