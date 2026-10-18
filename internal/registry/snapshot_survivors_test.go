package registry

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/0x524a/onvif-mcp/internal/config"
)

// no-hard-limit-bound: a limit above the hard bound is refused before any request.
func TestSnapshotLimitAboveHardBoundSendsNothing(t *testing.T) {
	var l reqLog
	addr, conns := listen127(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { l.note(r); _, _ = w.Write(testJPEG(t, 8, 8)) }))
	e := snapEntry(config.Camera{Endpoint: "http://" + addr + "/device_service"})
	for _, lim := range []int64{0, -1, 64<<20 + 1} {
		if _, err := fetch(t, e, "http://"+addr+"/s", lim); err == nil {
			t.Errorf("limit %d accepted", lim)
		}
	}
	if conns.Load() != 0 || l.count() != 0 {
		t.Errorf("a request was sent")
	}
}

// proxy-from-env: HTTP_PROXY must not divert a snapshot request. Go never proxies
// loopback, so use a name that the test resolver maps to 127.0.0.1.
func TestSnapshotIgnoresProxyEnvironment(t *testing.T) {
	var proxied, direct reqLog
	paddr, _ := listen127(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxied.note(r); w.WriteHeader(502) }))
	daddr, _ := listen127(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { direct.note(r); _, _ = w.Write(testJPEG(t, 8, 8)) }))
	t.Setenv("HTTP_PROXY", "http://"+paddr)
	t.Setenv("http_proxy", "http://"+paddr)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	old := lookupHost
	lookupHost = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	t.Cleanup(func() { lookupHost = old })
	_, port, _ := net.SplitHostPort(daddr)
	e := snapEntry(config.Camera{Endpoint: "http://cam.example.test:" + port + "/device_service"})
	if _, err := e.FetchSnapshot(context.Background(), "http://cam.example.test:"+port+"/s", 1<<20, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if proxied.count() != 0 || direct.count() != 1 {
		t.Errorf("proxied=%d direct=%d", proxied.count(), direct.count())
	}
}
