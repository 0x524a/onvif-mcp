package tools

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/0x524a/onvif-go/discovery"
)

func announce(n int, addr func(i int) string) []*discovery.Device {
	out := make([]*discovery.Device, n)
	for i := range out {
		out[i] = &discovery.Device{EndpointRef: fmt.Sprintf("urn:uuid:%04d", i), XAddrs: []string{addr(i)}}
	}
	return out
}

func xaddrsOf(c any) []string {
	var out []string
	for _, x := range c.(map[string]any)["xaddrs"].([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestDiscoverCapsCandidatesAndSaysSo(t *testing.T) {
	f := &fakeDisc{devs: announce(100, func(i int) string { return fmt.Sprintf("http://10.0.%d.%d/s", i/200, i%200+1) })}
	res := call(t, discoverSession(t, f), "camera.discover", nil)
	d := dataMap(t, res)
	if n := len(d["candidates"].([]any)); n != 64 {
		t.Errorf("candidates = %d, want 64", n)
	}
	if d["truncated"] != true || d["total"] != float64(100) {
		t.Errorf("truncated=%v total=%v, want true/100", d["truncated"], d["total"])
	}
	if !strings.Contains(textOf(res), "64 of 100") {
		t.Errorf("text must say the list is partial: %q", textOf(res))
	}
	if !strings.Contains(d["note"].(string), "crowd") {
		t.Errorf("note must warn that announcements can crowd out real cameras: %v", d["note"])
	}
}

func TestDiscoverUnderTheCapIsNotTruncated(t *testing.T) {
	f := &fakeDisc{devs: announce(3, func(i int) string { return fmt.Sprintf("http://10.0.0.%d/s", i+1) })}
	d := dataMap(t, call(t, discoverSession(t, f), "camera.discover", nil))
	if d["truncated"] != false || d["total"] != float64(3) {
		t.Errorf("truncated=%v total=%v", d["truncated"], d["total"])
	}
}

// A flood of low-address fakes must not push an on-link camera out of the cap.
func TestDiscoverCapPrefersOnLinkOverLexicalOrder(t *testing.T) {
	old := onLink
	onLink = func(ip net.IP) bool { return ip.Equal(net.ParseIP("192.0.2.50")) }
	t.Cleanup(func() { onLink = old })
	devs := announce(300, func(i int) string { return fmt.Sprintf("http://10.0.%d.%d/s", i/200, i%200+1) })
	devs = append(devs, &discovery.Device{EndpointRef: "urn:uuid:real", XAddrs: []string{"http://192.0.2.50/onvif/device_service"}})
	d := dataMap(t, call(t, discoverSession(t, &fakeDisc{devs: devs}), "camera.discover", nil))
	found := false
	for _, c := range d["candidates"].([]any) {
		if xaddrsOf(c)[0] == "http://192.0.2.50/onvif/device_service" {
			found = true
		}
	}
	if !found {
		t.Error("the on-link camera was crowded out by lexically lower fakes")
	}
	if d["truncated"] != true {
		t.Error("the cap was hit and must be signalled")
	}
}

func TestDiscoverSpecialAddressesRankLastAndSnippetUsesTheBest(t *testing.T) {
	f := &fakeDisc{devs: []*discovery.Device{{EndpointRef: "urn:uuid:a", XAddrs: []string{
		"http://127.0.0.1/a", "http://169.254.169.254/b", "http://localhost/c", "http://[::1]/d", "http://192.0.2.9/real",
	}}}}
	d := dataMap(t, call(t, discoverSession(t, f), "camera.discover", nil))
	c := d["candidates"].([]any)[0]
	xs := xaddrsOf(c)
	if len(xs) != 4 {
		t.Fatalf("xaddrs = %v, want 4", xs)
	}
	if xs[0] != "http://192.0.2.9/real" {
		t.Errorf("a real address must come first, got %v", xs)
	}
	if snip := c.(map[string]any)["config_snippet"].(string); !strings.Contains(snip, "192.0.2.9") {
		t.Errorf("snippet must use the best address: %s", snip)
	}
	if d["xaddrs_dropped"] != float64(1) {
		t.Errorf("xaddrs_dropped = %v, want 1", d["xaddrs_dropped"])
	}
}

// Junk announced first must not push the real address out of the cap: the cap
// applies after validation.
func TestDiscoverCapsXAddrsAfterValidity(t *testing.T) {
	f := &fakeDisc{devs: []*discovery.Device{{EndpointRef: "urn:uuid:a", XAddrs: []string{
		"ftp://h/1", "file:///x", "http://", "javascript:alert(1)", "ftp://h/2", "http://10.0.0.1/real",
	}}}}
	d := dataMap(t, call(t, discoverSession(t, f), "camera.discover", nil))
	cands := d["candidates"].([]any)
	if len(cands) != 1 || xaddrsOf(cands[0])[0] != "http://10.0.0.1/real" {
		t.Fatalf("junk first must not hide the real address: %v", d)
	}
}

func TestDiscoverLimitsPerDevice(t *testing.T) {
	var xs, scopes []string
	for i := 0; i < 10; i++ {
		xs = append(xs, fmt.Sprintf("http://10.0.0.%d/s", i+1))
	}
	for i := 0; i < 50; i++ {
		scopes = append(scopes, fmt.Sprintf("onvif://www.onvif.org/name/%d", i))
	}
	scopes = append(scopes, "   ", "\x1b\x00")
	f := &fakeDisc{devs: []*discovery.Device{{EndpointRef: "urn:uuid:a", XAddrs: xs, Scopes: scopes}}}
	d := dataMap(t, call(t, discoverSession(t, f), "camera.discover", nil))
	c := d["candidates"].([]any)[0].(map[string]any)
	if n := len(c["xaddrs"].([]any)); n != 4 {
		t.Errorf("xaddrs = %d, want 4", n)
	}
	if n := len(c["scopes"].([]any)); n != 16 {
		t.Errorf("scopes = %d, want 16", n)
	}
	if d["xaddrs_dropped"] != float64(6) {
		t.Errorf("xaddrs_dropped = %v, want 6", d["xaddrs_dropped"])
	}
}

func TestDiscoverIgnoresUnusableAnnouncements(t *testing.T) {
	f := &fakeDisc{devs: []*discovery.Device{
		{EndpointRef: "a", XAddrs: []string{"ftp://h/x"}},
		{EndpointRef: "b", XAddrs: []string{"file:///x"}},
		{EndpointRef: "c", XAddrs: []string{"http://"}},
		{EndpointRef: "d", XAddrs: []string{"http://h/" + strings.Repeat("a", 3000)}},
		{EndpointRef: "e", XAddrs: []string{"http://" + strings.Repeat("a", 300) + ".example/x"}},
		{EndpointRef: "f", XAddrs: []string{"http://10.0.0.1/ok"}},
	}}
	d := dataMap(t, call(t, discoverSession(t, f), "camera.discover", nil))
	if n := len(d["candidates"].([]any)); n != 1 {
		t.Errorf("candidates = %d, want 1", n)
	}
	if d["ignored"] != float64(5) {
		t.Errorf("ignored = %v, want 5", d["ignored"])
	}
}

func TestDiscoverIsDeterministicWhateverTheArrivalOrder(t *testing.T) {
	a := []*discovery.Device{
		{EndpointRef: "r1", XAddrs: []string{"http://10.0.0.2/b", "http://10.0.0.1/a"}},
		{EndpointRef: "r2", XAddrs: []string{"http://10.0.0.1/a", "http://10.0.0.2/b"}}, // same set: collapses
		{EndpointRef: "r3", XAddrs: []string{"http://10.0.0.1/a", "http://10.0.0.3/c"}}, // shares the first only
		{EndpointRef: "r4", XAddrs: []string{"http://10.0.0.1/a", "http://10.0.0.1/a"}}, // duplicate within a device
	}
	b := []*discovery.Device{a[3], a[2], a[1], a[0]}
	da := dataMap(t, call(t, discoverSession(t, &fakeDisc{devs: a}), "camera.discover", nil))
	db := dataMap(t, call(t, discoverSession(t, &fakeDisc{devs: b}), "camera.discover", nil))
	ca, cb := da["candidates"].([]any), db["candidates"].([]any)
	if len(ca) != 3 || len(cb) != 3 {
		t.Fatalf("want 3 distinct candidates, got %d and %d", len(ca), len(cb))
	}
	for i := range ca {
		if fmt.Sprint(xaddrsOf(ca[i])) != fmt.Sprint(xaddrsOf(cb[i])) {
			t.Errorf("order depends on arrival: %v vs %v", xaddrsOf(ca[i]), xaddrsOf(cb[i]))
		}
	}
}

func TestDiscoverKeepsIPv6AndZoneAddresses(t *testing.T) {
	f := &fakeDisc{devs: []*discovery.Device{{EndpointRef: "a", XAddrs: []string{"http://[2001:db8::1]:80/s", "http://[fe80::1%25eth0]/s"}}}}
	d := dataMap(t, call(t, discoverSession(t, f), "camera.discover", nil))
	xs := xaddrsOf(d["candidates"].([]any)[0])
	if len(xs) != 2 {
		t.Errorf("IPv6 addresses lost: %v", xs)
	}
}

func TestDiscoverBackstopDeadlineIsProbePlusTwoSeconds(t *testing.T) {
	f := &fakeDisc{}
	before := time.Now()
	dataMap(t, call(t, discoverSession(t, f), "camera.discover", map[string]any{"timeout_seconds": 4}))
	if f.deadline.IsZero() {
		t.Fatal("the discoverer's context has no deadline")
	}
	if got := f.deadline.Sub(before); got < 5*time.Second || got > 7*time.Second {
		t.Errorf("deadline in %v, want about 6s", got)
	}
}

// A host with no usable network interface makes the probe fail to send; that
// is an unreachable ToolError, not an empty list.
func TestDiscoverWithNoNetworkIsUnreachable(t *testing.T) {
	f := &fakeDisc{err: &net.OpError{Op: "write", Net: "udp", Err: syscall.ENETUNREACH}}
	res := call(t, discoverSession(t, f), "camera.discover", nil)
	if !res.IsError {
		t.Fatalf("expected an error: %s", wire(t, res))
	}
	code, hint := errCode(t, res)
	if code != "unreachable" {
		t.Errorf("code = %q, want unreachable", code)
	}
	if !strings.Contains(hint, "network interface") {
		t.Errorf("hint should explain the missing interface, got %q", hint)
	}
}

func TestDiscoverTextAndToolDescribeBlockingAndCancellation(t *testing.T) {
	cs := discoverSession(t, &fakeDisc{})
	lt, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range lt.Tools {
		if tl.Name == "camera.discover" {
			for _, want := range []string{"blocks", "unverified", "untrusted"} {
				if !strings.Contains(strings.ToLower(tl.Description), want) {
					t.Errorf("description should mention %q: %s", want, tl.Description)
				}
			}
			return
		}
	}
	t.Fatal("camera.discover not registered")
}
