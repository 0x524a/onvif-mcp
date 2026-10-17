package tools

import (
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/0x524a/onvif-go/discovery"
)

// pinOffLink makes every address read as not directly attached, so ranking in
// these tests does not depend on the host's interfaces.
func pinOffLink(t *testing.T) {
	t.Helper()
	old := onLink
	onLink = func(net.IP) bool { return false }
	t.Cleanup(func() { onLink = old })
}

func refsAndFirst(cs []Candidate) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.EndpointRef+"@"+c.XAddrs[0])
	}
	return out
}

func TestCandidatesDedupeOnTheWholeAddressSet(t *testing.T) {
	pinOffLink(t)
	got := candidatesFrom([]*discovery.Device{
		{EndpointRef: "r1", XAddrs: []string{"http://10.0.0.1/a", "http://10.0.0.2/b"}},
		// Same first address, different second: a different device.
		{EndpointRef: "r2", XAddrs: []string{"http://10.0.0.1/a", "http://10.0.0.3/c"}},
		// Same set as r1, announced in the other order and under another ref:
		// the same device, the first-seen reference wins.
		{EndpointRef: "r3", XAddrs: []string{"http://10.0.0.2/b", "http://10.0.0.1/a"}},
	})
	if got.total != 2 || len(got.cands) != 2 {
		t.Fatalf("total=%d cands=%d: %v", got.total, len(got.cands), refsAndFirst(got.cands))
	}
	byRef := map[string]bool{}
	for _, c := range got.cands {
		byRef[c.EndpointRef] = true
	}
	if !byRef["r1"] || !byRef["r2"] || byRef["r3"] {
		t.Errorf("refs = %v", byRef)
	}
}

func TestCandidatesOrderTiesByEndpointRef(t *testing.T) {
	pinOffLink(t)
	a := &discovery.Device{EndpointRef: "a", XAddrs: []string{"http://10.0.0.1/s", "http://10.0.0.8/s"}}
	b := &discovery.Device{EndpointRef: "b", XAddrs: []string{"http://10.0.0.1/s", "http://10.0.0.9/s"}}
	for _, in := range [][]*discovery.Device{{a, b}, {b, a}} {
		got := candidatesFrom(in)
		if r := refsAndFirst(got.cands); !reflect.DeepEqual(r, []string{"a@http://10.0.0.1/s", "b@http://10.0.0.1/s"}) {
			t.Errorf("order = %v", r)
		}
	}
}

func TestCandidatesSortAddressesAndDropRepeatsWithinADevice(t *testing.T) {
	pinOffLink(t)
	got := candidatesFrom([]*discovery.Device{{
		EndpointRef: "r",
		XAddrs: []string{
			"http://10.0.0.9/z", "http://10.0.0.1/a", "http://10.0.0.9/z",
			"http://127.0.0.1/loop", "http://10.0.0.5/m", "http://10.0.0.1/a",
		},
	}})
	want := []string{"http://10.0.0.1/a", "http://10.0.0.5/m", "http://10.0.0.9/z", "http://127.0.0.1/loop"}
	if len(got.cands) != 1 || !reflect.DeepEqual(got.cands[0].XAddrs, want) {
		t.Fatalf("xaddrs = %v, want %v", got.cands[0].XAddrs, want)
	}
	if !strings.Contains(got.cands[0].ConfigSnippet, "http://10.0.0.1/a") {
		t.Errorf("snippet must use the best address: %s", got.cands[0].ConfigSnippet)
	}
}

func TestCandidatesRankSpecialAddressesAfterOrdinaryOnes(t *testing.T) {
	pinOffLink(t)
	for _, host := range []string{"127.0.0.1", "169.254.169.254", "0.0.0.0", "224.0.0.1", "localhost", "[::1]", "[fe80::1]"} {
		got := candidatesFrom([]*discovery.Device{{EndpointRef: "r", XAddrs: []string{"http://" + host + "/a", "http://10.9.9.9/z"}}})
		if got.cands[0].XAddrs[0] != "http://10.9.9.9/z" {
			t.Errorf("%s ranked ahead of an ordinary address: %v", host, got.cands[0].XAddrs)
		}
	}
	// A hostname (not an IP) is ordinary, and an on-link address beats it.
	onLinkIP := net.ParseIP("10.1.1.1")
	old := onLink
	onLink = func(ip net.IP) bool { return ip.Equal(onLinkIP) }
	defer func() { onLink = old }()
	got := candidatesFrom([]*discovery.Device{{EndpointRef: "r", XAddrs: []string{"http://aaa.example/x", "http://10.1.1.1/x", "http://10.0.0.1/x"}}})
	if want := []string{"http://10.1.1.1/x", "http://10.0.0.1/x", "http://aaa.example/x"}; !reflect.DeepEqual(got.cands[0].XAddrs, want) {
		t.Errorf("xaddrs = %v, want %v", got.cands[0].XAddrs, want)
	}
}

func TestCandidatesScopesDropEmptyAfterScrubAndCap(t *testing.T) {
	var scopes []string
	scopes = append(scopes, "   ", "\t")
	for i := 0; i < 40; i++ {
		scopes = append(scopes, "onvif://www.onvif.org/name/"+string(rune('A'+i%26))+string(rune('a'+i/26)))
	}
	got := candidatesFrom([]*discovery.Device{{EndpointRef: "r", XAddrs: []string{"http://10.0.0.1/s"}, Scopes: scopes}})
	c := got.cands[0]
	if len(c.Scopes) != maxScopes {
		t.Errorf("scopes = %d, want %d", len(c.Scopes), maxScopes)
	}
	for _, s := range c.Scopes {
		if strings.TrimSpace(s) == "" {
			t.Errorf("an empty scope was kept: %q", s)
		}
	}
}
