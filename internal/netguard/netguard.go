// Package netguard holds the one predicate that decides which hosts
// onvif-mcp never opens a stream connection to. The registry applies it to
// advertised hostnames and the prober applies it to the resolved address.
package netguard

import (
	"net"
	"net/netip"
	"strings"
)

// NeverProbed reports whether host is a target onvif-mcp refuses to probe even
// for a camera that trusts its advertised hosts: unspecified, multicast,
// broadcast and link-local addresses (this covers the 169.254.169.254 cloud
// metadata address), IPv4-mapped forms of those, and numeric spellings that
// net/netip does not parse but a system resolver may.
func NeverProbed(host string) bool {
	h := strings.TrimSuffix(host, ".")
	if a, err := netip.ParseAddr(h); err == nil {
		a = a.WithZone("").Unmap()
		return a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
			a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) ||
			(a.Is4() && a.As4()[0] == 0)
	}
	if net.ParseIP(h) != nil {
		return true // unexpected spelling of an IP; do not guess
	}
	last := h
	if i := strings.LastIndexByte(h, '.'); i >= 0 {
		last = h[i+1:]
	}
	if last == "" {
		return true
	}
	if strings.HasPrefix(strings.ToLower(last), "0x") {
		return true
	}
	for _, c := range last {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true // a final label of digits only is an address spelling, not a name
}
