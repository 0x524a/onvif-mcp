// Package netguard holds the one predicate that decides which hosts
// onvif-mcp never opens a stream connection to. The registry applies it to
// advertised hostnames and the prober applies it to the resolved address.
package netguard

import (
	"net"
	"net/netip"
	"strings"
)

var (
	nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")
	nat64Local     = netip.MustParsePrefix("64:ff9b:1::/48")
	sixToFour      = netip.MustParsePrefix("2002::/16")
	v4Compatible   = netip.MustParsePrefix("::/96")
	awsIMDSv6      = netip.MustParseAddr("fd00:ec2::254")
	alibabaIMDS    = netip.AddrFrom4([4]byte{100, 100, 100, 200})
	oracleIMDS     = netip.AddrFrom4([4]byte{192, 0, 0, 192})
	ipv6Loopback   = netip.IPv6Loopback()
)

// neverProbedAddr is the address-level rule. An IPv4 address carried inside an
// IPv6 one (NAT64, 6to4, deprecated IPv4-compatible) is judged as that IPv4
// address, since a translator or tunnel on the path may deliver the packet to
// it.
func neverProbedAddr(a netip.Addr) bool {
	if a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) ||
		(a.Is4() && a.As4()[0] == 0) ||
		a == awsIMDSv6 || a == alibabaIMDS || a == oracleIMDS {
		return true
	}
	if !a.Is6() {
		return false
	}
	b := a.As16()
	switch {
	case nat64WellKnown.Contains(a):
		return neverProbedAddr(netip.AddrFrom4([4]byte(b[12:16])))
	case nat64Local.Contains(a):
		// RFC 8215 local-use prefix; the embedding depends on the prefix
		// length, so check both the low 32 bits and the RFC 6052 /48 layout
		// (bits 48..63, skip the u octet, then bits 72..87).
		return neverProbedAddr(netip.AddrFrom4([4]byte(b[12:16]))) ||
			neverProbedAddr(netip.AddrFrom4([4]byte{b[6], b[7], b[9], b[10]}))
	case sixToFour.Contains(a):
		return neverProbedAddr(netip.AddrFrom4([4]byte(b[2:6])))
	case v4Compatible.Contains(a) && a != ipv6Loopback:
		return neverProbedAddr(netip.AddrFrom4([4]byte(b[12:16])))
	}
	return false
}

// NeverProbed reports whether host is a target onvif-mcp refuses to probe even
// for a camera that trusts its advertised hosts: unspecified, multicast,
// broadcast and link-local addresses (this covers the 169.254.169.254 cloud
// metadata address), IPv4-mapped forms of those, and numeric spellings that
// net/netip does not parse but a system resolver may. IPv4 addresses embedded
// in NAT64 (64:ff9b::/96, 64:ff9b:1::/48), 6to4 (2002::/16) and IPv4-compatible
// (::/96) addresses are judged as the IPv4 address, and the cloud metadata
// addresses fd00:ec2::254, 100.100.100.200 and 192.0.0.192 are refused.
func NeverProbed(host string) bool {
	h := strings.TrimSuffix(host, ".")
	if a, err := netip.ParseAddr(h); err == nil {
		return neverProbedAddr(a.WithZone("").Unmap())
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
