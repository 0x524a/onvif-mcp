package httpserver

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Operational limits. They are constants, not flags; the README table
// is written from these names.
const (
	MaxConns          = 128
	MaxConnsPerIP     = 8
	ReadHeaderTimeout = 5 * time.Second
	ReadTimeout       = 30 * time.Second
	IdleTimeout       = 60 * time.Second
	WriteTimeout      = 180 * time.Second
	MaxHeaderBytes    = 16 << 10
	MaxBodyBytes      = 64 << 10
	MaxInFlight       = 32
	ShutdownTimeout   = 10 * time.Second
	ShutdownGrace     = 2 * time.Second

	// DefaultListen is the loopback address served when -listen is not given.
	DefaultListen = "127.0.0.1:8808"
)

// Flags is the HTTP-relevant part of the command line, as parsed. Explicit
// records which flags the operator actually passed, so a flag that does not
// apply to the chosen mode is an error instead of silently ignored.
type Flags struct {
	Transport    string
	Listen       string
	Tokens       string
	AllowRemote  bool
	AllowedHosts string // comma separated, as given
	TLSCert      string
	TLSKey       string
	NewToken     string

	EnableControl           bool
	SnapshotMaxBytes        int
	DefaultSnapshotMaxBytes int

	Explicit map[string]bool
}

// Resolved is what Validate decided. Only meaningful for Transport "http".
type Resolved struct {
	HTTP     bool   // -transport http
	NewToken bool   // one-shot token generator mode
	Listen   string // host:port to bind, IP literal
	Loopback bool
	TLS      bool

	hosts map[string]struct{}
}

// AllowedHost reports whether a Host header hostname (already stripped of its
// port) is on the allowlist. The comparison is exact and case-insensitive; no
// suffix or wildcard matching, and a trailing dot is a different host.
func (r Resolved) AllowedHost(host string) bool {
	_, ok := r.hosts[strings.ToLower(host)]
	return ok
}

// HostCount is the allowlist size, for the startup line.
func (r Resolved) HostCount() int { return len(r.hosts) }

var (
	tokenIDRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	hostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

	httpOnlyFlags = []string{"listen", "http-tokens", "http-allow-remote", "http-allowed-hosts", "tls-cert", "tls-key"}
)

// Validate checks every flag combination before any file is opened or socket
// bound. Every error is a usage error (exit 2) and names the flag at fault; none
// echoes a file name's contents or a token.
func Validate(f Flags) (Resolved, error) {
	ex := f.Explicit
	if f.NewToken != "" || ex["new-token"] {
		for name := range ex {
			if name != "new-token" && name != "version" {
				return Resolved{}, fmt.Errorf("-new-token cannot be combined with -%s (only -version)", name)
			}
		}
		if !tokenIDRe.MatchString(f.NewToken) {
			return Resolved{}, errors.New("-new-token: the id must match [a-z0-9][a-z0-9._-]{0,63}")
		}
		return Resolved{NewToken: true}, nil
	}

	switch f.Transport {
	case "", "stdio":
		for _, n := range httpOnlyFlags {
			if ex[n] {
				return Resolved{}, fmt.Errorf("-%s requires -transport http", n)
			}
		}
		return Resolved{}, nil
	case "http":
	default:
		return Resolved{}, errors.New(`-transport must be "stdio" or "http"`)
	}

	// From here on: HTTP.
	if f.EnableControl {
		return Resolved{}, errors.New("-enable-control cannot be used with -transport http: write tools are not offered over HTTP in this release; use stdio")
	}
	if f.Tokens == "" {
		return Resolved{}, errors.New("-transport http requires -http-tokens (a token file); generate a token with: onvif-mcp -new-token ID")
	}
	if f.DefaultSnapshotMaxBytes > 0 && f.SnapshotMaxBytes > f.DefaultSnapshotMaxBytes {
		return Resolved{}, fmt.Errorf("-snapshot-max-bytes cannot exceed the default (%d) with -transport http: replies are buffered in memory", f.DefaultSnapshotMaxBytes)
	}
	if (f.TLSCert == "") != (f.TLSKey == "") {
		if f.TLSCert == "" {
			return Resolved{}, errors.New("-tls-key requires -tls-cert")
		}
		return Resolved{}, errors.New("-tls-cert requires -tls-key")
	}

	listen := f.Listen
	if !ex["listen"] && listen == "" {
		listen = DefaultListen
	}
	addr, loopback, err := resolveListen(listen)
	if err != nil {
		return Resolved{}, err
	}
	r := Resolved{HTTP: true, Listen: addr, Loopback: loopback, TLS: f.TLSCert != ""}

	extra, err := parseHosts(f.AllowedHosts)
	if err != nil {
		return Resolved{}, err
	}
	if !loopback {
		switch {
		case !f.AllowRemote:
			return Resolved{}, errors.New("-listen is not a loopback address: pass -http-allow-remote (with -tls-cert, -tls-key and -http-allowed-hosts) to serve other machines")
		case !r.TLS:
			return Resolved{}, errors.New("a non-loopback -listen requires -tls-cert and -tls-key: a bearer token must not cross a network in clear text")
		case len(extra) == 0:
			return Resolved{}, errors.New("a non-loopback -listen requires -http-allowed-hosts (the names clients use to reach this server)")
		}
	}
	r.hosts = map[string]struct{}{}
	if loopback {
		for _, h := range []string{"localhost", "127.0.0.1", "::1"} {
			r.hosts[h] = struct{}{}
		}
	}
	for _, h := range extra {
		r.hosts[h] = struct{}{}
	}
	return r, nil
}

// IsLoopback reports whether a is a loopback address, looking through an
// IPv4-mapped IPv6 form.
func IsLoopback(a netip.Addr) bool { return a.Unmap().IsLoopback() }

// resolveListen turns -listen into an IP literal host:port and classifies it.
// Names are never resolved to decide a security property: only "localhost" and
// IP literals are accepted.
func resolveListen(s string) (addr string, loopback bool, err error) {
	bad := func(why string) (string, bool, error) {
		return "", false, fmt.Errorf("-listen: %s (want IP:port, [IPv6]:port or localhost:port)", why)
	}
	if s == "" {
		return bad("empty address")
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return bad("not a host:port address")
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return bad("port is not a number from 0 to 65535")
	}
	if host == "" {
		// ":8808" binds every interface.
		return net.JoinHostPort("", strconv.Itoa(int(p))), false, nil
	}
	if strings.EqualFold(host, "localhost") {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(p))), true, nil
	}
	ip, perr := netip.ParseAddr(host)
	if perr != nil || ip.Zone() != "" {
		return bad("host is not an IP literal or localhost")
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(p))), IsLoopback(ip), nil
}

// parseHosts normalises -http-allowed-hosts: lowercase hostnames or IP literals,
// no port, no wildcard, no trailing dot, no empty element.
func parseHosts(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []string
	for _, h := range strings.Split(s, ",") {
		h = strings.ToLower(strings.TrimSpace(h))
		h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
		if ip, err := netip.ParseAddr(h); err == nil && ip.Zone() == "" {
			out = append(out, ip.String())
			continue
		}
		if h == "" || len(h) > 253 || !hostnameRe.MatchString(h) {
			return nil, errors.New("-http-allowed-hosts: each entry must be a hostname or IP literal without port, wildcard or trailing dot")
		}
		out = append(out, h)
	}
	return out, nil
}
