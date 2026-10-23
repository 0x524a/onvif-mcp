package httpserver

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

// Listen binds r.Listen and returns a listener that enforces the connection
// caps (MaxConns, MaxConnsPerIP). After the bind it re-checks the address the
// kernel actually gave us: a loopback-only configuration must not end up on a
// wider address, whatever the listen function did. listenFn is net.Listen when
// nil; tests inject one.
func Listen(r Resolved, listenFn func(network, address string) (net.Listener, error)) (net.Listener, error) {
	if listenFn == nil {
		listenFn = net.Listen
	}
	l, err := listenFn("tcp", r.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	ap, err := netip.ParseAddrPort(l.Addr().String())
	if err != nil {
		_ = l.Close()
		return nil, errors.New("listen: cannot interpret the bound address")
	}
	if r.Loopback && !IsLoopback(ap.Addr()) {
		_ = l.Close()
		return nil, errors.New("listen: bound a non-loopback address although a loopback bind was configured")
	}
	return newLimitListener(l, MaxConns, MaxConnsPerIP), nil
}

// limitListener closes excess connections on accept, before any bytes are read:
// at most global at once, and at most perIP per remote address (IPv6 peers are
// keyed by /64). Loopback peers, which include a local reverse proxy, are exempt
// from the per-IP cap but not from the global one.
type limitListener struct {
	net.Listener
	global, perIP int

	mu    sync.Mutex
	n     int
	perIn map[netip.Addr]int
}

func newLimitListener(l net.Listener, global, perIP int) net.Listener {
	return &limitListener{Listener: l, global: global, perIP: perIP, perIn: map[netip.Addr]int{}}
}

// peerKey returns the address a connection is counted under and whether the per-IP
// cap applies to it.
func peerKey(a net.Addr) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		// An address we cannot parse is counted as one anonymous peer: refusing
		// to exempt what we cannot classify.
		return netip.Addr{}, true
	}
	ip := ap.Addr().Unmap()
	if ip.IsLoopback() {
		return ip, false
	}
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.Addr(), true
	}
	return ip, true
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		key, perIP := peerKey(c.RemoteAddr())
		l.mu.Lock()
		if l.n >= l.global || (perIP && l.perIn[key] >= l.perIP) {
			l.mu.Unlock()
			_ = c.Close()
			continue
		}
		l.n++
		if perIP {
			l.perIn[key]++
		}
		l.mu.Unlock()
		return &limitConn{Conn: c, l: l, key: key, perIP: perIP}, nil
	}
}

type limitConn struct {
	net.Conn
	l     *limitListener
	key   netip.Addr
	perIP bool
	once  sync.Once
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.l.mu.Lock()
		defer c.l.mu.Unlock()
		c.l.n--
		if c.perIP {
			if c.l.perIn[c.key]--; c.l.perIn[c.key] <= 0 {
				delete(c.l.perIn, c.key)
			}
		}
	})
	return err
}
