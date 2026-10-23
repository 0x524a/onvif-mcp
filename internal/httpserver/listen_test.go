package httpserver

import (
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type stubListener struct {
	addr   net.Addr
	closed bool
	net.Listener
}

func (s *stubListener) Addr() net.Addr { return s.addr }
func (s *stubListener) Close() error   { s.closed = true; return nil }

func TestListenRechecksBoundAddr(t *testing.T) {
	// A listen function that returns a non-loopback address although a loopback
	// bind was requested must be closed and refused.
	stub := &stubListener{addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 1}}
	_, err := Listen(Resolved{HTTP: true, Listen: "127.0.0.1:0", Loopback: true},
		func(string, string) (net.Listener, error) { return stub, nil })
	if err == nil || !stub.closed {
		t.Fatalf("err=%v closed=%v; want the listener closed and an error", err, stub.closed)
	}
	// A real loopback bind passes the recheck and reports its address.
	l, err := Listen(Resolved{HTTP: true, Listen: "127.0.0.1:0", Loopback: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	if !IsLoopback(netip.MustParseAddrPort(l.Addr().String()).Addr()) {
		t.Errorf("bound %v", l.Addr())
	}
	// A listen error is passed on.
	if _, err := Listen(Resolved{HTTP: true, Listen: "127.0.0.1:0", Loopback: true},
		func(string, string) (net.Listener, error) { return nil, errors.New("boom") }); err == nil {
		t.Error("listen error swallowed")
	}
}

func TestIsLoopback(t *testing.T) {
	for s, want := range map[string]bool{
		"127.0.0.1": true, "127.9.9.9": true, "::1": true, "::ffff:127.0.0.1": true,
		"0.0.0.0": false, "::": false, "192.0.2.1": false, "10.0.0.1": false, "::ffff:10.0.0.1": false, "2001:db8::1": false,
	} {
		if got := IsLoopback(netip.MustParseAddr(s)); got != want {
			t.Errorf("IsLoopback(%s) = %v, want %v", s, got, want)
		}
	}
}

// fakeConn lets the limiter be tested with chosen peer addresses.
type fakeConn struct {
	net.Conn
	remote net.Addr
	shut   atomic.Bool
}

func (f *fakeConn) RemoteAddr() net.Addr { return f.remote }
func (f *fakeConn) Close() error         { f.shut.Store(true); return nil }
func (f *fakeConn) isClosed() bool       { return f.shut.Load() }

type fakeListener struct {
	net.Listener
	ch chan net.Conn
}

func (f *fakeListener) Accept() (net.Conn, error) {
	c, ok := <-f.ch
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}
func (f *fakeListener) Close() error   { return nil }
func (f *fakeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

// limited is a limit listener over a fake one, with a single goroutine
// accepting from it so successive drains see a consistent stream.
type limited struct {
	fl  *fakeListener
	out chan net.Conn
}

func newLimited(global, perIP int) (*limited, *fakeListener) {
	fl := &fakeListener{ch: make(chan net.Conn, 512)}
	l := newLimitListener(fl, global, perIP)
	lm := &limited{fl: fl, out: make(chan net.Conn, 512)}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			lm.out <- c
		}
	}()
	return lm, fl
}

func peer(ip string) *fakeConn {
	return &fakeConn{remote: &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000}}
}

// accepted collects what the limit listener let through within a short window.
func accepted(l *limited, _ int) []net.Conn {
	var got []net.Conn
	timeout := time.After(150 * time.Millisecond)
	for {
		select {
		case c := <-l.out:
			got = append(got, c)
		case <-timeout:
			return got
		}
	}
}

func TestGlobalConnectionCapClosesTheExcessUnserved(t *testing.T) {
	l, fl := newLimited(128, 8)
	conns := make([]*fakeConn, 129)
	for i := range conns {
		// many distinct addresses, so the per-IP cap does not bite
		conns[i] = peer(net.IPv4(10, 0, 0, 0).String())
		conns[i].remote = &net.TCPAddr{IP: net.IPv4(10, 0, byte(i/200), byte(i%200+1)), Port: 40000}
		fl.ch <- conns[i]
	}
	got := accepted(l, 129)
	if len(got) != 128 {
		t.Fatalf("served %d, want 128", len(got))
	}
	if !conns[128].isClosed() {
		t.Error("the 129th connection must be closed")
	}
	// Freeing one slot admits the next arrival.
	_ = got[0].Close()
	extra := peer("198.51.100.1")
	fl.ch <- extra
	if g := accepted(l, 1); len(g) != 1 || extra.isClosed() {
		t.Errorf("slot not reusable after close: served=%d closed=%v", len(g), extra.isClosed())
	}
}

func TestPerIPCapAppliesToNonLoopbackPeersOnly(t *testing.T) {
	l, fl := newLimited(128, 8)
	var same []*fakeConn
	for i := 0; i < 9; i++ {
		c := peer("203.0.113.7")
		same = append(same, c)
		fl.ch <- c
	}
	other := peer("203.0.113.8")
	fl.ch <- other
	got := accepted(l, 10)
	if len(got) != 9 || !same[8].isClosed() || other.isClosed() {
		t.Fatalf("served %d; 9th from one address closed=%v, other address closed=%v", len(got), same[8].isClosed(), other.isClosed())
	}
	// Closing one of the first eight frees the budget for that address.
	_ = got[0].Close()
	again := peer("203.0.113.7")
	fl.ch <- again
	if g := accepted(l, 1); len(g) != 1 || again.isClosed() {
		t.Error("per-IP slot not released on close")
	}
}

func TestIPv6PeersShareABudgetPerSlash64(t *testing.T) {
	l, fl := newLimited(128, 2)
	a, b, c := peer("2001:db8:0:1::1"), peer("2001:db8:0:1::2"), peer("2001:db8:0:1:ffff::3")
	d := peer("2001:db8:0:2::1")
	for _, x := range []*fakeConn{a, b, c, d} {
		fl.ch <- x
	}
	_ = accepted(l, 4)
	if a.isClosed() || b.isClosed() || !c.isClosed() || d.isClosed() {
		t.Errorf("closed: a=%v b=%v c=%v d=%v; want only c (third in the same /64)", a.isClosed(), b.isClosed(), c.isClosed(), d.isClosed())
	}
}

func TestLoopbackPeersAreExemptFromPerIPButNotGlobal(t *testing.T) {
	l, fl := newLimited(20, 2)
	var cs []*fakeConn
	for i := 0; i < 21; i++ {
		c := peer("127.0.0.1")
		cs = append(cs, c)
		fl.ch <- c
	}
	got := accepted(l, 21)
	if len(got) != 20 || !cs[20].isClosed() {
		t.Fatalf("served %d (loopback must bypass per-IP cap 2 but obey global 20); last closed=%v", len(got), cs[20].isClosed())
	}
}

func TestDoubleCloseReleasesOnce(t *testing.T) {
	l, fl := newLimited(1, 1)
	c1 := peer("203.0.113.1")
	fl.ch <- c1
	got := accepted(l, 1)
	_ = got[0].Close()
	_ = got[0].Close()
	c2, c3 := peer("203.0.113.2"), peer("203.0.113.3")
	fl.ch <- c2
	fl.ch <- c3
	_ = accepted(l, 2)
	if c2.isClosed() || !c3.isClosed() {
		t.Errorf("a double Close must free one slot, not two: c2.closed=%v c3.closed=%v", c2.isClosed(), c3.isClosed())
	}
}
