package probe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// spy is a scripted RTSP listener that counts connections, requests and
// Authorization headers. respond returns the full response for one request.
type spy struct {
	ln      net.Listener
	conns   atomic.Int32
	auths   atomic.Int32
	reqs    atomic.Int32
	desc    atomic.Int32
	respond func(method, cseq string) string
	mu      sync.Mutex
	open    []net.Conn
	wg      sync.WaitGroup
}

func startSpy(t *testing.T, ip string, respond func(method, cseq string) string) *spy {
	t.Helper()
	ln, err := net.Listen("tcp", ip+":0")
	if err != nil {
		t.Skipf("cannot listen on %s: %v", ip, err)
	}
	s := &spy{ln: ln, respond: respond}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			s.mu.Lock()
			s.open = append(s.open, c)
			s.mu.Unlock()
			s.wg.Add(1)
			go func() { defer s.wg.Done(); s.serve(c) }()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		s.mu.Lock()
		for _, c := range s.open {
			_ = c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return s
}

func (s *spy) addr() string { return s.ln.Addr().String() }

func (s *spy) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	for {
		var method, cseq string
		first := true
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			low := strings.ToLower(line)
			switch {
			case first:
				method = strings.Fields(line)[0]
				first = false
				s.reqs.Add(1)
				if method == "DESCRIBE" {
					s.desc.Add(1)
				}
			case strings.HasPrefix(low, "cseq:"):
				cseq = strings.TrimSpace(line[5:])
			case strings.HasPrefix(low, "authorization:"):
				s.auths.Add(1)
			}
		}
		if _, err := fmt.Fprint(c, s.respond(method, cseq)); err != nil {
			return
		}
	}
}

func redirectTo(loc string) func(method, cseq string) string {
	return func(method, cseq string) string {
		if method == "OPTIONS" {
			return fmt.Sprintf("RTSP/1.0 200 OK\r\nCSeq: %s\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n", cseq)
		}
		return fmt.Sprintf("RTSP/1.0 302 Found\r\nCSeq: %s\r\nLocation: %s\r\n\r\n", cseq, loc)
	}
}

func challenge(www string) func(method, cseq string) string {
	return func(method, cseq string) string {
		if method == "OPTIONS" {
			return fmt.Sprintf("RTSP/1.0 200 OK\r\nCSeq: %s\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n", cseq)
		}
		return fmt.Sprintf("RTSP/1.0 401 Unauthorized\r\nCSeq: %s\r\nWWW-Authenticate: %s\r\n\r\n", cseq, www)
	}
}

func TestRedirectToAnotherHostIsNotFollowed(t *testing.T) {
	const digest = `Digest realm="cam", nonce="abc123"`
	const basic = `Basic realm="cam"`
	for _, tc := range []struct {
		name string
		www  string
		cred bool
		loc  func(b *spy) string
	}{
		{"basic with credentials", basic, true, func(b *spy) string { return "rtsp://" + b.addr() + "/x" }},
		{"digest with credentials", digest, true, func(b *spy) string { return "rtsp://" + b.addr() + "/x" }},
		{"basic without credentials", basic, false, func(b *spy) string { return "rtsp://" + b.addr() + "/x" }},
		{"digest without credentials", digest, false, func(b *spy) string { return "rtsp://" + b.addr() + "/x" }},
		{"by name", basic, true, func(b *spy) string { _, p, _ := net.SplitHostPort(b.addr()); return "rtsp://localhost:" + p + "/x" }},
		{"same host other port", basic, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := startSpy(t, "127.0.0.2", challenge(tc.www))
			var loc string
			if tc.loc != nil {
				loc = tc.loc(b)
			} else {
				_, p, _ := net.SplitHostPort(b.addr())
				// 127.0.0.1 with the other server's port: same IP as the
				// camera, different port.
				loc = "rtsp://127.0.0.1:" + p + "/x"
			}
			a := startSpy(t, "127.0.0.1", redirectTo(loc))
			u := "rtsp://" + a.addr() + "/s"
			if tc.cred {
				u = "rtsp://" + testUser + ":" + testPass + "@" + a.addr() + "/s"
			}
			_, err := NewRTSP().Describe(context.Background(), u, 2*time.Second)
			if !errors.Is(err, ErrRedirected) {
				t.Fatalf("err = %v, want ErrRedirected", err)
			}
			assertNoLeak(t, err)
			time.Sleep(100 * time.Millisecond)
			if n := b.conns.Load(); n != 0 {
				t.Errorf("redirect target got %d connection(s), want 0", n)
			}
			if n := b.auths.Load(); n != 0 {
				t.Errorf("redirect target got %d Authorization header(s), want 0", n)
			}
			if n := a.desc.Load(); n != 1 {
				t.Errorf("camera saw %d DESCRIBE, want 1", n)
			}
		})
	}
}

func TestRedirectOnOptionsIsNotFollowed(t *testing.T) {
	b := startSpy(t, "127.0.0.2", challenge(`Basic realm="x"`))
	a := startSpy(t, "127.0.0.1", func(_, cseq string) string {
		return fmt.Sprintf("RTSP/1.0 301 Moved\r\nCSeq: %s\r\nLocation: rtsp://%s/x\r\n\r\n", cseq, b.addr())
	})
	_, err := NewRTSP().Describe(context.Background(), probeWithCreds(a.addr()), 2*time.Second)
	if !errors.Is(err, ErrRedirected) {
		t.Fatalf("err = %v, want ErrRedirected", err)
	}
	if b.conns.Load() != 0 || b.auths.Load() != 0 {
		t.Errorf("target saw conns=%d auths=%d", b.conns.Load(), b.auths.Load())
	}
}

func goroutinesBackTo(t *testing.T, base int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		n := runtime.NumGoroutine()
		if n <= base {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			buf = buf[:runtime.Stack(buf, true)]
			t.Fatalf("goroutines %d, want <= %d\n%s", n, base, buf)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSelfRedirectLoopTerminatesAndLeaksNothing(t *testing.T) {
	var self string
	a := startSpy(t, "127.0.0.1", func(method, cseq string) string {
		return redirectTo("rtsp://"+self+"/loop")(method, cseq)
	})
	self = a.addr()
	// Settle: the spy's accept goroutine is part of the baseline.
	base := runtime.NumGoroutine()
	for i := 0; i < 3; i++ {
		start := time.Now()
		_, err := NewRTSP().Describe(context.Background(), probeWithCreds(a.addr()), 2*time.Second)
		if !errors.Is(err, ErrRedirected) {
			t.Fatalf("err = %v, want ErrRedirected", err)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("loop took %v to refuse", d)
		}
	}
	before := a.desc.Load()
	time.Sleep(300 * time.Millisecond)
	if after := a.desc.Load(); after != before {
		t.Errorf("DESCRIBE count grew from %d to %d after Describe returned", before, after)
	}
	if before != 3 {
		t.Errorf("DESCRIBE count = %d, want exactly 3 (one per probe)", before)
	}
	// Server-side connections close with the probe; goroutines return to baseline.
	goroutinesBackTo(t, base+3) // 3 spy serve goroutines may still be unwinding
	goroutinesBackTo(t, base+3)
}

func TestTimeoutAndCancelTearDownTheClient(t *testing.T) {
	quit := make(chan struct{})
	srv := startSpy(t, "127.0.0.1", func(method, cseq string) string {
		if method == "OPTIONS" {
			return fmt.Sprintf("RTSP/1.0 200 OK\r\nCSeq: %s\r\n\r\n", cseq)
		}
		<-quit // never answer DESCRIBE
		return ""
	})
	t.Cleanup(func() { close(quit) }) // runs before the spy's own cleanup
	base := runtime.NumGoroutine()

	_, err := NewRTSP().Describe(context.Background(), probeWithCreds(srv.addr()), 300*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	_, err = NewRTSP().Describe(ctx, probeWithCreds(srv.addr()), 10*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want canceled", err)
	}
	// The spy's blocked serve goroutines (2) are expected; the client's must be gone.
	goroutinesBackTo(t, base+2)
}

func TestSlowLorisStillHonoursTheTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				// Dribble a status line one byte at a time, forever.
				for _, b := range []byte(strings.Repeat("RTSP/1.0 200 OK ", 200)) {
					select {
					case <-stop:
						return
					case <-time.After(30 * time.Millisecond):
					}
					if _, err := c.Write([]byte{b}); err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { close(stop); _ = ln.Close(); wg.Wait() })

	start := time.Now()
	_, err = NewRTSP().Describe(context.Background(), probeWithCreds(ln.Addr().String()), 400*time.Millisecond)
	if d := time.Since(start); d > 400*time.Millisecond+time.Second {
		t.Errorf("returned after %v", d)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want deadline", err)
	}
	assertNoLeak(t, err)
}

func TestEOFDuringDescribeIsMarked(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if strings.HasPrefix(line, "OPTIONS") {
						_, _ = fmt.Fprint(c, "RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")
					}
					if strings.HasPrefix(line, "DESCRIBE") {
						_ = c.Close()
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	_, err = NewRTSP().Describe(context.Background(), probeWithCreds(ln.Addr().String()), 2*time.Second)
	if !errors.Is(err, ErrEndedDuringDescribe) {
		t.Fatalf("err = %v, want ErrEndedDuringDescribe", err)
	}
	assertNoLeak(t, err)
}
