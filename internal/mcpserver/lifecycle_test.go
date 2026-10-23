package mcpserver

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/stdio"
)

// These tests pin the go-sdk v1.7.0 facts that the PTZ motion design (plan
// 2026-10-18-phase13a, section 1) relies on, on the in-memory transport and on
// the shipped one (internal/stdio in front of mcp.IOTransport). If one of them
// fails after an SDK upgrade, the shutdown model in the plan must be revisited;
// do not improvise a different one.

type blockIn struct{}
type blockOut struct {
	Done bool `json:"done"`
}

// lifecycleRig is a server with one tool, "block", that parks until released or
// until its own context is cancelled.
type lifecycleRig struct {
	srv      *mcp.Server
	started  chan struct{}
	ctxDone  chan struct{} // closed when the handler context is cancelled
	release  chan struct{} // closing it lets the handler return
	returned chan struct{} // closed when the handler returned
	quick    chan struct{} // closed when the "quick" tool ran
}

func newLifecycleRig() *lifecycleRig {
	r := &lifecycleRig{
		started: make(chan struct{}, 4), ctxDone: make(chan struct{}),
		release: make(chan struct{}), returned: make(chan struct{}), quick: make(chan struct{}),
	}
	r.srv = mcp.NewServer(&mcp.Implementation{Name: "lifecycle", Version: "0"}, nil)
	mcp.AddTool(r.srv, &mcp.Tool{Name: "block", Description: "parks"},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ blockIn) (*mcp.CallToolResult, blockOut, error) {
			r.started <- struct{}{}
			go func() {
				select {
				case <-ctx.Done():
					close(r.ctxDone)
				case <-r.release:
				}
			}()
			select {
			case <-ctx.Done():
			case <-r.release:
			}
			close(r.returned)
			return nil, blockOut{Done: true}, nil
		})
	mcp.AddTool(r.srv, &mcp.Tool{Name: "quick", Description: "returns at once"},
		func(context.Context, *mcp.CallToolRequest, blockIn) (*mcp.CallToolResult, blockOut, error) {
			select {
			case <-r.quick:
			default:
				close(r.quick)
			}
			return nil, blockOut{Done: true}, nil
		})
	return r
}

// session is one connected pair plus the handles a pin needs.
type session struct {
	cs       *mcp.ClientSession
	cancelRn context.CancelFunc // cancels the Server.Run context
	runDone  chan error         // Server.Run's return value
	eof      func()             // ends the client side the way a vanished client does
}

type transportKind struct {
	name string
	open func(t *testing.T, r *lifecycleRig) *session
}

func kinds() []transportKind {
	return []transportKind{
		{"inmemory", func(t *testing.T, r *lifecycleRig) *session {
			st, ct := mcp.NewInMemoryTransports()
			runCtx, cancel := context.WithCancel(context.Background())
			runDone := make(chan error, 1)
			go func() { runDone <- r.srv.Run(runCtx, st) }()
			cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil).Connect(context.Background(), ct, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cancel(); _ = cs.Close() })
			return &session{cs: cs, cancelRn: cancel, runDone: runDone, eof: func() { _ = cs.Close() }}
		}},
		{"stdio", func(t *testing.T, r *lifecycleRig) *session {
			c2sR, c2sW := io.Pipe()
			s2cR, s2cW := io.Pipe()
			tr := stdio.NewTransport(c2sR, s2cW, stdio.MaxLineBytes, quietLog())
			runCtx, cancel := context.WithCancel(context.Background())
			runDone := make(chan error, 1)
			go func() { runDone <- r.srv.Run(runCtx, tr) }()
			ct := &mcp.IOTransport{Reader: s2cR, Writer: c2sW}
			cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil).Connect(context.Background(), ct, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cancel(); _ = c2sW.Close(); _ = s2cW.Close(); _ = cs.Close() })
			// A vanished client: its stdin-facing writer closes, the server reads EOF.
			return &session{cs: cs, cancelRn: cancel, runDone: runDone, eof: func() { _ = c2sW.Close() }}
		}},
	}
}

func waitClosed(t *testing.T, ch <-chan struct{}, within time.Duration, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(within):
		t.Fatalf("%s: not within %v", what, within)
	}
}

func notClosed(t *testing.T, ch <-chan struct{}, for_ time.Duration, what string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("%s: happened, it must not", what)
	case <-time.After(for_):
	}
}

// startBlocked begins a "block" call and waits until the handler is running.
func startBlocked(t *testing.T, r *lifecycleRig, s *session, ctx context.Context) {
	t.Helper()
	go func() { _, _ = s.cs.CallTool(ctx, &mcp.CallToolParams{Name: "block", Arguments: map[string]any{}}) }()
	waitClosed(t, chanOf(r.started), 5*time.Second, "handler start")
}

func chanOf(c chan struct{}) <-chan struct{} {
	out := make(chan struct{})
	go func() { <-c; close(out) }()
	return out
}

// (a) A blocked handler does not make a second call unreachable.
func TestLifecycleSecondCallReturnsWhileFirstIsBlocked(t *testing.T) {
	for _, k := range kinds() {
		t.Run(k.name, func(t *testing.T) {
			r := newLifecycleRig()
			s := k.open(t, r)
			startBlocked(t, r, s, context.Background())
			done := make(chan error, 1)
			go func() {
				_, err := s.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "quick", Arguments: map[string]any{}})
				done <- err
			}()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the second call did not return while the first was blocked")
			}
			close(r.release)
		})
	}
}

// (b) The client's notifications/cancelled cancels the handler context.
func TestLifecycleClientCancelCancelsHandlerContext(t *testing.T) {
	for _, k := range kinds() {
		t.Run(k.name, func(t *testing.T) {
			r := newLifecycleRig()
			s := k.open(t, r)
			callCtx, cancel := context.WithCancel(context.Background())
			startBlocked(t, r, s, callCtx)
			cancel()
			waitClosed(t, r.ctxDone, time.Second, "handler context cancelled by notifications/cancelled")
		})
	}
}

// (c) Closing the client side (stdin EOF) cancels the handler context.
//
// Stdio only: on the in-memory transport ClientSession.Close does not end the
// stream while the client has a call in flight (jsonrpc2 Connection.Close waits
// for in-flight work first), so it cannot model a vanished client there. The
// shipped transport is the one that matters for this pin.
func TestLifecycleClientEOFCancelsHandlerContext(t *testing.T) {
	for _, k := range kinds() {
		if k.name != "stdio" {
			continue
		}
		t.Run(k.name, func(t *testing.T) {
			r := newLifecycleRig()
			s := k.open(t, r)
			startBlocked(t, r, s, context.Background())
			go s.eof()
			waitClosed(t, r.ctxDone, time.Second, "handler context cancelled by client EOF")
		})
	}
}

// (d) Cancelling the Server.Run context alone does NOT cancel the handler
// context, and Run does not return until the handler has.
func TestLifecycleRunContextDoesNotCancelHandlerAndRunWaitsForIt(t *testing.T) {
	for _, k := range kinds() {
		t.Run(k.name, func(t *testing.T) {
			r := newLifecycleRig()
			s := k.open(t, r)
			startBlocked(t, r, s, context.Background())
			s.cancelRn()
			notClosed(t, r.ctxDone, 400*time.Millisecond, "handler context cancelled by the Run context")
			select {
			case err := <-s.runDone:
				t.Fatalf("Run returned (%v) while a handler was still running", err)
			case <-time.After(400 * time.Millisecond):
			}
			close(r.release)
			select {
			case err := <-s.runDone:
				if err != nil && !errors.Is(err, context.Canceled) {
					t.Logf("Run returned %v after the handler finished", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Run did not return after the handler returned")
			}
			waitClosed(t, r.returned, time.Second, "handler returned")
		})
	}
}
