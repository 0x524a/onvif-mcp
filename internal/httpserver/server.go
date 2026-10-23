package httpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
)

// Config is everything Server needs.
type Config struct {
	Resolved Resolved
	Tokens   *TokenStore
	MCP      *mcp.Server // the tool registry; one server for every request
	Log      *slog.Logger

	TLSCert, TLSKey string

	// CancelTools cancels the base context of every tool call (the one passed to
	// mcpserver.WithBaseContext). Shutdown calls it when in-flight requests
	// outlive the drain deadline.
	CancelTools func()
	// OnFirstSignal runs as soon as shutdown begins, before draining. main uses it
	// to restore default signal handling so a second signal terminates the process.
	OnFirstSignal func()

	tm *timeouts // tests only
}

// timeouts are the D8 values; tests shorten them.
type timeouts struct {
	readHeader, read, idle, write, shutdown, grace time.Duration
}

func defaultTimeouts() *timeouts {
	return &timeouts{ReadHeaderTimeout, ReadTimeout, IdleTimeout, WriteTimeout, ShutdownTimeout, ShutdownGrace}
}

// Server is the HTTP transport: an http.Server around Chain around the SDK's
// streamable handler, in stateless JSON-response mode over HTTP/1.1 only.
type Server struct {
	cfg   Config
	tm    *timeouts
	chain *Chain
	srv   *http.Server
}

// New builds the server and loads the TLS certificate, if any. It binds nothing.
func New(cfg Config) (*Server, error) {
	if cfg.Tokens == nil || cfg.MCP == nil || cfg.Tokens.Len() == 0 {
		return nil, errors.New("httpserver: a token store and an MCP server are required")
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	tm := cfg.tm
	if tm == nil {
		tm = defaultTimeouts()
	}

	var tlsCfg *tls.Config
	if cfg.TLSCert != "" || cfg.TLSKey != "" {
		certPEM, err := os.ReadFile(cfg.TLSCert) //nolint:gosec // path is an operator-supplied flag
		if err != nil {
			return nil, fmt.Errorf("read tls certificate: %w", err)
		}
		// The key is read like the camera config: a regular file, owner-only.
		keyPEM, err := config.ReadPrivateFile(cfg.TLSKey, 64<<10, "tls key")
		if err != nil {
			return nil, err
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, errors.New("tls certificate and key do not form a valid pair")
		}
		tlsCfg = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{pair},
			NextProtos:   []string{"http/1.1"},
		}
	}

	// Stateless + JSON responses: no session table, authentication on every
	// request, single-shot replies. The SDK's Host check is only scoped to
	// loopback-local connections, so we disable it and apply our own on every
	// bind. We use none of the SDK's compatibility knobs.
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return cfg.MCP }, &mcp.StreamableHTTPOptions{
		Stateless:                  true,
		JSONResponse:               true,
		DisableLocalhostProtection: true,
		MaxRequestBodyBytes:        MaxBodyBytes,
	})
	chain := NewChain(ChainConfig{
		Resolved: cfg.Resolved, Tokens: cfg.Tokens, Inner: handler, Log: cfg.Log, MaxInFlight: MaxInFlight,
	})

	protos := new(http.Protocols)
	protos.SetHTTP1(true)
	srv := &http.Server{
		Handler:           chain,
		ReadHeaderTimeout: tm.readHeader,
		ReadTimeout:       tm.read,
		WriteTimeout:      tm.write,
		IdleTimeout:       tm.idle,
		MaxHeaderBytes:    MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(cfg.Log.Handler(), slog.LevelDebug),
		TLSConfig:         tlsCfg,
		Protocols:         protos,
	}
	return &Server{cfg: cfg, tm: tm, chain: chain, srv: srv}, nil
}

// Chain exposes the middleware chain (its in-flight gauge, for tests).
func (s *Server) Chain() *Chain { return s.chain }

// Serve serves on l until ctx is done, then shuts down in one phase (the server
// has only read tools, so there is no write outcome to protect):
//
//  1. OnFirstSignal, so a second signal terminates the process
//  2. drain: new requests get 503 + Connection: close; Shutdown stops accepting,
//     closes idle connections and waits for in-flight requests, up to the deadline
//  3. if the deadline passed: cancel the tools' base context, wait a short grace
//     so cancelled handlers can write their error reply, then Close
//
// It returns nil after a clean stop and an error only if Shutdown failed for a
// reason other than the deadline, or the listener failed before ctx was done.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	errc := make(chan error, 1)
	go func() {
		if s.srv.TLSConfig != nil {
			errc <- s.srv.ServeTLS(l, "", "")
		} else {
			errc <- s.srv.Serve(l)
		}
	}()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}

	if s.cfg.OnFirstSignal != nil {
		s.cfg.OnFirstSignal()
	}
	s.cfg.Log.Info("shutting down", "in_flight", s.chain.InFlight())
	s.chain.Drain()
	sctx, cancel := context.WithTimeout(context.Background(), s.tm.shutdown)
	defer cancel()
	err := s.srv.Shutdown(sctx)
	if err == nil {
		<-errc
		return nil
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		_ = s.srv.Close()
		return fmt.Errorf("shutdown: %w", err)
	}
	s.cfg.Log.Warn("shutdown deadline passed; cancelling in-flight calls", "aborted", s.chain.InFlight())
	if s.cfg.CancelTools != nil {
		s.cfg.CancelTools()
	}
	time.Sleep(s.tm.grace)
	_ = s.srv.Close() // Shutdown at its deadline does not close remaining connections
	<-errc
	return nil
}
