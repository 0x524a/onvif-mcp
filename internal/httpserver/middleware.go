package httpserver

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

// ChainConfig configures NewChain.
type ChainConfig struct {
	Resolved    Resolved
	Tokens      *TokenStore
	Inner       http.Handler // the streamable MCP handler
	Log         *slog.Logger
	MaxInFlight int
	Now         func() time.Time // nil means time.Now
}

// Chain is the fixed middleware chain in front of the MCP handler. Outermost
// first: panic recovery and access log, drain gate, path, Host, Origin,
// authentication, in-flight cap, then the SDK's bearer stage (which only carries
// the already-verified identity) and the MCP handler.
type Chain struct {
	h        http.Handler
	draining atomic.Bool
	inflight atomic.Int32
	cfg      ChainConfig
	failLog  rateLimitedLog
}

type ctxKey int

const (
	infoKey ctxKey = iota
	verifiedKey
)

// reqInfo lets inner stages tell the access log who the caller was.
type reqInfo struct{ caller string }

// NewChain builds the chain.
func NewChain(cfg ChainConfig) *Chain {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.MaxInFlight <= 0 {
		cfg.MaxInFlight = MaxInFlight
	}
	c := &Chain{cfg: cfg}
	c.failLog = rateLimitedLog{now: cfg.Now}

	// The SDK stage runs after our authentication. Its verifier returns the
	// identity we already established; its failure branches are unreachable (a
	// test proves it), which is why its distinguishing error text never reaches
	// a client.
	verifier := func(ctx context.Context, _ string, _ *http.Request) (*auth.TokenInfo, error) {
		id, ok := ctx.Value(verifiedKey).(string)
		if !ok || id == "" {
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{UserID: id}, nil
	}
	sdkStage := auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{AllowMissingExpiration: true})(cfg.Inner)

	c.h = c.recoverAndLog(c.drain(c.path(c.host(c.origin(c.authenticate(c.limit(sdkStage)))))))
	return c
}

// ServeHTTP implements http.Handler.
func (c *Chain) ServeHTTP(w http.ResponseWriter, r *http.Request) { c.h.ServeHTTP(w, r) }

// Drain makes every further request a 503 with Connection: close. Called at the
// start of shutdown.
func (c *Chain) Drain() { c.draining.Store(true) }

// InFlight is the number of requests inside the in-flight cap. Exported for tests.
func (c *Chain) InFlight() int { return int(c.inflight.Load()) }

// reject writes a fixed, input-independent response and closes the connection.
// Every response sent before authentication succeeds goes through here, so an
// unauthenticated peer cannot keep a connection alive with cheap rejected
// requests.
func reject(w http.ResponseWriter, code int, body string, extra ...string) {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Connection", "close")
	for i := 0; i+1 < len(extra); i += 2 {
		h.Set(extra[i], extra[i+1])
	}
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body))
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
	wrote  bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wrote {
		s.status, s.wrote = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(p []byte) (int, error) {
	if !s.wrote {
		s.status, s.wrote = http.StatusOK, true
	}
	n, err := s.ResponseWriter.Write(p)
	s.bytes += int64(n)
	return n, err
}

func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (c *Chain) recoverAndLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := c.cfg.Now()
		info := &reqInfo{caller: "-"}
		sw := &statusWriter{ResponseWriter: w}
		r = r.WithContext(context.WithValue(r.Context(), infoKey, info))
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler { //nolint:errorlint // sentinel panic value, compared by identity as net/http does
					panic(rec)
				}
				// The panic value is deliberately not logged: it can carry anything
				// the handler held, including secrets.
				c.cfg.Log.Error("http handler panicked")
				if !sw.wrote {
					reject(sw, http.StatusInternalServerError, "internal error\n")
				}
			}
			status := sw.status
			if status == 0 {
				status = http.StatusOK
			}
			attrs := []any{
				"caller", info.caller, "remote", r.RemoteAddr, "status", status, "bytes", sw.bytes,
				"dur_ms", c.cfg.Now().Sub(start).Milliseconds(),
			}
			switch {
			case status == http.StatusUnauthorized:
				// Rate limited: a failed-auth flood must not flood the log.
				c.failLog.log(c.cfg.Log, "authentication failed", attrs)
			case status >= 400:
				c.cfg.Log.Warn("http request", attrs...)
			default:
				c.cfg.Log.Debug("http request", attrs...)
			}
		}()
		next.ServeHTTP(sw, r)
	})
}

func (c *Chain) drain(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c.draining.Load() {
			reject(w, http.StatusServiceUnavailable, "shutting down\n", "Retry-After", "1")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (c *Chain) path(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" {
			reject(w, http.StatusNotFound, "not found\n")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hostName extracts the hostname from a Host header value for comparison:
// lowercased, port stripped (and required to be 1 to 5 digits when present),
// IPv6 brackets removed and the address canonicalised, zones refused.
func hostName(h string) (string, bool) {
	if h == "" || strings.ContainsAny(h, " \t@/\\%") {
		return "", false
	}
	host := h
	if sh, port, err := net.SplitHostPort(h); err == nil {
		if n, perr := strconv.Atoi(port); perr != nil || port == "" || len(port) > 5 || n < 0 || n > 65535 {
			return "", false
		}
		host = sh
	} else if strings.HasPrefix(h, "[") {
		if !strings.HasSuffix(h, "]") {
			return "", false
		}
		host = h[1 : len(h)-1]
	} else if strings.Contains(h, ":") {
		// Neither host:port nor a bracketed IPv6 literal (e.g. "localhost:").
		return "", false
	}
	if host == "" {
		return "", false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String(), true
	}
	if strings.Contains(host, ":") {
		return "", false
	}
	return strings.ToLower(host), true
}

func (c *Chain) host(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, ok := hostName(r.Host)
		if !ok || !c.cfg.Resolved.AllowedHost(h) {
			reject(w, http.StatusForbidden, "forbidden\n")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// origin refuses any request that carries an Origin header, whatever its value:
// browser clients are out of scope, and a rebinding page always sends one.
func (c *Chain) origin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, present := r.Header["Origin"]; present {
			reject(w, http.StatusForbidden, "forbidden\n")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authenticate answers every failure with the same bytes. It reads only the
// Authorization header (never the query, a form or a cookie), requires exactly
// one such header, and splits it with strings.Fields as the SDK stage does.
func (c *Chain) authenticate(next http.Handler) http.Handler {
	deny := func(w http.ResponseWriter) {
		reject(w, http.StatusUnauthorized, "unauthorized\n", "WWW-Authenticate", "Bearer")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vals := r.Header.Values("Authorization")
		if len(vals) != 1 {
			deny(w)
			return
		}
		f := strings.Fields(vals[0])
		if len(f) != 2 || !strings.EqualFold(f[0], "bearer") {
			deny(w)
			return
		}
		id, _, ok := c.cfg.Tokens.Verify(f[1])
		if !ok {
			deny(w)
			return
		}
		if info, _ := r.Context().Value(infoKey).(*reqInfo); info != nil {
			info.caller = id
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), verifiedKey, id)))
	})
}

// limit caps requests in flight after authentication. It frees its slot when
// the HTTP handler returns; the tool-level caps in mcpserver are what bound
// camera work that outlives a dropped request.
func (c *Chain) limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if int(c.inflight.Add(1)) > c.cfg.MaxInFlight {
			c.inflight.Add(-1)
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("busy\n"))
			return
		}
		defer c.inflight.Add(-1)
		next.ServeHTTP(w, r)
	})
}

// rateLimitedLog emits at most one line per second and counts what it dropped.
type rateLimitedLog struct {
	mu         sync.Mutex
	now        func() time.Time
	last       time.Time
	suppressed int
}

func (l *rateLimitedLog) log(log *slog.Logger, msg string, attrs []any) {
	l.mu.Lock()
	t := l.now()
	if !l.last.IsZero() && t.Sub(l.last) < time.Second {
		l.suppressed++
		l.mu.Unlock()
		return
	}
	n := l.suppressed
	l.last, l.suppressed = t, 0
	l.mu.Unlock()
	if n > 0 {
		attrs = append(attrs, "suppressed", n)
	}
	log.Warn(msg, attrs...)
}
