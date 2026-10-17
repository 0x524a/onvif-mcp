// Package registry holds the configured cameras and hands out a fresh,
// initialised onvif.Client per call. No client is cached or shared.
//
// onvif-go functions used (github.com/0x524a/onvif-go, pinned v1.2.0):
//   - NewClient            client.go: builds a client from an endpoint
//   - WithCredentials      client.go: sets username and password
//   - WithTimeout          client.go: sets the HTTP client timeout
//   - WithHTTPClient       client.go: supplies the HTTP client, so each client
//     gets its own transport with keep-alives off
//   - (*Client).Initialize client.go: fetches capabilities and populates the
//     PTZ, Imaging and Events endpoints
//
// onvif-go v1.2.0 exposes no Close method, so a client holds nothing that
// needs releasing beyond its HTTP transport. That transport is private to the
// client and has keep-alives disabled, so no idle connection or goroutine
// outlives the call once the caller drops the client.
package registry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"

	onvif "github.com/0x524a/onvif-go"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/redact"
)

// ErrUnknownCamera is returned for an ID that is not in the config.
var ErrUnknownCamera = errors.New("unknown camera")

// maxProbeInFlight bounds how many cameras Probe contacts at once.
const maxProbeInFlight = 8

// Probe states.
const (
	StateReachable   = "reachable"
	StateUnreachable = "unreachable"
)

// Entry is one configured camera.
type Entry struct {
	id      string
	control bool

	// mu guards cfg, which only the test hook ever changes.
	mu  sync.RWMutex
	cfg config.Camera
}

// Status is the display form of an entry, used by camera.list. It never
// contains the password.
type Status struct {
	ID       string `json:"id"`
	Endpoint string `json:"endpoint"`
	State    string `json:"state,omitempty"` // "reachable" | "unreachable"; set only by Probe
	Error    string `json:"error,omitempty"` // scrubbed mcperr message; set only by Probe
	// ErrorCode is the mcperr taxonomy code for Error; set only by Probe.
	ErrorCode string `json:"error_code,omitempty"`
	Control   bool   `json:"control_allowed"`
}

// Registry maps camera ID to entry. It is read-only after New.
type Registry struct {
	entries map[string]*Entry
}

// New builds the registry from config. It makes no network call: a camera that
// is down cannot delay or fail startup. A nil config or nil camera yields an
// empty registry or is skipped.
func New(cfg *config.Config) *Registry {
	r := &Registry{entries: map[string]*Entry{}}
	if cfg == nil {
		return r
	}
	for key, cam := range cfg.Cameras {
		if cam == nil {
			continue
		}
		id := cam.ID
		if id == "" {
			id = key
		}
		c := *cam
		c.ID = id
		r.entries[id] = &Entry{id: id, control: c.Control, cfg: c}
	}
	return r
}

// Get returns the entry for id.
func (r *Registry) Get(id string) (*Entry, error) {
	if r != nil {
		if e, ok := r.entries[id]; ok {
			return e, nil
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownCamera, id)
}

// List returns every configured camera, ordered by ID. No network call. The
// result is a fresh slice; mutating it does not affect the registry.
func (r *Registry) List() []Status {
	if r == nil {
		return []Status{}
	}
	out := make([]Status, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e.status())
	}
	sortStatuses(out)
	return out
}

// Probe initialises every camera and reports which answered. At most
// maxProbeInFlight cameras are contacted at once, each bounded by that
// camera's own timeout and by ctx, so one dead camera cannot hold up the
// result and cancelling ctx returns promptly. Results are ordered by ID.
func (r *Registry) Probe(ctx context.Context) []Status {
	if r == nil || len(r.entries) == 0 {
		return []Status{}
	}
	entries := make([]*Entry, 0, len(r.entries))
	for _, e := range r.entries {
		entries = append(entries, e)
	}
	out := make([]Status, len(entries))
	sem := make(chan struct{}, maxProbeInFlight)
	var wg sync.WaitGroup
	for i, e := range entries {
		wg.Add(1)
		go func(i int, e *Entry) {
			defer wg.Done()
			s := e.status()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				fillError(&s, e.id, ctx.Err())
				out[i] = s
				return
			}
			if _, err := e.Client(ctx); err != nil {
				fillError(&s, e.id, err)
			} else {
				s.State = StateReachable
			}
			out[i] = s
		}(i, e)
	}
	wg.Wait()
	sortStatuses(out)
	return out
}

func fillError(s *Status, id string, err error) {
	te := mcperr.FromError(err, id, "probe")
	s.State = StateUnreachable
	s.Error = te.Message
	s.ErrorCode = string(te.Code)
}

func sortStatuses(s []Status) {
	sort.Slice(s, func(i, j int) bool { return s[i].ID < s[j].ID })
}

func (e *Entry) status() Status {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return Status{ID: e.id, Endpoint: redact.Scrub(e.cfg.Endpoint), Control: e.control}
}

// ID returns the camera's stable handle.
func (e *Entry) ID() string { return e.id }

// ControlAllowed reports whether this camera opted in to write tools.
func (e *Entry) ControlAllowed() bool { return e.control }

// Client returns a new client that has completed Initialize. The caller owns
// it and it is never shared, which is what keeps onvif-go issue #60 out of
// reach. This is the only place a client is obtained; the later events work
// adds its long-lived client here.
//
// ctx cancellation aborts the in-flight request (onvif-go builds its HTTP
// requests with the caller's context). On failure the returned error wraps the
// original, so mcperr.FromError classifies it (unreachable, timeout,
// auth_failed, ...). Its text is not scrubbed; callers report it only through
// mcperr.
func (e *Entry) Client(ctx context.Context) (*onvif.Client, error) {
	e.mu.RLock()
	cam := e.cfg
	e.mu.RUnlock()

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("client for %s: %w", cam.ID, err)
	}

	// A private transport with keep-alives off: no idle connection can outlive
	// the call, and onvif-go v1.2.0 has no Close to release one.
	hc := &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyFromEnvironment,
			DisableKeepAlives: true,
		},
		// Match onvif-go's default: never follow redirects, so http is not
		// silently upgraded or credentials replayed elsewhere.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	c, err := onvif.NewClient(cam.Endpoint,
		onvif.WithHTTPClient(hc),
		onvif.WithCredentials(cam.Username, cam.Password),
		onvif.WithTimeout(cam.Timeout()),
	)
	if err != nil {
		return nil, fmt.Errorf("new client for %s: %w", cam.ID, err)
	}
	// Initialize is not a mere connectivity probe: it populates the PTZ and
	// Imaging endpoints, without which those services wrongly report
	// ErrServiceNotSupported.
	if err := c.Initialize(ctx); err != nil {
		return nil, fmt.Errorf("initialize %s: %w", cam.ID, classify(err))
	}
	return c, nil
}

// classified keeps the original error text but also unwraps to a onvif-go
// sentinel, so mcperr.FromError can classify it.
type classified struct {
	err      error
	sentinel error
}

func (c *classified) Error() string   { return c.err.Error() }
func (c *classified) Unwrap() []error { return []error{c.err, c.sentinel} }

// classify attaches the onvif-go sentinel that onvif-go v1.2.0 itself omits:
// transport failures and authentication faults come back as plain wrapped
// errors with no sentinel, which mcperr would file under "internal". Timeouts
// and cancellation already unwrap to context errors and are left alone.
func classify(err error) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) ||
		errors.Is(err, onvif.ErrTimeout) {
		return err
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return &classified{err: err, sentinel: onvif.ErrTimeout}
	}
	var oe *net.OpError
	var de *net.DNSError
	if errors.As(err, &oe) || errors.As(err, &de) {
		return &classified{err: err, sentinel: onvif.ErrConnectionFailed}
	}
	l := strings.ToLower(err.Error())
	for _, sig := range []string{"authentication failed", "notauthorized", "not authorized", "unauthorized", "status 401"} {
		if strings.Contains(l, sig) {
			return &classified{err: err, sentinel: onvif.ErrAuthenticationFailed}
		}
	}
	return err
}

// setEndpointForTest repoints an entry so recovery can be exercised. Test-only.
func (e *Entry) setEndpointForTest(endpoint, user, pass string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg.Endpoint = endpoint
	e.cfg.Username = user
	e.cfg.Password = pass
}
