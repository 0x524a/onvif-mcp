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
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	onvif "github.com/0x524a/onvif-go"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/redact"
)

// ErrUnknownCamera is returned for an ID that is not in the config.
var ErrUnknownCamera = errors.New("unknown camera")

// maxProbeInFlight bounds how many cameras Probe contacts at once.
const maxProbeInFlight = 8

// defaultProbeBudget is the overall time Probe allows itself when the caller's
// context sets no sooner deadline.
const defaultProbeBudget = 15 * time.Second

// Probe states.
const (
	StateReachable   = "reachable"
	StateUnreachable = "unreachable"
)

// Entry is one configured camera.
//
// The credentials sit behind a pointer to a type that formats safely, and
// Entry formats itself (String, GoString, Format, LogValue) as id, scrubbed
// endpoint and control only. fmt cannot call methods on unexported fields, so
// the pointer indirection is what keeps a bare "%+v" of an Entry, a Registry
// or a map of them from printing the password: nested pointers print as
// addresses. Entry holds no lock, so it is also safe to copy and format by
// value.
type Entry struct {
	id      string
	control bool
	cred    *credentials
}

// credentials is the camera's connection settings, including the password.
type credentials struct {
	// mu guards cam, which only the test hook ever changes.
	mu  sync.RWMutex
	cam config.Camera
}

func (c *credentials) String() string             { return "registry.credentials{REDACTED}" }
func (c *credentials) GoString() string           { return c.String() }
func (c *credentials) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }
func (c *credentials) LogValue() slog.Value       { return slog.StringValue("REDACTED") }

// String renders the entry without credentials.
func (e Entry) String() string {
	return fmt.Sprintf("Entry{id:%q endpoint:%q control:%t}", e.id, e.endpoint(), e.control)
}

// GoString renders the entry without credentials.
func (e Entry) GoString() string { return "registry." + e.String() }

// Format makes every fmt verb print String; no verb can reach the password.
func (e Entry) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		_, _ = io.WriteString(f, e.GoString())
		return
	}
	_, _ = io.WriteString(f, e.String())
}

// LogValue implements slog.LogValuer.
func (e Entry) LogValue() slog.Value {
	return slog.GroupValue(slog.String("id", e.id), slog.String("endpoint", e.endpoint()),
		slog.Bool("control", e.control))
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
	// probeBudget bounds one Probe call as a whole; tests shorten it.
	probeBudget time.Duration
}

// String renders the registry as its camera IDs only.
func (r Registry) String() string {
	ids := make([]string, 0, len(r.entries))
	for id := range r.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return fmt.Sprintf("Registry{cameras:%q}", ids)
}

// GoString renders the registry without credentials.
func (r Registry) GoString() string { return "registry." + r.String() }

// Format makes every fmt verb print String.
func (r Registry) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		_, _ = io.WriteString(f, r.GoString())
		return
	}
	_, _ = io.WriteString(f, r.String())
}

// LogValue implements slog.LogValuer.
func (r Registry) LogValue() slog.Value {
	ids := make([]string, 0, len(r.entries))
	for id := range r.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return slog.GroupValue(slog.Int("cameras", len(ids)), slog.String("ids", strings.Join(ids, ",")))
}

// New builds the registry from config. It makes no network call: a camera that
// is down cannot delay or fail startup. A nil config or nil camera yields an
// empty registry or is skipped.
func New(cfg *config.Config) *Registry {
	r := &Registry{entries: map[string]*Entry{}, probeBudget: defaultProbeBudget}
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
		r.entries[id] = &Entry{id: id, control: c.Control, cred: &credentials{cam: c}}
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
// camera's own timeout and by ctx, so cancelling ctx returns promptly.
// Results are ordered by ID.
//
// Probe also has an overall budget (15s by default) layered on ctx. Without
// it the worst case is ceil(N/8) waves of the per-camera timeout, for example
// 20 hung cameras at 10s each is about 30s. With it, Probe returns within the
// budget plus scheduling slack whatever N and the camera timeouts are; a
// camera not finished by then is reported unreachable with a timeout code.
func (r *Registry) Probe(ctx context.Context) []Status {
	if r == nil || len(r.entries) == 0 {
		return []Status{}
	}
	budget := r.probeBudget
	if budget <= 0 {
		budget = defaultProbeBudget
	}
	ctx, cancelBudget := context.WithTimeout(ctx, budget)
	defer cancelBudget()
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

func (e Entry) status() Status {
	return Status{ID: e.id, Endpoint: e.endpoint(), Control: e.control}
}

// endpoint returns the configured endpoint with credentials scrubbed.
func (e Entry) endpoint() string {
	if e.cred == nil {
		return ""
	}
	e.cred.mu.RLock()
	defer e.cred.mu.RUnlock()
	return redact.Scrub(e.cred.cam.Endpoint)
}

// ID returns the camera's stable handle.
func (e Entry) ID() string { return e.id }

// ControlAllowed reports whether this camera opted in to write tools.
func (e Entry) ControlAllowed() bool { return e.control }

// scrubbedError is an error whose text has already been through
// redact.Scrub, while Unwrap keeps the original chain so errors.Is and
// errors.As (and therefore mcperr.FromError) still work. A caller that logs
// or prints a failure from Client directly cannot leak endpoint userinfo or a
// query secret.
type scrubbedError struct {
	msg string
	err error
}

func (e *scrubbedError) Error() string { return e.msg }
func (e *scrubbedError) Unwrap() error { return e.err }

func scrubbed(err error) error {
	return &scrubbedError{msg: redact.Scrub(err.Error()), err: err}
}

// newTransport returns a private transport with keep-alives off. It sets no
// Proxy, matching onvif-go's own default transport: an HTTP_PROXY in the
// server's environment must not divert camera traffic, which carries
// credentials.
func newTransport() *http.Transport {
	return &http.Transport{DisableKeepAlives: true}
}

// Client returns a new client that has completed Initialize. The caller owns
// it and it is never shared, which is what keeps onvif-go issue #60 out of
// reach. This is the only place a client is obtained; the later events work
// adds its long-lived client here.
//
// ctx cancellation aborts the in-flight request (onvif-go builds its HTTP
// requests with the caller's context). On failure the returned error wraps
// the original and its text is already scrubbed, so mcperr.FromError alone
// classifies it (unreachable, timeout, auth_failed, ...).
func (e Entry) Client(ctx context.Context) (*onvif.Client, error) {
	if e.cred == nil {
		return nil, fmt.Errorf("client for %s: no connection settings", e.id)
	}
	e.cred.mu.RLock()
	cam := e.cred.cam
	e.cred.mu.RUnlock()

	if err := ctx.Err(); err != nil {
		return nil, scrubbed(fmt.Errorf("client for %s: %w", cam.ID, err))
	}

	// A private transport with keep-alives off: no idle connection can outlive
	// the call, and onvif-go v1.2.0 has no Close to release one.
	hc := &http.Client{
		Transport: newTransport(),
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
		return nil, scrubbed(fmt.Errorf("new client for %s: %w", cam.ID, err))
	}
	// Initialize is not a mere connectivity probe: it populates the PTZ and
	// Imaging endpoints, without which those services wrongly report
	// ErrServiceNotSupported.
	if err := c.Initialize(ctx); err != nil {
		return nil, scrubbed(fmt.Errorf("initialize %s: %w", cam.ID, err))
	}
	return c, nil
}

// setEndpointForTest repoints an entry so recovery can be exercised. Test-only.
func (e Entry) setEndpointForTest(endpoint, user, pass string) {
	e.cred.mu.Lock()
	defer e.cred.mu.Unlock()
	e.cred.cam.Endpoint = endpoint
	e.cred.cam.Username = user
	e.cred.cam.Password = pass
}
