// Package config loads camera definitions and credentials. Credentials live
// here and in the registry only; they never appear in a tool argument.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/0x524a/onvif-mcp/internal/redact"
)

// ErrConfigPermissions is returned when the config file is readable by anyone
// other than its owner. Credentials live in this file, so loose permissions are
// refused rather than warned about.
var ErrConfigPermissions = errors.New("config file must not be group- or world-readable")

// ErrNotRegular is returned when the config path is a directory, FIFO, device
// or other non-regular file.
var ErrNotRegular = errors.New("config path is not a regular file")

const (
	defaultTimeout = 10 * time.Second
	maxTimeoutSecs = 300
	maxConfigBytes = 1 << 20
	redactedMark   = "[REDACTED]"
)

// idRe restricts camera IDs: they appear in tool arguments and env var names.
var idRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Camera is one addressable camera. ID is the config map key, not a field.
// Its formatting and JSON encoding never include Password.
type Camera struct {
	ID             string `json:"-"`
	Endpoint       string `json:"endpoint"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
	// Control opts this camera in to write tools. Defaults false. The
	// process-level flag is a separate, additional gate.
	Control bool `json:"control,omitempty"`
	// TrustAdvertisedHosts lets the camera's advertised service addresses
	// (media, PTZ, imaging) point at a host other than the configured
	// endpoint's. Defaults false: such a request is refused, because a hostile
	// camera could otherwise aim the server, and the WS-Security header it
	// sends, at any host. Set it for NATed or multi-homed cameras.
	TrustAdvertisedHosts bool `json:"trust_advertised_hosts,omitempty"`
	// AllowBasicOverHTTP lets camera.snapshot answer a Basic-only challenge on
	// a plain http request, which sends the password in cleartext (base64 is
	// not encryption) and which an on-path attacker can provoke by rewriting a
	// Digest challenge to Basic. Defaults false. Digest, and Basic over https,
	// are unaffected. Set it only for a camera that offers nothing but Basic on
	// a network you trust.
	AllowBasicOverHTTP bool `json:"allow_basic_over_http,omitempty"`
}

// Timeout returns the configured per-camera timeout, defaulting to 10s.
// onvif-go's own default is 30s, which is too long for an agent that retries.
func (c *Camera) Timeout() time.Duration {
	if c.TimeoutSeconds <= 0 {
		return defaultTimeout
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// String implements fmt.Stringer without exposing the password.
func (c Camera) String() string {
	return fmt.Sprintf("Camera{ID:%q Endpoint:%q Username:%q Password:%s TimeoutSeconds:%d Control:%t}",
		c.ID, redact.Scrub(c.Endpoint), c.Username, redactedMark, c.TimeoutSeconds, c.Control)
}

// GoString implements fmt.GoStringer without exposing the password.
func (c Camera) GoString() string { return "config." + c.String() }

// Format implements fmt.Formatter so that every verb (%v %+v %#v %s %q %x %d)
// prints the redacted form.
func (c Camera) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		_, _ = io.WriteString(f, c.GoString())
		return
	}
	_, _ = io.WriteString(f, c.String())
}

// MarshalJSON encodes the camera with the password replaced by [REDACTED].
// Unmarshalling is unaffected and keeps the real value.
func (c Camera) MarshalJSON() ([]byte, error) {
	type plain Camera // drops methods, avoids recursion
	p := plain(c)
	p.Password = redactedMark
	return json.Marshal(p)
}

// Config is the whole server configuration.
type Config struct {
	Cameras map[string]*Camera `json:"cameras"`
	// ControlEnabled mirrors the --enable-control flag. It is not read from the
	// file by default; main sets it. Kept here so policy has one source.
	ControlEnabled bool `json:"-"`
}

// Load reads and validates a config file. It refuses non-regular files and
// files readable by group or other, applies per-camera password overrides from
// the environment, and registers every password with redact so it is scrubbed
// from any later error or log text.
func Load(path string) (*Config, error) {
	b, err := ReadPrivateFile(path, maxConfigBytes, "config")
	if err != nil {
		return nil, err
	}

	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, parseError(err, b)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse config: unexpected data after the top-level object")
	}
	if dup, err := duplicateCameraID(b); err != nil {
		return nil, parseError(err, b)
	} else if dup != "" {
		return nil, fmt.Errorf("camera ID %q is defined more than once", redact.Scrub(dup))
	}
	if len(cfg.Cameras) == 0 {
		return nil, errors.New("config defines no cameras")
	}

	ids := make([]string, 0, len(cfg.Cameras))
	for id := range cfg.Cameras {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	envOwner := map[string]string{}
	for _, id := range ids {
		if id == "." || id == ".." || !idRe.MatchString(id) {
			return nil, fmt.Errorf("camera ID %q is invalid: must match [A-Za-z0-9._-]{1,64}", id)
		}
		key := envKey(id)
		if other, dup := envOwner[key]; dup {
			return nil, fmt.Errorf("cameras %q and %q both map to environment variable %s", other, id, key)
		}
		envOwner[key] = id
	}

	for _, id := range ids {
		cam := cfg.Cameras[id]
		if cam == nil {
			return nil, fmt.Errorf("camera %q is null", id)
		}
		cam.ID = id
		if strings.TrimSpace(cam.Endpoint) == "" {
			return nil, fmt.Errorf("camera %q has an empty endpoint", id)
		}
		if hasUserinfo(cam.Endpoint) {
			return nil, fmt.Errorf("camera %q endpoint embeds credentials (user:pass@host); use the username and password fields", id)
		}
		if err := checkEndpoint(cam.Endpoint); err != nil {
			return nil, fmt.Errorf("camera %q endpoint %w", id, err)
		}
		if cam.TimeoutSeconds < 0 || cam.TimeoutSeconds > maxTimeoutSecs {
			return nil, fmt.Errorf("camera %q timeout_seconds must be between 0 and %d", id, maxTimeoutSecs)
		}
		if v, ok := os.LookupEnv(envKey(id)); ok {
			if v == "" {
				return nil, fmt.Errorf("camera %q: environment variable %s is set but empty; unset it or give it a value", id, envKey(id))
			}
			cam.Password = v
		}
		if cam.Password != "" && !redact.RegisterSecret(cam.Password) {
			return nil, fmt.Errorf("camera %q: password cannot be protected from log leakage (too short or secret registry full)", id)
		}
	}
	return &cfg, nil
}

// parseError turns a JSON error into one that cannot quote config values. b is
// the file's bytes, used to find the offset of an unexpected end and to name
// the camera an error is in.
func parseError(err error, b []byte) error {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return fmt.Errorf("parse config: invalid JSON at byte %d", syn.Offset)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return fmt.Errorf("parse config: invalid JSON at byte %d (the file ends too soon)", len(b))
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		name, uerr := strconv.Unquote(strings.TrimPrefix(err.Error(), "json: unknown field "))
		if uerr != nil || len(name) > 64 {
			return errors.New("parse config: unknown field")
		}
		if id := cameraWithKey(b, name); id != "" {
			return fmt.Errorf("parse config: camera %q has an unknown field %q", id, redact.Scrub(name))
		}
		return fmt.Errorf("parse config: unknown field %q", redact.Scrub(name))
	case errors.As(err, &typ):
		field := typ.Field
		if i := strings.LastIndexByte(field, '.'); i >= 0 {
			field = field[i+1:]
		}
		if id := cameraAtOffset(b, typ.Offset); id != "" {
			return fmt.Errorf("parse config: camera %q: field %q has the wrong type (expected %s)", id, redact.Scrub(field), typ.Type)
		}
		return fmt.Errorf("parse config: field %q has the wrong type (expected %s)", redact.Scrub(typ.Field), typ.Type)
	default:
		return errors.New("parse config: malformed JSON")
	}
}

// walkCameras calls fn for every camera entry of the top-level "cameras"
// object of already-parsed JSON: the id, the offset just after its key, and
// its raw value. fn returns false to stop. Errors end the walk silently: this
// only improves messages.
func walkCameras(b []byte, fn func(id string, keyEnd int64, val json.RawMessage) bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if _, err := dec.Token(); err != nil {
		return
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return
		}
		if key, _ := kt.(string); key != "cameras" {
			var skip json.RawMessage
			if dec.Decode(&skip) != nil {
				return
			}
			continue
		}
		if d, err := dec.Token(); err != nil {
			return
		} else if dl, ok := d.(json.Delim); !ok || dl != '{' {
			continue
		}
		for dec.More() {
			it, err := dec.Token()
			if err != nil {
				return
			}
			id, _ := it.(string)
			end := dec.InputOffset()
			var val json.RawMessage
			if dec.Decode(&val) != nil || !fn(id, end, val) {
				return
			}
		}
		return
	}
}

// cameraWithKey returns the first camera whose entry has a key called name.
func cameraWithKey(b []byte, name string) (found string) {
	walkCameras(b, func(id string, _ int64, val json.RawMessage) bool {
		var m map[string]json.RawMessage
		if json.Unmarshal(val, &m) == nil {
			if _, ok := m[name]; ok {
				found = id
				return false
			}
		}
		return true
	})
	return found
}

// cameraAtOffset returns the camera whose entry contains byte offset off.
func cameraAtOffset(b []byte, off int64) (found string) {
	walkCameras(b, func(id string, keyEnd int64, _ json.RawMessage) bool {
		if keyEnd < off {
			found = id
			return true
		}
		return false
	})
	return found
}

// hasUserinfo reports whether the authority part of endpoint contains '@'.
// Endpoints may omit the scheme (a bare host), so this is a string check
// rather than a URL parse.
func hasUserinfo(endpoint string) bool {
	rest := endpoint
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	return strings.Contains(rest, "@")
}

// envKey builds the per-camera password override variable, e.g. camera
// "front-door" reads ONVIF_MCP_FRONT_DOOR_PASSWORD.
func envKey(id string) string {
	up := strings.ToUpper(id)
	up = strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(up)
	return "ONVIF_MCP_" + up + "_PASSWORD"
}

// checkEndpoint limits the scheme to none, http or https and requires a
// parseable host. Its errors never include the endpoint text, because
// url.Parse errors quote their input.
func checkEndpoint(endpoint string) error {
	ep := strings.TrimSpace(endpoint)
	rest := ep
	if i := strings.Index(ep, "://"); i >= 0 {
		switch strings.ToLower(ep[:i]) {
		case "http", "https":
			rest = ep[i+3:]
		default:
			return errors.New("has an unsupported scheme (only http, https or none)")
		}
	}
	u, err := url.Parse("http://" + rest)
	if err != nil || u.Host == "" || u.User != nil || strings.HasSuffix(u.Host, ":") {
		return errors.New("is not a valid host or URL")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return errors.New("has an invalid port")
		}
	}
	return nil
}

// duplicateCameraID walks the already-validated JSON and returns the first
// repeated key inside the top-level "cameras" object, or "".
func duplicateCameraID(b []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if _, err := dec.Token(); err != nil { // top-level '{'
		return "", err
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return "", err
		}
		if key, _ := kt.(string); key != "cameras" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return "", err
			}
			continue
		}
		vt, err := dec.Token()
		if err != nil {
			return "", err
		}
		if d, ok := vt.(json.Delim); !ok || d != '{' {
			continue // null; nothing to check
		}
		seen := map[string]bool{}
		for dec.More() {
			it, err := dec.Token()
			if err != nil {
				return "", err
			}
			id, _ := it.(string)
			if seen[id] {
				return id, nil
			}
			seen[id] = true
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return "", err
			}
		}
		if _, err := dec.Token(); err != nil { // closing '}'
			return "", err
		}
	}
	return "", nil
}

// ReadPrivateFile reads a small secret-bearing file the way Load reads the
// config: it refuses anything but a regular file, anything readable by group or
// other (ErrConfigPermissions), and anything over max bytes. The permission
// check is on the opened handle, not the path, so the checked file is the read
// file, and opening a FIFO cannot block. what names the file in error text
// ("config", "token file"); no file content is ever put in an error.
func ReadPrivateFile(path string, limit int, what string) ([]byte, error) {
	// O_NONBLOCK so opening a FIFO returns immediately instead of waiting for
	// a writer; the Stat below then rejects it.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // path is operator supplied
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", what, err)
	}
	defer func() { _ = f.Close() }()

	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", what, err)
	}
	if !st.Mode().IsRegular() {
		return nil, ErrNotRegular
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %v; run: chmod 600 %s", ErrConfigPermissions, path, st.Mode().Perm(), path)
	}

	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", what, err)
	}
	if len(b) > limit {
		return nil, fmt.Errorf("%s file too large", what)
	}
	return b, nil
}
