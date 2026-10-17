// Package config loads camera definitions and credentials. Credentials live
// here and in the registry only; they never appear in a tool argument.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/0x524a/onvif-mcp/internal/redact"
)

// ErrConfigPermissions is returned when the config file is readable by anyone
// other than its owner. Credentials live in this file, so loose permissions are
// refused rather than warned about.
var ErrConfigPermissions = errors.New("config file must not be group- or world-readable")

const (
	defaultTimeout = 10 * time.Second
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
	f, err := os.Open(path) //nolint:gosec // path is operator supplied
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Stat the opened handle, not the path, so the checked file is the read file.
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat config: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("config path is not a regular file")
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %v", ErrConfigPermissions, path, st.Mode().Perm())
	}

	b, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if len(b) > maxConfigBytes {
		return nil, errors.New("config file too large")
	}

	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, parseError(err)
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
		if !idRe.MatchString(id) {
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
		if v, ok := os.LookupEnv(envKey(id)); ok {
			cam.Password = v
		}
		if cam.Password != "" && !redact.RegisterSecret(cam.Password) {
			return nil, fmt.Errorf("camera %q: password cannot be protected from log leakage (too short or secret registry full)", id)
		}
	}
	return &cfg, nil
}

// parseError turns a JSON error into one that cannot quote config values.
func parseError(err error) error {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return fmt.Errorf("parse config: invalid JSON at byte %d", syn.Offset)
	case errors.As(err, &typ):
		return fmt.Errorf("parse config: field %q has the wrong type (expected %s)", redact.Scrub(typ.Field), typ.Type)
	default:
		return errors.New("parse config: malformed JSON")
	}
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
