package safety

import (
	"context"
	"errors"
	"regexp"
	"strings"
)

// Caller is who is asking. Over stdio it is the operator who started the
// process; over HTTP it is the holder of a bearer token. Every field is
// unexported and the zero value is invalid and refused everywhere, so a code
// path that forgets to establish a caller fails closed. There is deliberately no
// constructor that takes a control boolean:
//
//   - StdioOperator is the only function that yields a Caller with control;
//   - RemoteCaller yields a valid Caller that can never have control.
//
// So a network transport has no API through which it could mint control. The
// remaining by-convention rule (only cmd/onvif-mcp and mcpserver call
// StdioOperator) is pinned by a grep test in cmd/onvif-mcp.
type Caller struct {
	id        string
	transport string
	valid     bool
	control   bool
}

// Valid reports whether the Caller was built by a constructor.
func (c Caller) Valid() bool { return c.valid }

// Control reports whether the Caller may use write and halt tools.
func (c Caller) Control() bool { return c.valid && c.control }

// ID is the bounded caller identifier for audit lines ("stdio" or a token id).
func (c Caller) ID() string { return c.id }

// Transport is "stdio" or the remote transport name.
func (c Caller) Transport() string { return c.transport }

// StdioOperator returns the process operator: valid, with control. It is the
// only constructor that sets the control bit.
func StdioOperator() Caller {
	return Caller{id: "stdio", transport: "stdio", valid: true, control: true}
}

var remoteIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// RemoteCaller returns a valid Caller for a network transport. It never has
// control. id must match the token id grammar; transport must be a short,
// printable name other than "stdio".
func RemoteCaller(id, transport string) (Caller, error) {
	if !remoteIDRe.MatchString(id) {
		return Caller{}, errors.New("caller id is not a valid token id")
	}
	t := strings.ToLower(transport)
	if t == "" || t == "stdio" || len(t) > 16 || !remoteIDRe.MatchString(t) || t != transport {
		return Caller{}, errors.New("caller transport must be a short lowercase name other than stdio")
	}
	return Caller{id: id, transport: transport, valid: true}, nil
}

type callerKey struct{}

// WithCaller stores c in ctx.
func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// CallerFrom returns the Caller in ctx. ok is false when there is none or the
// stored one is invalid; a nil ctx has none.
func CallerFrom(ctx context.Context) (Caller, bool) {
	if ctx == nil {
		return Caller{}, false
	}
	c, ok := ctx.Value(callerKey{}).(Caller)
	if !ok || !c.valid {
		return Caller{}, false
	}
	return c, true
}
