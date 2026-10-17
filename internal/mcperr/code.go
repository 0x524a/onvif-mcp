// Package mcperr defines the closed error taxonomy that every onvif-mcp tool
// reports through, spanning both onvif-go and rtspeek failures.
package mcperr

// Code is a stable, machine-readable failure class. These strings are part of
// the contract with the calling agent.
type Code string

// The nine failure codes. The set is closed; see the architecture spec.
const (
	CodeUnreachable     Code = "unreachable"
	CodeTimeout         Code = "timeout"
	CodeAuthFailed      Code = "auth_failed"
	CodeNotSupported    Code = "not_supported"
	CodeNotFound        Code = "not_found"
	CodeInvalidArgument Code = "invalid_argument"
	CodeDeviceFault     Code = "device_fault"
	CodeBlockedByPolicy Code = "blocked_by_policy"
	CodeInternal        Code = "internal"
)

// Retryable reports whether retrying the same call could plausibly succeed
// without operator intervention.
func (c Code) Retryable() bool {
	switch c {
	case CodeUnreachable, CodeTimeout:
		return true
	default:
		return false
	}
}

// SOAPFault carries the device's own fault code, preserved so an agent can
// distinguish vendor quirks.
type SOAPFault struct {
	Code   string `json:"code"`
	Reason string `json:"reason,omitempty"`
}

// ToolError is the structured payload an agent receives on failure.
type ToolError struct {
	Code      Code   `json:"code"`
	Retryable bool   `json:"retryable"`
	Message   string `json:"message"`
	Camera    string `json:"camera,omitempty"`
	Operation string `json:"operation,omitempty"`
	Hint      string `json:"hint,omitempty"`
	// RetryAfterSeconds is set only for rate-limited calls.
	RetryAfterSeconds *int       `json:"retry_after_seconds,omitempty"`
	SOAP              *SOAPFault `json:"soap,omitempty"`
}

// Out is the uniform envelope every tool returns. Exactly one of Data or Error
// is populated. It exists because the SDK's automatic error packing carries
// only err.Error() text, which would discard Code and Retryable.
type Out[T any] struct {
	Data  *T         `json:"data,omitempty"`
	Error *ToolError `json:"error,omitempty"`
}

// OK wraps a successful result.
func OK[T any](d T) Out[T] { return Out[T]{Data: &d} }

// Fail wraps a failure.
func Fail[T any](te *ToolError) Out[T] { return Out[T]{Error: te} }
