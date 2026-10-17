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
	Code   string `json:"code" jsonschema:"the fault code exactly as the camera sent it, for example ter:NotAuthorized or ter:NoEntity"`
	Reason string `json:"reason,omitempty" jsonschema:"the fault reason text the camera sent; absent when it sent none"`
}

// ToolError is the structured payload an agent receives on failure.
type ToolError struct {
	Code      Code   `json:"code" jsonschema:"failure class, one of: unreachable, timeout, auth_failed, not_supported, not_found, invalid_argument, device_fault, blocked_by_policy, internal"`
	Retryable bool   `json:"retryable" jsonschema:"true when repeating the identical call may succeed with no one changing anything (unreachable, timeout); false means the cause must be fixed first, so do not retry in a loop"`
	Message   string `json:"message" jsonschema:"what failed, as the operation name and the root cause; credentials are removed"`
	Camera    string `json:"camera,omitempty" jsonschema:"the camera id the call addressed; absent when no camera was involved"`
	Operation string `json:"operation,omitempty" jsonschema:"the ONVIF operation that failed; Initialize means connecting to the camera before any operation ran"`
	Hint      string `json:"hint,omitempty" jsonschema:"the next step to try, written for the calling agent"`
	// RetryAfterSeconds is set only for rate-limited calls.
	RetryAfterSeconds *int       `json:"retry_after_seconds,omitempty" jsonschema:"wait this many seconds before retrying; present only for calls refused by a rate limit"`
	SOAP              *SOAPFault `json:"soap,omitempty" jsonschema:"the camera's own SOAP fault, present when the camera answered with one"`
}

// Out is the uniform envelope every tool returns. Exactly one of Data or Error
// is populated. It exists because the SDK's automatic error packing carries
// only err.Error() text, which would discard Code and Retryable.
type Out[T any] struct {
	Data  *T         `json:"data,omitempty" jsonschema:"the result; present only when the call succeeded"`
	Error *ToolError `json:"error,omitempty" jsonschema:"present only when the call failed; the result is then also flagged isError"`
}

// OK wraps a successful result.
func OK[T any](d T) Out[T] { return Out[T]{Data: &d} }

// Fail wraps a failure.
func Fail[T any](te *ToolError) Out[T] { return Out[T]{Error: te} }
