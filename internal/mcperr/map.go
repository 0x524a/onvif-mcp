package mcperr

import (
	"context"
	"errors"
	"strings"

	"github.com/0x524A/rtspeek/pkg/rtspeek"
	onvif "github.com/0x524a/onvif-go"

	"github.com/0x524a/onvif-mcp/internal/redact"
)

// classifier is reused rather than reimplemented: rtspeek exports its taxonomy
// but never applies it to the errors DescribeStream returns.
var classifier = rtspeek.NewErrorClassifier()

// isAuthSignal reports whether text indicates an authentication failure. It is
// used both for SOAP fault codes and for RTSP error text.
func isAuthSignal(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "notauthorized") ||
		strings.Contains(l, "not authorized") ||
		strings.Contains(l, "unauthorized") ||
		strings.Contains(l, "401")
}

// FromError maps an onvif-go error onto the taxonomy.
//
// Order matters: *ONVIFError has no Unwrap method, so it can never match a
// sentinel through errors.Is. It is therefore checked first with errors.As.
func FromError(err error, camera, operation string) *ToolError {
	if err == nil {
		return nil
	}
	return sanitize(fromError(err, camera, operation))
}

// sanitize scrubs every free-text field of te, as defence in depth: no
// constructor path may emit credentials regardless of where the text came from.
func sanitize(te *ToolError) *ToolError {
	te.Message = redact.Scrub(te.Message)
	te.Hint = redact.Scrub(te.Hint)
	te.Camera = redact.Scrub(te.Camera)
	te.Operation = redact.Scrub(te.Operation)
	if te.SOAP != nil {
		te.SOAP.Code = redact.Scrub(te.SOAP.Code)
		te.SOAP.Reason = redact.Scrub(te.SOAP.Reason)
	}
	return te
}

func fromError(err error, camera, operation string) *ToolError {
	if err == nil {
		return nil
	}
	te := &ToolError{
		Camera:    camera,
		Operation: operation,
		Message:   redact.Scrub(err.Error()),
	}

	var oe *onvif.ONVIFError
	if errors.As(err, &oe) {
		te.SOAP = &SOAPFault{Code: oe.Code, Reason: oe.Reason}
		if isAuthSignal(oe.Code) || isAuthSignal(oe.Reason) {
			te.Code = CodeAuthFailed
			te.Hint = "verify the username and password configured for this camera"
		} else {
			te.Code = CodeDeviceFault
			te.Hint = "the device returned a SOAP fault; the operation may be advertised but not implemented"
		}
		te.Retryable = te.Code.Retryable()
		return te
	}

	switch {
	case errors.Is(err, onvif.ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		te.Code = CodeTimeout
		te.Hint = "the camera did not answer in time; retry, or raise its configured timeout"
	case errors.Is(err, onvif.ErrConnectionFailed):
		te.Code = CodeUnreachable
		te.Hint = "check power, network reachability, and the configured endpoint"
	case errors.Is(err, onvif.ErrAuthenticationFailed),
		errors.Is(err, onvif.ErrAuthenticationRequired):
		te.Code = CodeAuthFailed
		te.Hint = "verify the username and password configured for this camera"
	case errors.Is(err, onvif.ErrServiceNotSupported),
		errors.Is(err, onvif.ErrPTZNotSupported),
		errors.Is(err, onvif.ErrSnapshotNotSupported):
		te.Code = CodeNotSupported
		te.Hint = "this camera does not implement the requested service"
	case errors.Is(err, onvif.ErrProfileNotFound),
		errors.Is(err, onvif.ErrPresetNotFound),
		errors.Is(err, onvif.ErrVideoSourceNotFound):
		te.Code = CodeNotFound
		te.Hint = "list the available tokens first, then pass one of them"
	case errors.Is(err, onvif.ErrInvalidParameter),
		errors.Is(err, onvif.ErrInvalidEndpoint),
		errors.Is(err, onvif.ErrInvalidEndpointFormat):
		te.Code = CodeInvalidArgument
	default:
		te.Code = CodeInternal
	}
	te.Retryable = te.Code.Retryable()
	return te
}

// FromStreamError maps an rtspeek error onto the taxonomy, reusing rtspeek's
// own classifier and then correcting for two ordering weaknesses in it.
func FromStreamError(err error, camera, operation string) *ToolError {
	if err == nil {
		return nil
	}
	return sanitize(fromStreamError(err, camera, operation))
}

func fromStreamError(err error, camera, operation string) *ToolError {
	if err == nil {
		return nil
	}
	te := &ToolError{
		Camera:    camera,
		Operation: operation,
		Message:   redact.Scrub(err.Error()),
	}

	if errors.Is(err, rtspeek.ErrInvalidURL) {
		te.Code = CodeInvalidArgument
		return te
	}

	reason := classifier.Classify(err)

	// Classify tests for "closed" before it tests for auth, so an error reading
	// "connection closed after 401 Unauthorized" returns connection_closed; and
	// a 401 carrying no WWW-Authenticate header returns other. Re-check auth
	// before accepting either verdict.
	if (reason == "connection_closed" || reason == "other") && isAuthSignal(err.Error()) {
		reason = "auth_required"
	}

	switch reason {
	case "connection_refused", "dns_error", "connection_closed":
		te.Code = CodeUnreachable
		te.Hint = "the stream endpoint is not reachable from this host"
	case "timeout":
		te.Code = CodeTimeout
	case "auth_required":
		te.Code = CodeAuthFailed
		te.Hint = "the stream rejected the camera's configured credentials"
	case "not_found":
		te.Code = CodeNotFound
	case "unsupported_scheme":
		te.Code = CodeInvalidArgument
	default:
		te.Code = CodeInternal
	}
	te.Retryable = te.Code.Retryable()
	return te
}

// Blocked builds the payload for a call refused by onvif-mcp's own policy
// rather than by the camera. A non-nil retryAfterSeconds marks it retryable.
func Blocked(camera, operation, message string, retryAfterSeconds *int) *ToolError {
	te := &ToolError{
		Code:      CodeBlockedByPolicy,
		Camera:    camera,
		Operation: operation,
		Message:   message,
	}
	if retryAfterSeconds != nil {
		te.Retryable = true
		te.RetryAfterSeconds = retryAfterSeconds
	}
	return sanitize(te)
}
