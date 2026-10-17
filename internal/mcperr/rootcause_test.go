package mcperr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"

	onvif "github.com/0x524a/onvif-go"

	"github.com/0x524a/onvif-mcp/internal/redact"
)

// chain builds the wrapper stack onvif-go and the registry put around a
// transport failure.
func chain(inner error) error {
	return fmt.Errorf("initialize front-door: %w",
		fmt.Errorf("failed to get capabilities: %w",
			fmt.Errorf("GetCapabilities failed: %w",
				fmt.Errorf("failed to send HTTP request: %w",
					&url.Error{Op: "Post", URL: "http://192.0.2.10/onvif/device_service", Err: inner}))))
}

// A message names the operation and the root cause, not the library's wrapper
// stack or the request URL.
func TestMessageIsOperationAndRootCause(t *testing.T) {
	te := FromError(chain(context.DeadlineExceeded), "front-door", "GetProfiles")
	if te.Message != "GetProfiles failed: context deadline exceeded" {
		t.Errorf("message = %q", te.Message)
	}
	if te.Code != CodeTimeout {
		t.Errorf("code = %s", te.Code)
	}
	for _, noise := range []string{"initialize", "failed to get capabilities", "GetCapabilities failed", "192.0.2.10", "Post"} {
		if strings.Contains(te.Message, noise) {
			t.Errorf("message keeps wrapper noise %q: %q", noise, te.Message)
		}
	}

	refused := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}
	te = FromError(chain(refused), "front-door", "Initialize")
	if te.Message != "Initialize failed: connect: connection refused" {
		t.Errorf("message = %q", te.Message)
	}
	if te.Code != CodeUnreachable {
		t.Errorf("code = %s", te.Code)
	}
}

func TestMessageWithoutOperationIsRootCause(t *testing.T) {
	te := FromError(chain(context.DeadlineExceeded), "", "")
	if te.Message != "context deadline exceeded" {
		t.Errorf("message = %q", te.Message)
	}
}

// A layer that is not a plain prefix wrapper (here an HTTP status line that
// carries information the sentinel underneath does not) is kept whole.
func TestMessageKeepsStatusLine(t *testing.T) {
	err := fmt.Errorf("initialize c: %w", fmt.Errorf("%w with status %d: %s", errors.New("HTTP request failed"), 503, "busy"))
	te := FromError(err, "c", "GetProfiles")
	if !strings.Contains(te.Message, "HTTP request failed with status 503") {
		t.Errorf("status lost: %q", te.Message)
	}
	if strings.Contains(te.Message, "initialize c") {
		t.Errorf("wrapper kept: %q", te.Message)
	}
	if te.Code != CodeUnreachable {
		t.Errorf("code = %s", te.Code)
	}
}

func TestMessageSOAPFaultBehindWrappers(t *testing.T) {
	err := fmt.Errorf("initialize c: %w", fmt.Errorf("GetProfiles failed: %w",
		errors.New("HTTP request failed with status 500: SOAP fault: [ter:NoProfile] no such profile")))
	te := FromError(err, "c", "GetProfiles")
	if te.Message != "GetProfiles failed: HTTP request failed with status 500: SOAP fault: [ter:NoProfile] no such profile" {
		t.Errorf("message = %q", te.Message)
	}
	if te.SOAP == nil || te.SOAP.Code != "ter:NoProfile" {
		t.Errorf("soap = %+v", te.SOAP)
	}
}

func TestMessageONVIFErrorBehindWrappers(t *testing.T) {
	err := fmt.Errorf("initialize c: %w", onvif.NewONVIFError("ter:Action", "Prohibited", "nope"))
	te := FromError(err, "c", "GetProfiles")
	if strings.Contains(te.Message, "initialize c") || !strings.Contains(te.Message, "Prohibited") {
		t.Errorf("message = %q", te.Message)
	}
}

// The root cause is scrubbed like everything else, including when the scrubbed
// wrapper text no longer ends with the child's text.
func TestRootCauseScrubbed(t *testing.T) {
	inner := errors.New("dial rtsp://admin:hunter2@192.0.2.10/s: connection refused")
	te := FromError(fmt.Errorf("outer: %w", inner), "c", "op")
	if strings.Contains(te.Message, "hunter2") {
		t.Errorf("secret in message: %q", te.Message)
	}
	if !strings.Contains(te.Message, "192.0.2.10") {
		t.Errorf("host lost: %q", te.Message)
	}
}

// The timeout hint must be something an agent can act on: it cannot change the
// config, so it is told to ask the operator.
func TestTimeoutHintNamesOperator(t *testing.T) {
	for _, err := range []error{context.DeadlineExceeded, chain(context.DeadlineExceeded), errors.New("read tcp: i/o timeout")} {
		te := FromError(err, "c", "op")
		if te.Code != CodeTimeout {
			t.Fatalf("code = %s for %v", te.Code, err)
		}
		if !strings.Contains(te.Hint, "ask the operator") || !strings.Contains(te.Hint, "timeout_seconds") {
			t.Errorf("hint = %q", te.Hint)
		}
	}
}

// scrubWrap mirrors the registry's wrapper: its text is the scrubbed text of
// the error it wraps, which then no longer ends with the inner text verbatim.
type scrubWrap struct{ err error }

func (e scrubWrap) Error() string { return redact.Scrub(e.err.Error()) }
func (e scrubWrap) Unwrap() error { return e.err }

func TestRootCauseSeesThroughAScrubbedWrapper(t *testing.T) {
	inner := &url.Error{Op: "Post", URL: "http://admin:hunter2@192.0.2.10/onvif/device_service", Err: context.DeadlineExceeded} //nolint:gosec // fake test fixture
	err := scrubWrap{fmt.Errorf("initialize c: %w", fmt.Errorf("failed to send HTTP request: %w", inner))}
	te := FromError(err, "c", "GetProfiles")
	if te.Message != "GetProfiles failed: context deadline exceeded" {
		t.Errorf("message = %q", te.Message)
	}
	if te.Code != CodeTimeout {
		t.Errorf("code = %s", te.Code)
	}
}
