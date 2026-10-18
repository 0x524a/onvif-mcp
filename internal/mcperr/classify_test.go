package mcperr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"

	onvif "github.com/0x524a/onvif-go"
)

func TestCancellationIsInternalNotRetryableWithHint(t *testing.T) {
	err := fmt.Errorf("client for c: %w", context.Canceled)
	te := FromError(err, "c", "probe")
	if te.Code != CodeInternal || te.Retryable {
		t.Fatalf("code=%s retryable=%v, want internal/false", te.Code, te.Retryable)
	}
	if te.Hint != "the call was cancelled before the camera answered" {
		t.Errorf("hint = %q", te.Hint)
	}
}

func TestTransportFailuresClassifyWithoutSentinels(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want Code
	}{
		{"typed op error", &url.Error{Op: "Post", URL: "http://h/", Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}}, CodeUnreachable},
		{"typed dns", &net.DNSError{Err: "no such host", Name: "h"}, CodeUnreachable},
		{"text refused", errors.New("failed to send HTTP request: dial tcp 10.0.0.1:80: connect: connection refused"), CodeUnreachable},
		{"text no route", errors.New("dial tcp 10.0.0.1:80: connect: no route to host"), CodeUnreachable},
		{"text net unreachable", errors.New("dial tcp 10.0.0.1:80: connect: network is unreachable"), CodeUnreachable},
		{"text no such host", errors.New("dial tcp: lookup cam.invalid: no such host"), CodeUnreachable},
		{"text reset", errors.New("read tcp 1.2.3.4:5->6.7.8.9:80: read: connection reset by peer"), CodeUnreachable},
		{"io timeout text", errors.New("read tcp 1.2.3.4:5->6.7.8.9:80: i/o timeout"), CodeTimeout},
		{"eof", fmt.Errorf("failed to send HTTP request: %w", &url.Error{Op: "Post", URL: "http://h/", Err: io.EOF}), CodeUnreachable},
		{"closed idle", errors.New(`Post "http://h/x": http: server closed idle connection`), CodeUnreachable},
		{"unexpected eof", fmt.Errorf("failed to read response body: %w", io.ErrUnexpectedEOF), CodeUnreachable},
	}
	for _, c := range cases {
		te := FromError(c.err, "c", "op")
		if te.Code != c.want {
			t.Errorf("%s: code=%s, want %s (%v)", c.name, te.Code, c.want, c.err)
		}
		if te.Hint == "" {
			t.Errorf("%s: empty hint", c.name)
		}
		if te.Retryable != c.want.Retryable() {
			t.Errorf("%s: retryable=%v", c.name, te.Retryable)
		}
	}
}

// TLS and scheme mismatches are operator configuration problems: retrying
// cannot help, so they are invalid_argument rather than the retryable
// unreachable.
func TestTLSFailuresAreInvalidArgumentWithPreciseHint(t *testing.T) {
	cases := map[string]error{
		"unknown authority": &url.Error{Op: "Post", URL: "https://h/", Err: &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}},
		"hostname":          &url.Error{Op: "Post", URL: "https://h/", Err: x509.HostnameError{Host: "h"}},
		"record header":     &url.Error{Op: "Post", URL: "https://h/", Err: tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}},
		"text x509":         errors.New("Post \"https://h/\": x509: certificate signed by unknown authority"),
		"text tls":          errors.New("remote error: tls: handshake failure"),
		"http to https":     errors.New(`Post "https://h/x": http: server gave HTTP response to HTTPS client`),
	}
	for name, err := range cases {
		te := FromError(err, "c", "op")
		if te.Code != CodeInvalidArgument || te.Retryable {
			t.Errorf("%s: code=%s retryable=%v", name, te.Code, te.Retryable)
		}
		if !strings.Contains(te.Hint, "http vs https") || !strings.Contains(te.Hint, "certificate") {
			t.Errorf("%s: hint = %q", name, te.Hint)
		}
	}
}

func TestGarbageResponsesAreDeviceFault(t *testing.T) {
	for _, msg := range []string{
		`Post "http://h/": malformed HTTP response "\x00\x01garbage"`,
		`Post "http://h/x": malformed HTTP status code "http"`,
		`Post "http://h/x": malformed HTTP version "x"`,
		`Post "http://h/x": readLoopPeekFailLocked: %!w(<nil>)`,
		"initialize c: failed to unmarshal SOAP envelope: EOF",
		"failed to unmarshal SOAP envelope: XML syntax error on line 1",
	} {
		te := FromError(errors.New(msg), "c", "op")
		if te.Code != CodeDeviceFault || te.Retryable {
			t.Errorf("%q: code=%s retryable=%v", msg, te.Code, te.Retryable)
		}
		if !strings.Contains(te.Hint, "not an ONVIF") {
			t.Errorf("%q: hint = %q", msg, te.Hint)
		}
	}
}

func TestHTTPStatusBeatsNotFoundHeuristic(t *testing.T) {
	cases := []struct {
		msg      string
		want     Code
		hint     string
		retry    bool
		notInHnt string
	}{
		{"initialize c: HTTP request failed with status 404: 404 page not found", CodeInvalidArgument, "endpoint path", false, "list the available tokens"},
		{"HTTP request failed with status 401: ", CodeAuthFailed, "username and password", false, ""},
		{"HTTP request failed with status 403: forbidden", CodeAuthFailed, "username and password", false, ""},
		{"HTTP request failed with status 502: host not found", CodeUnreachable, "gateway", true, "list the available tokens"},
		{"HTTP request failed with status 503: no such service", CodeUnreachable, "gateway", true, ""},
		{"HTTP request failed with status 504: ", CodeUnreachable, "gateway", true, ""},
		{"HTTP request failed with status 301: ", CodeInvalidArgument, "redirect", false, ""},
		{"HTTP request failed with status 302: ", CodeInvalidArgument, "redirect", false, ""},
		{"HTTP request failed with status 307: ", CodeInvalidArgument, "redirect", false, ""},
		{"HTTP request failed with status 308: ", CodeInvalidArgument, "redirect", false, ""},
		{"HTTP request failed with status 400: SOAP fault: Authentication failed: Invalid username or password", CodeAuthFailed, "username and password", false, ""},
		// A 500 SOAP fault about a missing token is still not_found.
		{"HTTP request failed with status 500: SOAP fault: preset not found: p9", CodeNotFound, "list the available tokens", false, ""},
	}
	for _, c := range cases {
		te := FromError(errors.New(c.msg), "c", "op")
		if te.Code != c.want || te.Retryable != c.retry {
			t.Errorf("%q: code=%s retryable=%v, want %s/%v", c.msg, te.Code, te.Retryable, c.want, c.retry)
		}
		if !strings.Contains(te.Hint, c.hint) {
			t.Errorf("%q: hint %q lacks %q", c.msg, te.Hint, c.hint)
		}
		if c.notInHnt != "" && strings.Contains(te.Hint, c.notInHnt) {
			t.Errorf("%q: hint %q must not contain %q", c.msg, te.Hint, c.notInHnt)
		}
	}
}

// A port number that merely contains "401" is not an auth failure.
func TestPortContaining401IsNotAuth(t *testing.T) {
	te := FromError(errors.New("dial tcp 10.0.0.1:4010: connect: connection refused"), "c", "op")
	if te.Code != CodeUnreachable {
		t.Errorf("code = %s", te.Code)
	}
}

func TestSentinelStillWinsOverText(t *testing.T) {
	err := fmt.Errorf("HTTP request failed with status 404: %w", onvif.ErrServiceNotSupported)
	if te := FromError(err, "c", "op"); te.Code != CodeNotSupported {
		t.Errorf("code = %s", te.Code)
	}
}

func TestHTTPBodyNeverEchoedInMessage(t *testing.T) {
	body := `<?xml version="1.0"?><s:Envelope><Header><wsse:Security><wsse:UsernameToken><wsse:Password Type="x#PasswordDigest">DIGESTSECRET</wsse:Password><wsse:Nonce>NONCESECRET</wsse:Nonce></wsse:UsernameToken></wsse:Security></Header></s:Envelope>`
	err := errors.New("initialize c: HTTP request failed with status 500: " + body)
	te := FromError(err, "c", "op")
	for _, leak := range []string{"DIGESTSECRET", "NONCESECRET", "<s:Envelope", "<?xml"} {
		if strings.Contains(te.Message, leak) {
			t.Errorf("message echoes %q: %q", leak, te.Message)
		}
	}
	if !strings.Contains(te.Message, "HTTP request failed with status 500") {
		t.Errorf("status lost: %q", te.Message)
	}
	// The prefix text before the first '<' is kept.
	te = FromError(errors.New("HTTP request failed with status 500: SOAP fault: boom <detail>x</detail>"), "c", "op")
	if !strings.Contains(te.Message, "SOAP fault: boom") || strings.Contains(te.Message, "<detail>") {
		t.Errorf("message = %q", te.Message)
	}
}

// The camera's reply body is not evidence: no word in it may choose the class.
func TestReplyBodyDoesNotSteerClassification(t *testing.T) {
	for _, body := range []string{
		"<html>unauthorized</html>", "unauthorized", "authentication failed",
		"<html>not found</html>", "not found", "no such preset", "NoEntity",
		"connection refused", "i/o timeout",
	} {
		err := fmt.Errorf("failed to send HTTP request: HTTP request failed with status 500: %s", body)
		te := FromError(err, "cam", "GotoPreset")
		if te.Code != CodeInternal {
			t.Errorf("body %q: code = %s, want internal", body, te.Code)
		}
	}
}

// The status line is still evidence.
func TestHTTPStatusStillClassifiesWithoutTheBody(t *testing.T) {
	for status, want := range map[int]Code{401: CodeAuthFailed, 403: CodeAuthFailed, 404: CodeInvalidArgument, 503: CodeUnreachable} {
		err := fmt.Errorf("HTTP request failed with status %d: <html>whatever</html>", status)
		if te := FromError(err, "cam", "Op"); te.Code != want {
			t.Errorf("status %d: code = %s, want %s", status, te.Code, want)
		}
	}
}
