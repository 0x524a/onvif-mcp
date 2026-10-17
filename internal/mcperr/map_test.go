package mcperr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/0x524A/rtspeek/pkg/rtspeek"
	onvif "github.com/0x524a/onvif-go"
)

func TestONVIFErrorCheckedBeforeSentinels(t *testing.T) {
	// A SOAP fault must map to device_fault and keep its fault code, even
	// though *ONVIFError has no Unwrap and matches no sentinel.
	err := onvif.NewONVIFError("ter:Action", "OperationProhibited", "not implemented")
	te := FromError(err, "cam-a", "GotoPreset")
	if te.Code != CodeDeviceFault {
		t.Errorf("got %s want %s", te.Code, CodeDeviceFault)
	}
	if te.SOAP == nil || te.SOAP.Code != "ter:Action" {
		t.Errorf("SOAP fault code not preserved: %+v", te.SOAP)
	}
	if te.Camera != "cam-a" || te.Operation != "GotoPreset" {
		t.Errorf("context lost: %+v", te)
	}
}

func TestONVIFAuthFaultMapsToAuthFailed(t *testing.T) {
	err := onvif.NewONVIFError("ter:NotAuthorized", "NotAuthorized", "bad creds")
	te := FromError(err, "cam-a", "GetProfiles")
	if te.Code != CodeAuthFailed {
		t.Errorf("got %s want %s", te.Code, CodeAuthFailed)
	}
	if te.Retryable {
		t.Error("auth_failed must not be retryable")
	}
}

func TestSentinelMapping(t *testing.T) {
	cases := []struct {
		err  error
		want Code
	}{
		{onvif.ErrTimeout, CodeTimeout},
		{context.DeadlineExceeded, CodeTimeout},
		{onvif.ErrConnectionFailed, CodeUnreachable},
		{onvif.ErrAuthenticationFailed, CodeAuthFailed},
		{onvif.ErrAuthenticationRequired, CodeAuthFailed},
		{onvif.ErrServiceNotSupported, CodeNotSupported},
		{onvif.ErrPTZNotSupported, CodeNotSupported},
		{onvif.ErrSnapshotNotSupported, CodeNotSupported},
		{onvif.ErrProfileNotFound, CodeNotFound},
		{onvif.ErrPresetNotFound, CodeNotFound},
		{onvif.ErrInvalidParameter, CodeInvalidArgument},
		{errors.New("something nobody mapped"), CodeInternal},
	}
	for _, c := range cases {
		if got := FromError(c.err, "cam", "Op").Code; got != c.want {
			t.Errorf("FromError(%v) = %s, want %s", c.err, got, c.want)
		}
	}
}

func TestSentinelMappingSurvivesWrapping(t *testing.T) {
	wrapped := fmt.Errorf("get profiles: %w", onvif.ErrConnectionFailed)
	if got := FromError(wrapped, "cam", "Op").Code; got != CodeUnreachable {
		t.Errorf("wrapped sentinel not matched: got %s", got)
	}
}

func TestMessageIsScrubbed(t *testing.T) {
	err := errors.New("dial rtsp://admin:s3cret@192.0.2.10:554/s1 failed")
	te := FromError(err, "cam", "Op")
	if strings.Contains(te.Message, "s3cret") {
		t.Errorf("credentials survived into the payload: %s", te.Message)
	}
}

func TestStreamAuthRecheckBeatsClassifierOrdering(t *testing.T) {
	// rtspeek's Classify checks "closed" before it checks auth, so this string
	// classifies as connection_closed upstream. We must still report auth.
	err := errors.New("connection closed after 401 Unauthorized")
	if got := FromStreamError(err, "cam", "Describe").Code; got != CodeAuthFailed {
		t.Errorf("got %s want %s", got, CodeAuthFailed)
	}
}

func TestStreamClassifierReuse(t *testing.T) {
	cases := []struct {
		err  error
		want Code
	}{
		{errors.New("dial tcp 192.0.2.10:554: connection refused"), CodeUnreachable},
		{errors.New("read tcp: i/o timeout"), CodeTimeout},
		{errors.New("lookup nosuchhost: no such host"), CodeUnreachable},
		{rtspeek.ErrInvalidURL, CodeInvalidArgument},
	}
	for _, c := range cases {
		if got := FromStreamError(c.err, "cam", "Describe").Code; got != c.want {
			t.Errorf("FromStreamError(%v) = %s, want %s", c.err, got, c.want)
		}
	}
}

func TestBlockedCarriesRetryAfter(t *testing.T) {
	after := 2
	te := Blocked("cam", "ptz.goto_preset", "rate limited", &after)
	if te.Code != CodeBlockedByPolicy {
		t.Errorf("got %s", te.Code)
	}
	if !te.Retryable || te.RetryAfterSeconds == nil || *te.RetryAfterSeconds != 2 {
		t.Errorf("rate-limited block must be retryable with a delay: %+v", te)
	}
	if plain := Blocked("cam", "ptz.goto_preset", "control disabled", nil); plain.Retryable {
		t.Error("a non-rate-limit block must not be retryable")
	}
}

func TestAllSentinelsMapped(t *testing.T) {
	cases := []struct {
		err  error
		want Code
	}{
		{onvif.ErrTimeout, CodeTimeout},
		{onvif.ErrConnectionFailed, CodeUnreachable},
		{onvif.ErrAuthenticationFailed, CodeAuthFailed},
		{onvif.ErrAuthenticationRequired, CodeAuthFailed},
		{onvif.ErrServiceNotSupported, CodeNotSupported},
		{onvif.ErrPTZNotSupported, CodeNotSupported},
		{onvif.ErrSnapshotNotSupported, CodeNotSupported},
		{onvif.ErrProfileNotFound, CodeNotFound},
		{onvif.ErrPresetNotFound, CodeNotFound},
		{onvif.ErrVideoSourceNotFound, CodeNotFound},
		{onvif.ErrInvalidParameter, CodeInvalidArgument},
		{onvif.ErrInvalidEndpoint, CodeInvalidArgument},
		{onvif.ErrInvalidEndpointFormat, CodeInvalidArgument},
		{context.DeadlineExceeded, CodeTimeout},
		{errors.New("unmapped"), CodeInternal},
	}
	for _, c := range cases {
		te := FromError(c.err, "cam", "Op")
		if te.Code != c.want {
			t.Errorf("FromError(%v) = %s, want %s", c.err, te.Code, c.want)
		}
		if te.Retryable != te.Code.Retryable() {
			t.Errorf("FromError(%v): Retryable %v disagrees with code %s", c.err, te.Retryable, te.Code)
		}
	}
}

func TestWrappedONVIFErrorAndDeadline(t *testing.T) {
	oe := onvif.NewONVIFError("ter:Action", "Nope", "boom")
	te := FromError(fmt.Errorf("get profiles: %w", oe), "cam", "Op")
	if te.Code != CodeDeviceFault || te.SOAP == nil || te.SOAP.Code != "ter:Action" {
		t.Errorf("wrapped ONVIFError not recognised: %+v", te)
	}
	te = FromError(fmt.Errorf("call: %w", context.DeadlineExceeded), "cam", "Op")
	if te.Code != CodeTimeout || !te.Retryable {
		t.Errorf("wrapped deadline not a retryable timeout: %+v", te)
	}
}

func TestIsAuthSignal(t *testing.T) {
	for _, s := range []string{"401", "HTTP 401 Unauthorized", "unauthorized", "UNAUTHORIZED", "not authorized", "Not Authorized", "ter:NotAuthorized"} {
		if !isAuthSignal(s) {
			t.Errorf("isAuthSignal(%q) = false", s)
		}
	}
	for _, s := range []string{"", "ter:Action", "timeout", "40"} {
		if isAuthSignal(s) {
			t.Errorf("isAuthSignal(%q) = true", s)
		}
	}
}

func TestSOAPAuthSignalInEitherField(t *testing.T) {
	cases := []struct{ name, code, reason string }{
		{"code only", "ter:NotAuthorized", "something else"},
		{"reason only", "ter:Action", "Sender not authorized"},
		{"reason 401", "ter:Action", "HTTP 401"},
		{"reason unauthorized", "ter:Action", "Unauthorized"},
	}
	for _, c := range cases {
		te := FromError(onvif.NewONVIFError(c.code, c.reason, "msg"), "cam", "Op")
		if te.Code != CodeAuthFailed {
			t.Errorf("%s: got %s want auth_failed", c.name, te.Code)
		}
	}
}

func TestSOAPFaultFieldsScrubbed(t *testing.T) {
	const leak = "rtsp://admin:SECRETPW@h/s" //nolint:gosec // fake test fixture
	te := FromError(onvif.NewONVIFError("ter:"+leak, "reason "+leak, "msg "+leak), "cam "+leak, "op "+leak)
	assertNoLeak(t, te)
	if te.SOAP == nil || !strings.Contains(te.SOAP.Reason, "rtsp://h/s") {
		t.Errorf("scrub destroyed useful text: %+v", te.SOAP)
	}
}

func assertNoLeak(t *testing.T, te *ToolError) {
	t.Helper()
	b, err := json.Marshal(te)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "SECRETPW") {
		t.Errorf("payload leaks credentials: %s", b)
	}
}

func TestStreamErrorScrubbedEverywhere(t *testing.T) {
	const leak = "rtsp://admin:SECRETPW@192.0.2.10/s1" //nolint:gosec // fake test fixture
	cases := []error{
		errors.New("dial " + leak + ": connection refused"),
		errors.New("describe " + leak + ": 401 Unauthorized"),
		fmt.Errorf("%s: %w", leak, rtspeek.ErrInvalidURL),
		errors.New("weird " + leak),
	}
	for _, err := range cases {
		te := FromStreamError(err, "cam "+leak, "op "+leak)
		assertNoLeak(t, te)
		if !strings.Contains(te.Message, "192.0.2.10") {
			t.Errorf("scrub destroyed host: %s", te.Message)
		}
	}
}

func TestFromErrorHintCameraOperationScrubbed(t *testing.T) {
	const leak = "rtsp://admin:SECRETPW@h/s" //nolint:gosec // fake test fixture
	assertNoLeak(t, FromError(errors.New("x "+leak), "c "+leak, "o "+leak))
	assertNoLeak(t, Blocked("c "+leak, "o "+leak, "m "+leak, nil))
}

func TestStreamArmsAndRetryable(t *testing.T) {
	cases := []struct {
		err  error
		want Code
	}{
		{errors.New("RTSP 404 Not Found"), CodeNotFound},
		{errors.New("unsupported scheme http"), CodeInvalidArgument},
		{errors.New("Sender not authorized"), CodeAuthFailed}, // classifier says "other"
		{errors.New("notauthorized"), CodeAuthFailed},         // classifier says "other"
		{errors.New("connection closed after 401"), CodeAuthFailed},
		{errors.New("dial tcp: connection refused"), CodeUnreachable},
		{errors.New("read: i/o timeout"), CodeTimeout},
		{errors.New("no such host"), CodeUnreachable},
		{errors.New("totally unknown"), CodeInternal},
		{rtspeek.ErrInvalidURL, CodeInvalidArgument},
	}
	for _, c := range cases {
		te := FromStreamError(c.err, "cam", "Describe")
		if te.Code != c.want {
			t.Errorf("FromStreamError(%v) = %s, want %s", c.err, te.Code, c.want)
		}
		if te.Retryable != te.Code.Retryable() {
			t.Errorf("FromStreamError(%v): Retryable %v disagrees with %s", c.err, te.Retryable, te.Code)
		}
	}
}

func TestBlockedFields(t *testing.T) {
	te := Blocked("cam-a", "ptz.move", "control disabled", nil)
	if te.Message != "control disabled" || te.Camera != "cam-a" || te.Operation != "ptz.move" {
		t.Errorf("fields lost: %+v", te)
	}
	if te.RetryAfterSeconds != nil {
		t.Error("RetryAfterSeconds must be nil")
	}
}
