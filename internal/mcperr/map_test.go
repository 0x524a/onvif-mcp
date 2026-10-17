package mcperr

import (
	"context"
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
