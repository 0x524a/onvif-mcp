package mcperr

import (
	"context"
	"errors"
	onvif "github.com/0x524a/onvif-go"
	"strings"
	"testing"
	"time"

	"github.com/0x524a/onvif-mcp/internal/testcam"
)

// onvif-go v1.2.0 returns SOAP faults as plain errors (internal/soap
// faultError): "SOAP fault: [code] reason[: detail]".
func TestSOAPFaultTextClassifiesAsDeviceFault(t *testing.T) {
	cases := []struct {
		name     string
		err      string
		want     Code
		soapCode string
	}{
		{"receiver", "GetStatus failed: SOAP fault: [s:Receiver] Handler error: boom", CodeDeviceFault, "s:Receiver"},
		{"http 500 wrapped", "GetProfiles failed: HTTP request failed with status 500: SOAP fault: [s:Sender] bad thing", CodeDeviceFault, "s:Sender"},
		{"action not supported", "SOAP fault: [ter:ActionNotSupported] Action not supported", CodeDeviceFault, "ter:ActionNotSupported"},
		{"auth", "initialize c: SOAP fault: [s:Sender] Sender not Authorized", CodeAuthFailed, "s:Sender"},
		{"not found", "SOAP fault: [ter:InvalidArgVal] ter:NoProfile profile missing", CodeNotFound, "ter:InvalidArgVal"},
		{"http 401 prefix", "HTTP request failed with status 401: SOAP fault: [s:Sender] denied", CodeAuthFailed, "s:Sender"},
	}
	for _, c := range cases {
		te := FromError(errors.New(c.err), "cam", "Op")
		if te.Code != c.want {
			t.Errorf("%s: code = %s, want %s (%+v)", c.name, te.Code, c.want, te)
		}
		if te.SOAP == nil || te.SOAP.Code != c.soapCode {
			t.Errorf("%s: soap = %+v, want code %q", c.name, te.SOAP, c.soapCode)
		}
		if te.Retryable {
			t.Errorf("%s: a fault must not be retryable", c.name)
		}
	}
}

func TestSOAPFaultReasonIsParsedAndNeverRawXML(t *testing.T) {
	err := errors.New("SOAP fault: [s:Receiver] Handler error: <s:Envelope><wsse:Password>pw</wsse:Password></s:Envelope>")
	te := FromError(err, "cam", "Op")
	if te.Code != CodeDeviceFault || te.SOAP == nil {
		t.Fatalf("got %+v", te)
	}
	if !strings.HasPrefix(te.SOAP.Reason, "Handler error:") {
		t.Errorf("reason = %q", te.SOAP.Reason)
	}
	for _, s := range []string{te.Message, te.SOAP.Reason, te.SOAP.Code} {
		if strings.Contains(s, "<") {
			t.Errorf("raw XML reached the payload: %q", s)
		}
	}
}

func TestFaultTextCannotSteerTransportClassification(t *testing.T) {
	// A device chooses its own fault text; "connection refused" in it must not
	// turn a fault into a retryable unreachable.
	te := FromError(errors.New("SOAP fault: [s:Receiver] dial tcp: connection refused i/o timeout status 404"), "cam", "Op")
	if te.Code != CodeDeviceFault || te.Retryable {
		t.Errorf("got %s retryable=%v", te.Code, te.Retryable)
	}
}

func TestRealCameraFaultIsDeviceFault(t *testing.T) {
	cam := testcam.Start(t)
	c, err := onvif.NewClient(cam.Endpoint(), onvif.WithCredentials(cam.Username(), cam.Password()))
	if err == nil {
		err = c.Initialize(context.Background())
	}
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = c.GetStatus(ctx, "no-such-profile")
	if err == nil {
		t.Fatal("camera did not fault on an unknown profile")
	}
	t.Logf("real fault text: %v", err)
	if !strings.Contains(err.Error(), "SOAP fault") {
		t.Fatalf("expected a SOAP fault error, got %v", err)
	}
	te := FromError(err, "cam", "GetStatus")
	if te.Code == CodeInternal {
		t.Fatalf("real fault classified internal: %v -> %+v", err, te)
	}
	if te.SOAP == nil || te.SOAP.Code == "" {
		t.Errorf("fault text %q produced no soap object: %+v", err, te)
	}
}
