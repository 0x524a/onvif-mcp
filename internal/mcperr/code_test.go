package mcperr

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRetryableByCode(t *testing.T) {
	retryable := []Code{CodeUnreachable, CodeTimeout}
	terminal := []Code{
		CodeAuthFailed, CodeNotSupported, CodeNotFound,
		CodeInvalidArgument, CodeDeviceFault, CodeInternal, CodeBlockedByPolicy,
	}
	for _, c := range retryable {
		if !c.Retryable() {
			t.Errorf("%s must be retryable", c)
		}
	}
	for _, c := range terminal {
		if c.Retryable() {
			t.Errorf("%s must not be retryable", c)
		}
	}
}

type demo struct {
	Name string `json:"name"`
}

func TestOKOmitsErrorField(t *testing.T) {
	b, err := json.Marshal(OK(demo{Name: "front-door"}))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(b), "error") {
		t.Errorf("success payload must omit error: %s", b)
	}
	if !strings.Contains(string(b), "front-door") {
		t.Errorf("success payload lost data: %s", b)
	}
}

func TestFailOmitsDataField(t *testing.T) {
	out := Fail[demo](&ToolError{
		Code: CodeUnreachable, Retryable: true, Message: "no route",
	})
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), `"data"`) {
		t.Errorf("error payload must omit data: %s", b)
	}
	if !strings.Contains(string(b), "unreachable") {
		t.Errorf("error payload lost the code: %s", b)
	}
}

func TestCodeValuesAreStableStrings(t *testing.T) {
	// These strings are a contract with the agent; changing one is breaking.
	want := map[Code]string{
		CodeUnreachable: "unreachable", CodeTimeout: "timeout",
		CodeAuthFailed: "auth_failed", CodeNotSupported: "not_supported",
		CodeNotFound: "not_found", CodeInvalidArgument: "invalid_argument",
		CodeDeviceFault: "device_fault", CodeBlockedByPolicy: "blocked_by_policy",
		CodeInternal: "internal",
	}
	for c, s := range want {
		if string(c) != s {
			t.Errorf("code drifted: got %q want %q", c, s)
		}
	}
	if len(want) != 9 {
		t.Fatalf("taxonomy must stay closed at nine codes, got %d", len(want))
	}
}

func TestToolErrorGoldenJSON(t *testing.T) {
	after := 3
	te := &ToolError{
		Code: CodeDeviceFault, Retryable: false, Message: "m",
		Camera: "cam-a", Operation: "op", Hint: "h",
		RetryAfterSeconds: &after,
		SOAP:              &SOAPFault{Code: "ter:Action", Reason: "why"},
	}
	b, err := json.Marshal(te)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"code":"device_fault","retryable":false,"message":"m","camera":"cam-a",` +
		`"operation":"op","hint":"h","retry_after_seconds":3,` +
		`"soap":{"code":"ter:Action","reason":"why"}}`
	if string(b) != want {
		t.Errorf("golden mismatch\n got %s\nwant %s", b, want)
	}
}

func TestOutEnvelopeKeyNames(t *testing.T) {
	ok, _ := json.Marshal(OK(demo{Name: "x"}))
	if string(ok) != `{"data":{"name":"x"}}` {
		t.Errorf("OK envelope: %s", ok)
	}
	fail, _ := json.Marshal(Fail[demo](&ToolError{Code: CodeInternal, Message: "m"}))
	if string(fail) != `{"error":{"code":"internal","retryable":false,"message":"m"}}` {
		t.Errorf("Fail envelope: %s", fail)
	}
}
