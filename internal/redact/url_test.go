package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

const withCreds = "rtsp://admin:s3cret@192.0.2.10:554/stream1" //nolint:gosec // fake test fixture, not a real credential

func TestStringStripsUserinfo(t *testing.T) {
	u, err := Parse(withCreds)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := u.String()
	for _, leak := range []string{"admin", "s3cret"} {
		if strings.Contains(got, leak) {
			t.Errorf("String() leaked %q: %s", leak, got)
		}
	}
	if !strings.Contains(got, "192.0.2.10:554/stream1") {
		t.Errorf("String() lost the host/path: %s", got)
	}
}

func TestMarshalJSONStripsUserinfo(t *testing.T) {
	u, _ := Parse(withCreds)
	b, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(b), "s3cret") {
		t.Errorf("MarshalJSON leaked the password: %s", b)
	}
}

func TestUnredactedKeepsCredentials(t *testing.T) {
	u, _ := Parse(withCreds)
	if !strings.Contains(u.Unredacted(), "s3cret") {
		t.Error("Unredacted() must retain credentials for internal use")
	}
}

func TestScrubFreeText(t *testing.T) {
	in := `dial failed for rtsp://admin:s3cret@192.0.2.10:554/s1: timeout`
	got := Scrub(in)
	if strings.Contains(got, "s3cret") || strings.Contains(got, "admin") {
		t.Errorf("Scrub left credentials: %s", got)
	}
	if !strings.Contains(got, "192.0.2.10") {
		t.Errorf("Scrub destroyed the useful part: %s", got)
	}
}

func TestZeroValueIsSafe(t *testing.T) {
	var u URL
	if u.String() != "" || u.Unredacted() != "" {
		t.Error("zero value must not panic and must be empty")
	}
}
