package redact

import (
	"encoding/json"
	"errors"
	"net/url"
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

func TestScrubTable(t *testing.T) {
	const pw = "SECRETPW"
	cases := []struct{ name, in, want string }{
		{"http", "GET http://u:" + pw + "@h/x failed", "GET http://h/x failed"},
		{"https", "https://u:" + pw + "@h:8443/x", "https://h:8443/x"},
		{"rtsps", "rtsps://u:" + pw + "@h/s", "rtsps://h/s"},
		{"user only", "rtsp://" + pw + "@h/s", "rtsp://h/s"},
		{"two urls", "rtsp://a:" + pw + "@h1/x then rtsp://b:" + pw + "@h2/y", "rtsp://h1/x then rtsp://h2/y"},
		{"second url clean", "rtsp://a:" + pw + "@h1/x then http://h2/ok", "rtsp://h1/x then http://h2/ok"},
		{"first url clean", "http://h2/ok then rtsp://a:" + pw + "@h1/x", "http://h2/ok then rtsp://h1/x"},
		{"no credentials", "dial rtsp://192.0.2.10:554/s1: timeout", "dial rtsp://192.0.2.10:554/s1: timeout"},
		{"at in password", "rtsp://admin:p@" + pw + "@10.0.0.1/s", "rtsp://10.0.0.1/s"},
		{"colon at in password", "rtsp://a:b@c:" + pw + "@h", "rtsp://h"},
		{"slash in password", "rtsp://admin:p/" + pw + "@h/s", "rtsp://h/s"},
		{"whitespace in userinfo", "rtsp://admin:pa " + pw + "@h/s", "rtsp://h/s"},
		{"newline in userinfo", "rtsp://admin:pa\n" + pw + "@h/s", "rtsp://h/s"},
		{"scheme-less", "failed for admin:" + pw + "@10.0.0.1:554/s", "failed for 10.0.0.1:554/s"},
		{"scheme-less at start", "admin:" + pw + "@10.0.0.1", "10.0.0.1"},
		{"double slash", "dial //admin:" + pw + "@10.0.0.1/s", "dial //10.0.0.1/s"},
		{"opaque", "bad rtsp:admin:" + pw + "@h", "bad rtsp:h"},
		{"percent encoded", "u=rtsp%3A%2F%2Fadmin%3A" + pw + "%40h%2Fs", "u=rtsp%3A%2F%2Fh%2Fs"},
		{"query password", "rtsp://h/s?password=" + pw + "&x=1", "rtsp://h/s?password=REDACTED&x=1"},
		{"query mixed case", "http://h/s?x=1&ToKeN=" + pw, "http://h/s?x=1&ToKeN=REDACTED"},
		{"query apikey", "http://h/s?apikey=" + pw + "&secret=" + pw + "&key=" + pw, "http://h/s?apikey=REDACTED&secret=REDACTED&key=REDACTED"},
		{"query passwd pwd auth", "?passwd=" + pw + "&pwd=" + pw + "&auth=" + pw, "?passwd=REDACTED&pwd=REDACTED&auth=REDACTED"},
		{"query benign kept", "http://h/s?channel=1&monkey=2", "http://h/s?channel=1&monkey=2"},
		{"email-like kept", "contact ops@example.com", "contact ops@example.com"},
		{"port not mistaken", "dial rtsp://h:554/p?e=1", "dial rtsp://h:554/p?e=1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Scrub(c.in)
			if got != c.want {
				t.Errorf("Scrub(%q)\n got %q\nwant %q", c.in, got, c.want)
			}
			if strings.Contains(got, pw) {
				t.Errorf("leaked %s: %q", pw, got)
			}
		})
	}
}

func TestParseErrorNeverContainsInput(t *testing.T) {
	for _, in := range []string{
		"rtsp://a:SECRETPW@h:badport/x",
		"rtsp://a:SECRETPW@h/%zz",
		"rtsp://a:SECRETPW@h\x7f/x",
	} {
		_, err := Parse(in)
		if err == nil {
			t.Errorf("Parse(%q) expected error", in)
			continue
		}
		if strings.Contains(err.Error(), "SECRETPW") || strings.Contains(err.Error(), "badport") {
			t.Errorf("error leaks input: %v", err)
		}
		var ue *url.Error
		if errors.As(err, &ue) {
			t.Errorf("error wraps *url.Error, which embeds the input: %v", err)
		}
	}
}

func TestParseMalformedIsErrInvalidURL(t *testing.T) {
	if _, err := Parse("://nope"); !errors.Is(err, ErrInvalidURL) {
		t.Errorf("want ErrInvalidURL, got %v", err)
	}
}

func TestStringRedactsQueryAndOpaque(t *testing.T) {
	u, err := Parse("rtsp://admin:SECRETPW@h/s?token=SECRETPW&Password=SECRETPW&ch=1")
	if err != nil {
		t.Fatal(err)
	}
	for _, got := range []string{u.String(), mustJSON(t, u)} {
		if strings.Contains(got, "SECRETPW") || strings.Contains(got, "admin") {
			t.Errorf("leaked: %s", got)
		}
		if !strings.Contains(got, "ch=1") || !strings.Contains(got, "token=REDACTED") {
			t.Errorf("wrong redaction: %s", got)
		}
	}
	o, err := Parse("rtsp:admin:SECRETPW@h")
	if err != nil {
		t.Fatal(err)
	}
	if got := o.String(); strings.Contains(got, "SECRETPW") || strings.Contains(got, "admin") {
		t.Errorf("opaque leaked: %s", got)
	}
	if !strings.Contains(u.Unredacted(), "SECRETPW") {
		t.Error("Unredacted must keep everything")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
