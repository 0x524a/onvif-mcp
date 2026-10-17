package redact

import (
	"strings"
	"sync"
	"testing"
)

const pw = "SECRETPW"

func TestURLStringFinalScrub(t *testing.T) {
	for _, in := range []string{
		"rtsp://a:" + pw + "@h,rtsp://b:" + pw + "@h",
		"http:///admin:" + pw + "@h",
		"http:/admin:" + pw + "@h",
		"a/user:" + pw + "@host",
		"rtsp://h/s#password=" + pw,
		"rtsp://h/s?pa%73sword=" + pw,
	} {
		u, err := Parse(in)
		if err != nil {
			t.Logf("Parse(%q) rejected: %v", in, err)
			continue
		}
		for _, got := range []string{u.String(), mustJSON(t, u)} {
			if strings.Contains(got, pw) {
				t.Errorf("Parse(%q) leaked: %s", in, got)
			}
		}
	}
}

func TestScrubDelimiters(t *testing.T) {
	for _, in := range []string{
		"ONVIF error [//admin:" + pw + "@h]: x",
		"{//admin:" + pw + "@h}",
		"|//admin:" + pw + "@h|",
		"(//admin:" + pw + "@h)",
		"<//admin:" + pw + "@h>",
		"`//admin:" + pw + "@h`",
		"[admin:" + pw + "@h]",
		"a/admin:" + pw + "@h",
	} {
		if got := Scrub(in); strings.Contains(got, pw) {
			t.Errorf("Scrub(%q) leaked: %q", in, got)
		}
	}
}

func TestScrubFailsClosedPastBound(t *testing.T) {
	for _, n := range []int{250, 255, 256, 257, 300, 1000} {
		long := strings.Repeat("A", n-len(pw)) + pw
		in := "dial rtsp://admin:" + long + "@h/s failed"
		got := Scrub(in)
		if strings.Contains(got, "AAAA") || strings.Contains(got, pw) {
			t.Errorf("n=%d leaked: %q", n, got)
		}
	}
	// '@' early and password continues far beyond the bound.
	in := "rtsp://admin:p@" + strings.Repeat("B", 300) + pw + "@h/s"
	if got := Scrub(in); strings.Contains(got, "BBBB") || strings.Contains(got, pw) {
		t.Errorf("leaked: %q", got)
	}
}

func TestScrubSensitiveKeys(t *testing.T) {
	cases := []string{
		"rtsp://h/s?pass=" + pw,
		"rtsp://h/s?Pwd=" + pw,
		"rtsp://h/s?pw=" + pw,
		"rtsp://h/s?access_token=" + pw,
		"rtsp://h/s?client-secret=" + pw,
		"rtsp://h/s?X-Api-Key=" + pw,
		"rtsp://h/s?credentials=" + pw,
		"rtsp://h/s?sig=" + pw,
		"rtsp://h/s?sid=" + pw,
		"rtsp://h/s?nonce=" + pw,
		"rtsp://h/s?response=" + pw,
		"rtsp://h/s?user[password]=" + pw,
		"rtsp://h/s?pa%73sword=" + pw,
		"rtsp://h/s?PASS%5FWORD=" + pw,
		"rtsp://h/s?a=1#password=" + pw,
		"rtsp://h/s#a=1&token=" + pw,
		"pass=" + pw,
		"error: pass=" + pw + " bad",
		"Authorization: Basic " + pw,
		"Authorization: Digest username=\"a\", realm=\"r\", response=\"" + pw + "\"",
		"proxy-authorization: Bearer " + pw,
		"password: " + pw,
		"Password : " + pw,
		`{"password":"` + pw + `"}`,
		`{"Password": "` + pw + `", "x":1}`,
		`{"apiKey":"` + pw + `"}`,
		`{\"password\":\"` + pw + `\"}`,
		`{"token":` + pw + `}`,
	}
	for _, in := range cases {
		got := Scrub(in)
		if strings.Contains(got, pw) {
			t.Errorf("Scrub(%q) leaked: %q", in, got)
		}
		if !strings.Contains(got, "REDACTED") {
			t.Errorf("Scrub(%q) no REDACTED marker: %q", in, got)
		}
	}
	for _, in := range []string{
		"rtsp://h/s?channel=1&mode=2",
		"error: connection refused",
		"unexpected response: 500",
	} {
		if got := Scrub(in); got != in {
			t.Errorf("Scrub(%q) over-redacted: %q", in, got)
		}
	}
}

func TestScrubEncodedForms(t *testing.T) {
	for _, in := range []string{
		"rtsp://admin:" + pw + "%40h/",
		"rtsp://admin:" + pw + "%2540h/",
		"rtsp://admin:" + pw + "%252540h/",
		"rtsp://admin:" + pw + "＠h/",
		"rtsp://admin:" + pw + "﹫h/",
		"rtsp%3A%2F%2Fadmin%3A" + pw + "%2540h",
		"x rtsp://admin%3A" + pw + "%40h/s y",
		"//admin:" + pw + "%40h",
	} {
		got := Scrub(in)
		if strings.Contains(got, pw) {
			t.Errorf("Scrub(%q) leaked: %q", in, got)
		}
	}
	if got := Scrub("see ops%40example.com ok"); got != "see ops%40example.com ok" {
		t.Errorf("benign encoded text altered: %q", got)
	}
}

func TestRegisterSecret(t *testing.T) {
	secrets := []string{"hunter2-plain", "p@ss/w rd", "a&b=c?d#e"}
	for _, s := range secrets {
		RegisterSecret(s)
		RegisterSecret(s) // idempotent
	}
	RegisterSecret("")
	RegisterSecret("ab") // too short: ignored
	if got := Scrub("ab and  x"); got != "ab and  x" {
		t.Errorf("short secret was registered: %q", got)
	}
	for _, s := range secrets {
		forms := []string{s, urlQueryEscape(s), urlPathEscape(s), urlUserinfoEscape(s)}
		for _, f := range forms {
			in := "prefix " + f + " suffix"
			got := Scrub(in)
			if strings.Contains(got, f) || !strings.Contains(got, "REDACTED") {
				t.Errorf("form %q not scrubbed: %q", f, got)
			}
			if got != "prefix REDACTED suffix" {
				t.Errorf("unexpected output for %q: %q", f, got)
			}
		}
	}
	// Free prose containing a registered secret is scrubbed.
	if got := Scrub("login failed with hunter2-plain today"); strings.Contains(got, "hunter2") {
		t.Errorf("leaked: %q", got)
	}
	// Registered secret hidden in an encoded token.
	if got := Scrub("x=hunter2%2Dplain"); strings.Contains(got, "hunter2") {
		t.Errorf("encoded registered secret leaked: %q", got)
	}
	// Dedup: registering again does not grow the set.
	secretsMu.RLock()
	n := len(registered)
	secretsMu.RUnlock()
	RegisterSecret("hunter2-plain")
	secretsMu.RLock()
	n2 := len(registered)
	secretsMu.RUnlock()
	if n != n2 {
		t.Errorf("RegisterSecret not idempotent: %d -> %d", n, n2)
	}
}

func TestRegisterSecretConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := "conc-secret-" + strings.Repeat("x", i%4) + "/@ "
			for j := 0; j < 200; j++ {
				RegisterSecret(s)
				if got := Scrub("a " + s + " b"); strings.Contains(got, "conc-secret") {
					t.Errorf("leaked: %q", got)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
