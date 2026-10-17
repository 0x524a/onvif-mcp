package redact

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestScrubEmptyUserUserinfo(t *testing.T) {
	for _, in := range []string{
		"http:/:" + pw + "@h",
		"a/:" + pw + "@h",
		":" + pw + "@h",
		"dial http:/:" + pw + "@h/x failed",
	} {
		if got := Scrub(in); strings.Contains(got, pw) {
			t.Errorf("Scrub(%q) leaked: %q", in, got)
		}
	}
}

func TestScrubJSONCompoundValues(t *testing.T) {
	for _, in := range []string{
		`{"password":["` + pw + `","SECONDELEM"]}`,
		`{"password": [ "a\"]", "` + pw + `" ], "x": 1}`,
		`{"password":{"v":"` + pw + `","w":["SECONDELEM"]}}`,
		`{"password":[[1,"` + pw + `"],"SECONDELEM"],"ok":2}`,
		`{"password":["` + pw + `","SECONDELEM"`, // unterminated
	} {
		got := Scrub(in)
		for _, leak := range []string{pw, "SECONDELEM", `a\"]`} {
			if strings.Contains(got, leak) {
				t.Errorf("Scrub(%q) leaked %q: %q", in, leak, got)
			}
		}
	}
	got := Scrub(`{"password":["` + pw + `"],"ok":2}`)
	if !strings.Contains(got, `"ok":2`) {
		t.Errorf("trailing sibling lost: %q", got)
	}
}

func TestScrubMultiWordColon(t *testing.T) {
	for _, in := range []string{
		"password: alpha SECRETPW gamma",
		"password=alpha&x=1", // kv form stays single-value
	} {
		got := Scrub(in)
		if strings.Contains(got, "alpha") || strings.Contains(got, "gamma") {
			t.Errorf("Scrub(%q) leaked: %q", in, got)
		}
	}
	if got := Scrub("password: a b c\nnext line"); got != "password: REDACTED\nnext line" {
		t.Errorf("end-of-line rule: %q", got)
	}
	// kv form is not extended to end of line.
	if got := Scrub("password=a b c"); got != "password=REDACTED b c" {
		t.Errorf("kv form: %q", got)
	}
	if got := Scrub("unexpected response: 500 bad"); got != "unexpected response: 500 bad" {
		t.Errorf("prose over-redacted: %q", got)
	}
}

func TestScrubNewSensitiveKeys(t *testing.T) {
	for _, k := range []string{"pin", "code", "passphrase", "credential", "authorization", "session", "cookie"} {
		for _, in := range []string{
			"rtsp://h/s?" + k + "=" + pw,
			k + "=" + pw,
			`{"` + k + `":"` + pw + `"}`,
		} {
			if got := Scrub(in); strings.Contains(got, pw) {
				t.Errorf("Scrub(%q) leaked: %q", in, got)
			}
		}
	}
}

func TestRegisterSecretEscapedForms(t *testing.T) {
	s := "Esc<&>\"q\\ p/w+x'é\t"
	RegisterSecret(s)
	var forms []string
	jm, _ := json.Marshal(s)
	forms = append(forms, string(jm[1:len(jm)-1]))
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	nb := strings.TrimSpace(buf.String())
	forms = append(forms, nb[1:len(nb)-1])
	q := strconv.Quote(s)
	forms = append(forms, q[1:len(q)-1])
	forms = append(forms,
		strings.ReplaceAll(s, " ", "+"),
		lowerPct(url.QueryEscape(s)),
		lowerPct(url.PathEscape(s)),
		url.QueryEscape(url.QueryEscape(s)),
		url.PathEscape(url.PathEscape(s)),
		lowerPct(url.QueryEscape(url.QueryEscape(s))),
	)
	for _, f := range forms {
		got := Scrub("pre " + f + " post")
		if got != "pre REDACTED post" {
			t.Errorf("form %q not scrubbed: %q", f, got)
		}
	}
	sp := "has space9"
	RegisterSecret(sp)
	if got := Scrub("x has+space9 y"); got != "x REDACTED y" {
		t.Errorf("plus form: %q", got)
	}
}
