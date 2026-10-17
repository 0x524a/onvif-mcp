package redact

import (
	"strings"
	"testing"
)

func TestScrubBlanksWSSecurityElements(t *testing.T) {
	cases := map[string]string{
		"digest":     `<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">7LWtDIGESTvalue=</wsse:Password>`,
		"plain":      `<Password>hunter22</Password>`,
		"nonce":      `<wsse:Nonce EncodingType="x#Base64Binary">lr9pNONCEvalue+/==</wsse:Nonce>`,
		"nsdecl":     `<s:Password xmlns:s="urn:x">hunter22</s:Password>`,
		"created":    `<wsu:Created>2026-10-17T10:11:12Z</wsu:Created>`,
		"digestelem": `<PasswordDigest>abcDIGEST</PasswordDigest>`,
	}
	for name, in := range cases {
		out := Scrub(`fault: <s:Envelope><Header>` + in + `</Header></s:Envelope>`)
		for _, leak := range []string{"7LWtDIGESTvalue", "hunter22", "lr9pNONCEvalue", "2026-10-17T10", "abcDIGEST"} {
			if strings.Contains(out, leak) {
				t.Errorf("%s: %q survives in %q", name, leak, out)
			}
		}
		if !strings.Contains(out, "REDACTED") {
			t.Errorf("%s: no REDACTED marker in %q", name, out)
		}
	}
}

func TestScrubSelfClosingElementDoesNotEatFollowingText(t *testing.T) {
	out := Scrub(`<Password/>keep this text<Other/>`)
	if !strings.Contains(out, "keep this text") {
		t.Errorf("text after self-closing element was blanked: %q", out)
	}
}

// A quoted URL followed by ": dial tcp" must not be read as a JSON
// "key": value pair, which used to swallow the word "dial".
func TestScrubQuotedURLBeforeColonKeepsDiagnostics(t *testing.T) {
	in := `Post "http://h/x?token=abcSECRET123&password=hunter22": dial tcp 127.0.0.1:1: connect: connection refused`
	out := Scrub(in)
	if strings.Contains(out, "abcSECRET123") || strings.Contains(out, "hunter22") {
		t.Fatalf("secret leaked: %q", out)
	}
	if !strings.Contains(out, "dial tcp 127.0.0.1:1") {
		t.Errorf("diagnostic text lost: %q", out)
	}
	out = Scrub(`password=hunter22": dial tcp`)
	if out != `password=REDACTED": dial tcp` {
		t.Errorf("got %q", out)
	}
}
