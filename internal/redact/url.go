// Package redact keeps credentials out of anything that crosses the MCP
// boundary. Redaction is a type rather than a convention: leaking requires
// deliberately calling Unredacted, which is reviewable.
package redact

import (
	"encoding/json"
	"net/url"
	"regexp"
)

// URL wraps a parsed URL whose default rendering omits userinfo.
type URL struct{ u *url.URL }

// Parse parses raw into a URL. The credentials, if any, are retained
// internally and reachable only through Unredacted.
func Parse(raw string) (URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return URL{}, err
	}
	return URL{u: u}, nil
}

// String renders the URL with any userinfo removed.
func (r URL) String() string {
	if r.u == nil {
		return ""
	}
	c := *r.u
	c.User = nil
	return c.String()
}

// MarshalJSON renders the redacted form, so embedding a URL in any output
// struct is safe by default.
func (r URL) MarshalJSON() ([]byte, error) { return json.Marshal(r.String()) }

// Unredacted returns the URL including credentials. Callers must never place
// the result into tool output, an error value, or a log line.
func (r URL) Unredacted() string {
	if r.u == nil {
		return ""
	}
	return r.u.String()
}

var userinfoRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://)[^/@\s]*@`)

// Scrub removes userinfo from every URL-like substring in s. It is applied to
// error text from dependencies, which may embed the URL they failed on.
func Scrub(s string) string { return userinfoRe.ReplaceAllString(s, "${1}") }
