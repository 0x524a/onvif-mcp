// Package redact keeps credentials out of anything that crosses the MCP
// boundary. Redaction is a type rather than a convention: leaking requires
// deliberately calling Unredacted, which is reviewable.
package redact

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// ErrInvalidURL is returned by Parse for any unparsable input. It is a fixed
// error on purpose: net/url's own error text embeds the whole input, userinfo
// included.
var ErrInvalidURL = errors.New("redact: malformed URL")

// URL wraps a parsed URL whose default rendering omits userinfo and the
// values of sensitive query parameters.
type URL struct{ u *url.URL }

// Parse parses raw into a URL. The credentials, if any, are retained
// internally and reachable only through Unredacted. On failure the returned
// error is ErrInvalidURL and never contains any part of raw.
func Parse(raw string) (URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return URL{}, ErrInvalidURL
	}
	return URL{u: u}, nil
}

// String renders the URL with userinfo (including opaque-form userinfo)
// removed and sensitive query values replaced by REDACTED.
func (r URL) String() string {
	if r.u == nil {
		return ""
	}
	c := *r.u
	c.User = nil
	if i := strings.LastIndexByte(c.Opaque, '@'); i >= 0 {
		c.Opaque = c.Opaque[i+1:]
	}
	c.RawQuery = rawQueryRe.ReplaceAllString(c.RawQuery, "${1}${2}=REDACTED")
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

const sensitiveNames = `password|passwd|pwd|token|auth|apikey|api_key|secret|key`

const (
	// maxAuthorityScan bounds how far past "scheme://" Scrub looks for the
	// closing '@' of userinfo.
	maxAuthorityScan = 256
	// delim is what may precede a bare (scheme-less) credential token.
	delim = `(^|[\s"'(<=,;])`
)

var (
	schemeRe = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.\-]*://`)
	// Percent-encoded "scheme://userinfo@": consume through the last %40 of
	// the whitespace-delimited token.
	encodedRe = regexp.MustCompile(`(?i)([a-z][a-z0-9+.\-]*%3A%2F%2F)\S*%40`)
	// Opaque form "rtsp:user:pw@host".
	opaqueRe = regexp.MustCompile(`(?i)` + delim + `((?:rtsps?|https?|ftp|onvif)):[^\s/@:]+(?::\S*)?@`)
	// "//user:pw@host" and "//user@host" (network-path reference).
	netPathRe = regexp.MustCompile(delim + `//[^\s/@:]*(?::\S*)?@`)
	// Scheme-less "user:pw@host". The password must not start with '/', so
	// "scheme://..." is never mistaken for it; plain "user@host" (an email
	// address) is deliberately left alone.
	bareRe = regexp.MustCompile(delim + `[^\s/@:]+:(?:[^\s/]\S*)?@`)

	queryRe    = regexp.MustCompile(`(?i)(^|[?&;\s])(` + sensitiveNames + `)=[^&;\s#"']*`)
	rawQueryRe = regexp.MustCompile(`(?i)(^|[&;])(` + sensitiveNames + `)=[^&;]*`)
)

// Scrub removes credentials from every URL-like substring in s. It is applied
// to error text from dependencies, which may embed the URL they failed on.
//
// Rule for "scheme://": the userinfo runs from just after "://" through the
// LAST '@' that occurs before the next "scheme://" (or end of input), looking
// at most maxAuthorityScan bytes ahead. Raw passwords may legitimately
// contain '@', ':', '/', spaces and newlines, so none of those end it; the
// only things that do are another URL starting, or the scan bound. This
// fails closed: a clean URL followed within the window by unrelated text
// containing '@' loses the text up to that '@'. Losing diagnostics is
// preferred over leaking a password.
//
// Also scrubbed: percent-encoded scheme://...%40, opaque scheme:user:pw@host,
// //user:pw@host, scheme-less user:pw@host, and the values of sensitive query
// parameters (password, passwd, pwd, token, auth, apikey, api_key, secret,
// key; case-insensitive) which become REDACTED.
func Scrub(s string) string {
	s = encodedRe.ReplaceAllString(s, "${1}")
	s = scrubAuthority(s)
	s = opaqueRe.ReplaceAllString(s, "${1}${2}:")
	s = netPathRe.ReplaceAllString(s, "${1}//")
	s = bareRe.ReplaceAllString(s, "${1}")
	return queryRe.ReplaceAllString(s, "${1}${2}=REDACTED")
}

func scrubAuthority(s string) string {
	locs := schemeRe.FindAllStringIndex(s, -1)
	if len(locs) == 0 {
		return s
	}
	var b strings.Builder
	prev := 0
	for i, loc := range locs {
		if loc[0] < prev {
			continue
		}
		end := len(s)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		if end-loc[1] > maxAuthorityScan {
			end = loc[1] + maxAuthorityScan
		}
		at := strings.LastIndexByte(s[loc[1]:end], '@')
		if at < 0 {
			continue
		}
		b.WriteString(s[prev:loc[1]])
		prev = loc[1] + at + 1
	}
	b.WriteString(s[prev:])
	return b.String()
}
