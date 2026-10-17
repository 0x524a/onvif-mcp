// Package redact keeps credentials out of anything that crosses the MCP
// boundary. Redaction is a type rather than a convention: leaking requires
// deliberately calling Unredacted, which is reviewable.
//
// Defence layers, in the order Scrub applies them: literal replacement of
// registered secrets (RegisterSecret; config loading must register every
// password), URL and key=value pattern passes, then a percent-decoded pass.
//
// Pattern scrubbing is best-effort defence in depth. RegisterSecret is the
// guarantee for known passwords: a registered secret is removed wherever it
// appears, in the raw, URL-escaped, JSON-escaped and Go-quoted forms it
// documents.
//
// Explicit non-goals, stated so nobody mistakes best-effort for a guarantee:
//
//   - key=value redaction consumes one whitespace-delimited token. A
//     multi-word value in that form ("password=two words") leaves the rest;
//     only the colon text form ("password: two words") redacts to end of line.
//   - Keys not in the sensitive list are not recognised.
//   - Path-style key forms ("/password/hunter2") are not recognised.
//   - Raw whitespace combined with an encoded '@' inside a password is not
//     reliably parsed as userinfo.
//   - HTML-entity, %u and \x40 style encodings are not decoded.
//   - Doubly-escaped or partially encoded registered secrets are removed only
//     in the exact forms RegisterSecret documents.
//   - Over-redaction is accepted: a false positive costs a diagnostic, a miss
//     leaks ("passed=3" becomes "passed=REDACTED").
//   - Performance: Scrub is linear in input size but slow, roughly 3 s per
//     MB, so callers should length-cap error text they feed it.
//   - Registered secrets are capped at 256 distinct entries.
//
// Also out of scope: free-form prose that contains a secret which is neither
// inside a URL or a recognised key=value, "key": value or "key: value" form,
// nor registered via RegisterSecret, is not detected. Nor are secrets
// transformed beyond those encodings (base64, hashes, upper-casing,
// truncation, splitting across fields), credentials in multi-line header
// continuations, or credential-bearing text that never passes through Scrub
// or a URL value.
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
// removed and sensitive query and fragment values replaced by REDACTED. The
// result is always passed through Scrub as a last line of defence.
func (r URL) String() string {
	if r.u == nil {
		return ""
	}
	c := *r.u
	c.User = nil
	if i := strings.LastIndexByte(c.Opaque, '@'); i >= 0 {
		c.Opaque = c.Opaque[i+1:]
	}
	// Final fallback: userinfo can hide in the path or host of a URL that
	// parses but is odd, and keys can hide in the fragment.
	return Scrub(c.String())
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

// sensitiveSubstrings are matched against a normalised key (percent-decoded,
// lowercased, with brackets, spaces, '-', '_', '.' and '+' removed). The set
// is deliberately broad: a false positive costs a diagnostic, a miss leaks.
var sensitiveSubstrings = []string{
	"pass", "pwd", "pw", "token", "secret", "key", "auth", "cred",
	"sig", "sid", "nonce", "response",
	"pin", "code", "session", "cookie", "jwt", "bearer",
}

// colonSubstrings is the subset used for the "key: value" text form, where a
// bare English word such as "response" or "key" is far more likely to be
// prose ("unexpected response: 500") than a credential.
var colonSubstrings = []string{
	"pass", "pwd", "pw", "token", "secret", "cred", "nonce", "apikey",
	"authorization", "authenticate", "authentication", "cookie", "jwt", "bearer",
}

const (
	// delim is what may precede a bare (scheme-less) credential token.
	delimChars = `\s"'(<=,;\[\]{}|)>` + "`"
	delim      = `(^|[` + delimChars + `])`
	// delimSlash additionally allows '/', for odd forms such as "a/u:pw@h".
	delimSlash = `(^|[` + delimChars + `/])`
	// keyDelim precedes a key=value or key: value pair.
	keyDelim = `(^|[?&;#,:` + delimChars + `])`
	keyChars = `[A-Za-z0-9_.%+\[\]\-]{1,64}`
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
	bareRe = regexp.MustCompile(delimSlash + `[^\s/@:]*:(?:[^\s/]\S*)?@`)

	// key=value, including query strings and fragments. The value is a quoted
	// string or runs to the next separator.
	kvRe = regexp.MustCompile(keyDelim + `(` + keyChars + `)=("[^"]*"|'[^']*'|[^&;\s#"']*)`)
	// key: value text form; the key is checked against colonSubstrings.
	colonRe = regexp.MustCompile(keyDelim + `(` + keyChars + `)([ \t]*:[ \t]*)("[^"]*"|'[^']*'|[^\s"']+)`)
	// HTTP-style credential headers: the whole rest of the line is the value.
	authHdrRe = regexp.MustCompile(`(?i)` + keyDelim +
		`((?:proxy-?)?authorization|www-authenticate|proxy-authenticate|authentication-info)([ \t]*:[ \t]*)(?:([A-Za-z][A-Za-z0-9\-]*)[ \t]+)?[^\r\n]*`)
	// JSON "key":"value", plain and backslash-escaped (JSON embedded in a
	// string).
	// The key excludes '/', '&', '=' and '?': a quoted URL followed by ": dial
	// tcp" is not a JSON key, and treating it as one swallowed the diagnostics.
	jsonKeyRe = regexp.MustCompile(`"([^"\\/&=?]{1,64})"[ \t\r\n]*:[ \t\r\n]*`)
	escJSONRe = regexp.MustCompile(`(\\"([^"\\]{1,64})\\"[ \t]*:[ \t]*)(\\"(?:[^"\\]|\\[^"])*\\"|[^\s,}\]"\\]+)`)

	// WS-Security UsernameToken parts echoed in a fault body: the element text
	// of Password (including PasswordDigest), Nonce and Created, under any
	// namespace prefix and with any attributes. A self-closing element has no
	// text and is left alone.
	wsseRe = regexp.MustCompile(`(?is)(<(?:[\w.\-]+:)?(?:Password\w*|Nonce|Created)(?:\s[^>]*[^/>])?>)[^<]+`)

	tokenRe = regexp.MustCompile(`\S+`)
)

// Scrub removes credentials from every URL-like substring in s. It is applied
// to error text from dependencies, which may embed the URL they failed on.
//
// Order: (1) registered secrets (see RegisterSecret) are replaced literally;
// (2) pattern passes; (3) a normalised pass, described below.
//
// Rule for "scheme://": the userinfo runs from just after "://" through the
// LAST '@' that occurs before the next "scheme://" (or end of input), however
// far away. Raw passwords may legitimately contain '@', ':', '/', spaces and
// newlines, so none of those end it; only another URL starting does. This
// fails closed, with no length bound beyond which text is left alone: a
// clean URL followed by unrelated text containing '@' loses everything up to
// that '@'. Losing diagnostics is preferred over leaking a password.
//
// Also scrubbed: percent-encoded scheme://...%40, opaque scheme:user:pw@host,
// //user:pw@host, scheme-less user:pw@host (delimited by whitespace, quotes,
// brackets, braces, parentheses, angle brackets, '|', '/', and similar);
// the values of sensitive keys in key=value form (query string, fragment,
// headers, logs), JSON "key":"value" form (also backslash-escaped) and
// "key: value" text form; and the value of Authorization-style headers
// through the end of the line. A key is sensitive when its normalised form
// (percent-decoded, lowercased, brackets/spaces/'-'/'_'/'.'/'+' removed)
// contains pass, pwd, pw, token, secret, key, auth, cred, sig, sid, nonce or
// response. The "key: value" text form uses only the credential-specific
// subset (bare "key", "sig", "sid", "response" and "auth" prefixes are
// ordinary English in "unexpected response: 500" and are not matched there).
//
// Normalised pass: each whitespace-delimited token that changes when
// percent-decoded (repeatedly, to defeat double encoding) and with fullwidth
// '＠' (U+FF20) and small '﹫' (U+FE6B) read as '@' is re-scrubbed in its
// decoded form. If that finds anything, mapping the redaction back onto the
// encoded text is not attempted: the whole token becomes REDACTED.
func Scrub(s string) string {
	s = scrubRegistered(s)
	s = scrubPatterns(s)
	return scrubNormalised(s)
}

func scrubPatterns(s string) string {
	s = wsseRe.ReplaceAllString(s, "${1}REDACTED")
	s = scrubJSON(s)
	s = escJSONRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := escJSONRe.FindStringSubmatch(m)
		if !sensitiveKey(sub[2], sensitiveSubstrings) {
			return m
		}
		return sub[1] + `\"REDACTED\"`
	})
	s = authHdrRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := authHdrRe.FindStringSubmatch(m)
		out := sub[1] + sub[2] + sub[3]
		if sub[4] != "" {
			out += sub[4] + " "
		}
		return out + "REDACTED"
	})
	s = encodedRe.ReplaceAllString(s, "${1}")
	s = scrubAuthority(s)
	s = opaqueRe.ReplaceAllString(s, "${1}${2}:")
	s = netPathRe.ReplaceAllString(s, "${1}//")
	s = bareRe.ReplaceAllString(s, "${1}")
	s = kvRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := kvRe.FindStringSubmatch(m)
		if !sensitiveKey(sub[2], sensitiveSubstrings) {
			return m
		}
		return sub[1] + sub[2] + "=REDACTED"
	})
	return scrubColon(s)
}

// scrubColon redacts the value of sensitive "key: value" text. For an
// unquoted value the whole rest of the line is taken (a password may contain
// spaces), except for Authorization-style headers, which authHdrRe already
// handled and which keep their single-token behaviour here.
func scrubColon(s string) string {
	var b strings.Builder
	prev := 0
	for _, m := range colonRe.FindAllStringSubmatchIndex(s, -1) {
		if m[0] < prev {
			continue
		}
		key := s[m[4]:m[5]]
		val := s[m[8]:m[9]]
		if strings.HasPrefix(val, "//") || !colonSensitive(key) {
			continue
		}
		end := m[1]
		if c := val[0]; c != '"' && c != '\'' && !strings.Contains(normKey(key), "authenticat") && !strings.Contains(normKey(key), "authoriz") {
			end = len(s)
			if i := strings.IndexAny(s[m[8]:], "\r\n"); i >= 0 {
				end = m[8] + i
			}
		}
		b.WriteString(s[prev:m[8]])
		b.WriteString("REDACTED")
		prev = end
	}
	b.WriteString(s[prev:])
	return b.String()
}

// scrubJSON redacts the value of every sensitive "key": value pair. The value
// may be a string, a bare token, or an array/object, which is consumed whole
// (brackets balanced, quote-aware; unterminated runs to the end of input).
func scrubJSON(s string) string {
	var b strings.Builder
	prev, from := 0, 0
	for from < len(s) {
		loc := jsonKeyRe.FindStringSubmatchIndex(s[from:])
		if loc == nil {
			break
		}
		keyEnd, valStart := from+loc[3], from+loc[1]
		if !sensitiveKey(s[from+loc[2]:keyEnd], sensitiveSubstrings) {
			from = valStart
			continue
		}
		end := jsonValueEnd(s, valStart)
		if end == valStart {
			from = valStart
			continue
		}
		b.WriteString(s[prev:valStart])
		b.WriteString(`"REDACTED"`)
		prev, from = end, end
	}
	b.WriteString(s[prev:])
	return b.String()
}

// jsonValueEnd returns the index just past the JSON value starting at i, or i
// if there is no value there.
func jsonValueEnd(s string, i int) int {
	if i >= len(s) {
		return i
	}
	switch s[i] {
	case '"':
		return jsonStringEnd(s, i)
	case '[', '{':
		depth := 0
		for j := i; j < len(s); j++ {
			switch s[j] {
			case '"':
				j = jsonStringEnd(s, j) - 1
			case '[', '{':
				depth++
			case ']', '}':
				depth--
				if depth == 0 {
					return j + 1
				}
			}
		}
		return len(s)
	}
	j := i
	for j < len(s) && !strings.ContainsRune(" \t\r\n,}]\"", rune(s[j])) {
		j++
	}
	return j
}

// jsonStringEnd returns the index just past the string starting at the quote
// at i, or len(s) when unterminated.
func jsonStringEnd(s string, i int) int {
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '"':
			return j + 1
		}
	}
	return len(s)
}

// scrubAuthority removes userinfo after every "scheme://".
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

// scrubNormalised re-scrubs, token by token, the decoded view of any token
// that differs from its decoded view.
func scrubNormalised(s string) string {
	return tokenRe.ReplaceAllStringFunc(s, func(t string) string {
		n := normalise(t)
		if n == t {
			return t
		}
		if scrubPatterns(n) != n || scrubRegistered(n) != n {
			return "REDACTED"
		}
		return t
	})
}

var atFold = strings.NewReplacer("＠", "@", "﹫", "@")

// normalise percent-decodes s (leniently; up to four rounds, for multiple
// encoding) and folds look-alike '@' characters.
func normalise(s string) string {
	s = atFold.Replace(s)
	for i := 0; i < 4; i++ {
		d := atFold.Replace(unescapeLenient(s))
		if d == s {
			break
		}
		s = d
	}
	return s
}

func unescapeLenient(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}

// normKey is the comparison form of a key.
func normKey(k string) string {
	k = strings.ToLower(normalise(k))
	return strings.NewReplacer("[", "", "]", "", " ", "", "-", "", "_", "", ".", "", "+", "").Replace(k)
}

func sensitiveKey(k string, subs []string) bool {
	n := normKey(k)
	for _, sub := range subs {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

func colonSensitive(k string) bool {
	return normKey(k) == "auth" || sensitiveKey(k, colonSubstrings)
}
