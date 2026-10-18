package redact

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// minSecretLen is the shortest secret RegisterSecret accepts. Shorter strings
// would shred unrelated text ("ab" appears everywhere).
const minSecretLen = 3

var (
	secretsMu  sync.RWMutex
	registered = map[string]struct{}{}
	// formSet is the union of secretForms over registered.
	formSet = map[string]struct{}{}
	// replacer replaces every literal form of every registered secret. It is
	// rebuilt on registration and is safe for concurrent use once built.
	replacer *strings.Replacer
)

func urlQueryEscape(s string) string { return url.QueryEscape(s) }
func urlPathEscape(s string) string  { return url.PathEscape(s) }

// urlUserinfoEscape is the password as url.UserPassword would encode it.
func urlUserinfoEscape(s string) string {
	return strings.TrimPrefix(url.UserPassword("", s).String(), ":")
}

var pctRe = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)

// lowerPct lowercases the hex digits of every percent escape in s.
func lowerPct(s string) string {
	return pctRe.ReplaceAllStringFunc(s, strings.ToLower)
}

// inner strips the surrounding quote characters from a quoted form.
func inner(q string) string {
	if len(q) >= 2 {
		return q[1 : len(q)-1]
	}
	return q
}

// secretForms returns every literal rendering of r that Scrub removes:
// raw, URL escapes (query, path, userinfo; also lowercase-hex and doubly
// encoded), '+' for space, JSON string escapes (HTML-escaped and not) and Go
// strconv.Quote escapes, the last three without outer quotes.
func secretForms(r string) []string {
	q, p := urlQueryEscape(r), urlPathEscape(r)
	forms := []string{
		r, q, p, urlUserinfoEscape(r),
		strings.ReplaceAll(r, " ", "+"),
		lowerPct(q), lowerPct(p), lowerPct(urlUserinfoEscape(r)),
		urlQueryEscape(q), urlPathEscape(p), lowerPct(urlQueryEscape(q)), lowerPct(urlPathEscape(p)),
		inner(strconv.Quote(r)),
	}
	if b, err := json.Marshal(r); err == nil {
		forms = append(forms, inner(string(b)))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(r) == nil {
		forms = append(forms, inner(strings.TrimSuffix(buf.String(), "\n")))
	}
	return forms
}

// maxSecrets bounds the number of distinct registered secrets. A deployment
// has one password per camera; the cap is a safety bound that keeps the
// per-registration rebuild cheap and the replacer small.
const maxSecrets = 256

// RegisterSecret records s as a secret that Scrub must remove wherever it
// appears, in any text, whether or not it sits inside a URL or key=value
// pair. Scrub replaces s literally, plus its url.QueryEscape, url.PathEscape
// and url.UserPassword encodings (also lowercase-hex, '+' for space and doubly
// encoded), and its JSON-escaped (HTML-escaped or not) and strconv.Quote
// escaped inner forms, with REDACTED, before any pattern matching.
//
// Config loading MUST register every camera password (and any other secret
// it reads) as soon as it is known; this is the only defence for a secret
// that appears in free-form prose. Calls are idempotent and safe for
// concurrent use.
//
// The registry is process-global and has no reset: a registered secret stays
// registered for the life of the process, and Scrub then removes it from every
// string, including ordinary prose. A short or common password (for example
// "abc" or "a b") therefore also redacts unrelated text that contains it, and
// in a test binary it does so for every later test. Tests must register
// distinctive values; a deployment that uses a very short password gets
// correspondingly noisy redaction.
//
// It returns true when s is covered by Scrub afterwards (newly registered or
// already registered). It returns false, registering nothing, when s is
// shorter than 3 bytes or when 256 distinct secrets are already registered;
// callers should treat false as a configuration error.
func RegisterSecret(s string) bool {
	if len(s) < minSecretLen {
		return false
	}
	secretsMu.Lock()
	defer secretsMu.Unlock()
	if _, ok := registered[s]; ok {
		return true
	}
	if len(registered) >= maxSecrets {
		return false
	}
	registered[s] = struct{}{}
	// Only the new secret's forms are computed; earlier ones are kept in
	// formSet, so each call costs one sort and one replacer build.
	for _, f := range secretForms(s) {
		if len(f) >= minSecretLen {
			formSet[f] = struct{}{}
		}
	}

	all := make([]string, 0, len(formSet))
	for f := range formSet {
		all = append(all, f)
	}
	// Longest first, so a secret that is a substring of another cannot
	// expose the remainder of the longer one.
	sort.Slice(all, func(i, j int) bool {
		if len(all[i]) != len(all[j]) {
			return len(all[i]) > len(all[j])
		}
		return all[i] < all[j]
	})
	pairs := make([]string, 0, 2*len(all))
	for _, f := range all {
		pairs = append(pairs, f, "REDACTED")
	}
	replacer = strings.NewReplacer(pairs...)
	return true
}

// scrubRegistered replaces every registered secret form in s.
func scrubRegistered(s string) string {
	secretsMu.RLock()
	r := replacer
	secretsMu.RUnlock()
	if r == nil {
		return s
	}
	return r.Replace(s)
}
