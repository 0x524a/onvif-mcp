package redact

import (
	"net/url"
	"sort"
	"strings"
	"sync"
)

// minSecretLen is the shortest secret RegisterSecret accepts. Shorter strings
// would shred unrelated text ("ab" appears everywhere).
const minSecretLen = 3

var (
	secretsMu  sync.RWMutex
	registered = map[string]struct{}{}
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

// RegisterSecret records s as a secret that Scrub must remove wherever it
// appears, in any text, whether or not it sits inside a URL or key=value
// pair. Scrub replaces s literally, plus its url.QueryEscape, url.PathEscape
// and url.UserPassword encodings, with REDACTED, before any pattern matching.
//
// Config loading MUST register every camera password (and any other secret
// it reads) as soon as it is known; this is the only defence for a secret
// that appears in free-form prose. Empty strings and strings shorter than 3
// bytes are ignored. Calls are idempotent and safe for concurrent use.
func RegisterSecret(s string) {
	if len(s) < minSecretLen {
		return
	}
	secretsMu.Lock()
	defer secretsMu.Unlock()
	if _, ok := registered[s]; ok {
		return
	}
	registered[s] = struct{}{}

	seen := map[string]struct{}{}
	var all []string
	for r := range registered {
		for _, f := range []string{r, urlQueryEscape(r), urlPathEscape(r), urlUserinfoEscape(r)} {
			if len(f) < minSecretLen {
				continue
			}
			if _, dup := seen[f]; !dup {
				seen[f] = struct{}{}
				all = append(all, f)
			}
		}
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
