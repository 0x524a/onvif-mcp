package registry

import (
	"crypto/md5" //nolint:gosec // HTTP Digest (RFC 2617/7616) is defined in terms of MD5; it is the camera's choice, not ours
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"
)

// maxChallengeParam bounds each challenge value echoed back in an
// Authorization header; the challenge comes from the camera.
const maxChallengeParam = 512

// challenge is one parsed WWW-Authenticate challenge.
type challenge struct {
	scheme string // lower case
	params map[string]string
}

// parseChallenges splits WWW-Authenticate header values into challenges. A
// single value may hold several ("Basic realm=x, Digest realm=y, nonce=z"), so
// the split is done quote-aware on top-level commas: an item that starts with
// a scheme token followed by whitespace starts a new challenge, anything else
// is a name=value parameter of the current one.
func parseChallenges(values []string) []challenge {
	var out []challenge
	for _, v := range values {
		for _, item := range splitTopLevel(v) {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if sch, rest, ok := leadingScheme(item); ok {
				out = append(out, challenge{scheme: strings.ToLower(sch), params: map[string]string{}})
				item = strings.TrimSpace(rest)
				if item == "" {
					continue
				}
			}
			if len(out) == 0 {
				continue
			}
			k, val, ok := splitParam(item)
			if ok {
				out[len(out)-1].params[strings.ToLower(k)] = val
			}
		}
	}
	return out
}

// splitTopLevel splits s at commas that are outside quoted strings.
func splitTopLevel(s string) []string {
	var parts []string
	inQuote, esc := false, false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case esc:
			esc = false
		case inQuote && c == '\\':
			esc = true
		case c == '"':
			inQuote = !inQuote
		case c == ',' && !inQuote:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

// leadingScheme reports whether item begins with an auth-scheme token that is
// followed by whitespace (not '='), returning the scheme and the remainder.
func leadingScheme(item string) (scheme, rest string, ok bool) {
	i := strings.IndexAny(item, " \t")
	tok := item
	if i >= 0 {
		tok = item[:i]
	}
	if tok == "" || strings.ContainsAny(tok, "=\"") {
		return "", "", false
	}
	if i < 0 {
		return tok, "", true // a bare scheme, for example "Negotiate"
	}
	return tok, item[i:], true
}

// splitParam parses name=value or name="quoted \"value\"".
func splitParam(item string) (k, v string, ok bool) {
	eq := strings.IndexByte(item, '=')
	if eq <= 0 {
		return "", "", false
	}
	k = strings.TrimSpace(item[:eq])
	v = strings.TrimSpace(item[eq+1:])
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		raw := v[1 : len(v)-1]
		var b strings.Builder
		for i := 0; i < len(raw); i++ {
			if raw[i] == '\\' && i+1 < len(raw) {
				i++
			}
			b.WriteByte(raw[i])
		}
		v = b.String()
	}
	return k, v, k != ""
}

// errAuthUnsupported means the camera asked for a scheme, algorithm or
// quality of protection this client does not implement.
var errAuthUnsupported = errors.New("unsupported authentication challenge")

// errBasicOverHTTP means only Basic was offered on a plain http request and
// the camera has not opted in to that.
var errBasicOverHTTP = errors.New("basic authentication over plain http is not allowed")

// authorize answers the camera's 401 with the strongest scheme it offered:
// Digest if present, else Basic. The method and uri are those of the request
// being retried.
//
// allowBasic says whether Basic may be answered; it is false on a plain http
// request unless the operator opted in, because the password would cross the
// network in cleartext and an on-path attacker can turn a Digest challenge
// into a Basic one. A Basic-only challenge then gives errBasicOverHTTP.
func authorize(chs []challenge, user, pass, method, uri string, allowBasic bool) (string, error) {
	for _, c := range chs {
		if c.scheme == "digest" {
			return digestHeader(c, user, pass, method, uri)
		}
	}
	for _, c := range chs {
		if c.scheme == "basic" {
			if !allowBasic {
				return "", errBasicOverHTTP
			}
			return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)), nil
		}
	}
	return "", errAuthUnsupported
}

func digestHeader(c challenge, user, pass, method, uri string) (string, error) {
	realm, nonce, opaque := c.params["realm"], c.params["nonce"], c.params["opaque"]
	for _, s := range []string{realm, nonce, opaque, user, uri} {
		if len(s) > maxChallengeParam || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return "", errAuthUnsupported
		}
	}
	if nonce == "" {
		return "", errAuthUnsupported
	}
	alg := strings.ToUpper(c.params["algorithm"])
	if alg == "" {
		alg = "MD5"
	}
	if _, _, ok := hashFor(alg); !ok {
		return "", errAuthUnsupported
	}
	qop := ""
	if q := c.params["qop"]; q != "" {
		for _, o := range strings.Split(q, ",") {
			if strings.EqualFold(strings.TrimSpace(o), "auth") {
				qop = "auth"
			}
		}
		if qop == "" {
			return "", errAuthUnsupported // only auth-int offered
		}
	}
	nc, cnonce := "", ""
	if qop != "" {
		nc = "00000001"
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			return "", errAuthUnsupported
		}
		cnonce = hex.EncodeToString(b)
	}
	resp := digestResponse(alg, user, realm, pass, method, uri, nonce, nc, cnonce, qop)

	var b strings.Builder
	fmt.Fprintf(&b, "Digest username=%s, realm=%s, nonce=%s, uri=%s", quote(user), quote(realm), quote(nonce), quote(uri))
	b.WriteString(", algorithm=" + alg)
	if qop != "" {
		fmt.Fprintf(&b, ", qop=%s, nc=%s, cnonce=%s", qop, nc, quote(cnonce))
	}
	fmt.Fprintf(&b, ", response=%s", quote(resp))
	if opaque != "" {
		fmt.Fprintf(&b, ", opaque=%s", quote(opaque))
	}
	return b.String(), nil
}

// quote renders a quoted-string.
func quote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// hashFor returns the hash for a Digest algorithm token and whether it is the
// -sess variant.
func hashFor(alg string) (func() hash.Hash, bool, bool) {
	switch alg {
	case "MD5":
		return md5.New, false, true
	case "MD5-SESS":
		return md5.New, true, true
	case "SHA-256":
		return sha256.New, false, true
	case "SHA-256-SESS":
		return sha256.New, true, true
	}
	return nil, false, false
}

// digestResponse computes the Digest "response" value (RFC 7616 section 3.4.1;
// for MD5 and qop auth this is RFC 2617 section 3.2.2.1). Without qop it is
// the RFC 2069 form.
func digestResponse(alg, user, realm, pass, method, uri, nonce, nc, cnonce, qop string) string {
	newH, sess, ok := hashFor(alg)
	if !ok {
		return ""
	}
	h := func(s string) string {
		x := newH()
		_, _ = x.Write([]byte(s))
		return hex.EncodeToString(x.Sum(nil))
	}
	ha1 := h(user + ":" + realm + ":" + pass)
	if sess {
		ha1 = h(ha1 + ":" + nonce + ":" + cnonce)
	}
	ha2 := h(method + ":" + uri)
	if qop == "" {
		return h(ha1 + ":" + nonce + ":" + ha2)
	}
	return h(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
}
