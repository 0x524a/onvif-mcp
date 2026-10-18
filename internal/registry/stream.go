package registry

import (
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/0x524a/onvif-mcp/internal/redact"
)

// StreamRefusalKind says why PrepareStream would not build a probe URL.
type StreamRefusalKind int

// The refusal kinds. None of them carries the camera-supplied address: it is
// untrusted text and may itself hold a secret.
const (
	// RefusedMalformed: not a usable rtsp or rtsps URL, or a port outside 1..65535.
	RefusedMalformed StreamRefusalKind = iota + 1
	// RefusedForeignHost: the host is not the camera's configured host and the
	// camera has not set trust_advertised_hosts.
	RefusedForeignHost
	// RefusedBlockedAddress: an address that is never probed, trust or not.
	RefusedBlockedAddress
)

// StreamRefusal is the error PrepareStream returns. Its text is fixed.
type StreamRefusal struct{ Kind StreamRefusalKind }

func (r *StreamRefusal) Error() string {
	switch r.Kind {
	case RefusedForeignHost:
		return "camera advertised a stream address on another host"
	case RefusedBlockedAddress:
		return "camera advertised a stream address that is never probed"
	default:
		return "camera advertised a stream address that is not a usable rtsp or rtsps URL"
	}
}

// maxStreamURIChars bounds a camera-supplied stream URI.
const maxStreamURIChars = 2048

// StreamProbe is the result of PrepareStream: a URL ready for the stream
// prober, carrying the camera's credentials when (and only when) the stream
// host is the camera's own. It is the only way credentials leave the registry
// and it exists solely for stream.inspect.
//
// It formats as REDACTED under every fmt verb, as JSON and text, and as a
// slog value, so logging or marshalling one cannot print the credentials.
// CredentialedURL is the single accessor of the secret.
type StreamProbe struct{ p *streamProbe }

type streamProbe struct {
	target        string
	display       string
	authenticated bool
	// forms are literal strings to remove from any text, longest first.
	forms []string
	// ci matches the password, and its escaped form, in any letter case.
	ci *regexp.Regexp
}

const streamMark = "registry.StreamProbe{REDACTED}"

// String returns a fixed marker.
func (s StreamProbe) String() string { return streamMark }

// GoString returns a fixed marker.
func (s StreamProbe) GoString() string { return streamMark }

// Format prints a fixed marker under every verb.
func (s StreamProbe) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, streamMark) }

// LogValue implements slog.LogValuer.
func (s StreamProbe) LogValue() slog.Value { return slog.StringValue("REDACTED") }

// MarshalJSON encodes a fixed marker.
func (s StreamProbe) MarshalJSON() ([]byte, error) { return []byte(`"REDACTED"`), nil }

// MarshalText encodes a fixed marker.
func (s StreamProbe) MarshalText() ([]byte, error) { return []byte("REDACTED"), nil }

// MarshalBinary encodes a fixed marker.
func (s StreamProbe) MarshalBinary() ([]byte, error) { return []byte("REDACTED"), nil }

// CredentialedURL returns the URL to probe. When Authenticated it contains the
// camera's password: hand it to the prober and nothing else.
func (s StreamProbe) CredentialedURL() string {
	if s.p == nil {
		return ""
	}
	return s.p.target
}

// Authenticated reports whether CredentialedURL carries credentials.
func (s StreamProbe) Authenticated() bool { return s.p != nil && s.p.authenticated }

// Display is the stream address without credentials, query or fragment:
// scheme, host, port and path.
func (s StreamProbe) Display() string {
	if s.p == nil {
		return ""
	}
	return s.p.display
}

// Scrub removes the credentials, in every form they can take in text, and
// then applies redact.Scrub.
func (s StreamProbe) Scrub(text string) string {
	if s.p != nil {
		for _, f := range s.p.forms {
			text = strings.ReplaceAll(text, f, "REDACTED")
		}
		if s.p.ci != nil {
			text = s.p.ci.ReplaceAllLiteralString(text, "REDACTED")
		}
	}
	return redact.Scrub(text)
}

// PrepareStream builds the URL stream.inspect probes from a stream URI the
// camera reported. The URI comes from the camera, so it is untrusted:
//
//   - scheme must be rtsp or rtsps, the host non-empty, any port 1..65535;
//   - userinfo in the camera's URI is discarded, never used or echoed;
//   - the configured credentials are injected only when the URI's host equals
//     the host of the configured ONVIF endpoint (the rule the advertised-host
//     guard applies to service addresses: case, trailing dot and IP spelling
//     ignored, port ignored);
//   - any other host is refused (RefusedForeignHost) unless the camera sets
//     trust_advertised_hosts, in which case the URL carries no credentials;
//   - unspecified, multicast, broadcast and link-local addresses, and numeric
//     host spellings a resolver may read as an address (decimal, octal, hex),
//     are refused even with trust.
func (e Entry) PrepareStream(rawURI string) (StreamProbe, error) {
	malformed := &StreamRefusal{Kind: RefusedMalformed}
	if e.cred == nil {
		return StreamProbe{}, malformed
	}
	e.cred.mu.RLock()
	cam := e.cred.cam
	e.cred.mu.RUnlock()

	if rawURI == "" || len(rawURI) > maxStreamURIChars {
		return StreamProbe{}, malformed
	}
	u, err := url.Parse(rawURI)
	if err != nil {
		// The parse error text quotes the URI; drop it.
		return StreamProbe{}, malformed
	}
	scheme := strings.ToLower(u.Scheme)
	host := u.Hostname()
	if (scheme != "rtsp" && scheme != "rtsps") || u.Opaque != "" || host == "" {
		return StreamProbe{}, malformed
	}
	if p := u.Port(); p != "" {
		n, perr := strconv.Atoi(p)
		if perr != nil || n < 1 || n > 65535 {
			return StreamProbe{}, malformed
		}
	}

	same := sameHost(host, endpointHost(cam.Endpoint))
	if !same {
		if !cam.TrustAdvertisedHosts {
			return StreamProbe{}, &StreamRefusal{Kind: RefusedForeignHost}
		}
		if neverProbed(host) {
			return StreamProbe{}, &StreamRefusal{Kind: RefusedBlockedAddress}
		}
	}

	out := url.URL{Scheme: scheme, Host: u.Host, Path: u.Path, RawPath: u.RawPath, RawQuery: u.RawQuery}
	display := url.URL{Scheme: scheme, Host: u.Host, Path: u.Path, RawPath: u.RawPath}
	sp := &streamProbe{display: display.String()}
	if same && cam.Username != "" {
		if cam.Password != "" {
			out.User = url.UserPassword(cam.Username, cam.Password)
		} else {
			out.User = url.User(cam.Username)
		}
		sp.authenticated = true
	}
	sp.target = out.String()

	// The canonical string must read back as the same host and the same
	// credentials, or something in the escaping is wrong; refuse rather than
	// send a credential somewhere unintended.
	back, err := url.Parse(sp.target)
	if err != nil || !sameHost(back.Hostname(), host) {
		return StreamProbe{}, malformed
	}
	if sp.authenticated {
		pw, _ := back.User.Password()
		if back.User.Username() != cam.Username || pw != cam.Password {
			return StreamProbe{}, malformed
		}
		sp.forms = scrubForms(cam.Username, cam.Password, sp.target)
		sp.ci = caseInsensitiveForms(cam.Username, cam.Password)
		// Cover the password everywhere, including prose in later errors.
		redact.RegisterSecret(cam.Password)
	}
	return StreamProbe{p: sp}, nil
}

// scrubForms lists the strings that must never survive in text, longest first.
func scrubForms(user, pass, target string) []string {
	set := map[string]struct{}{target: {}}
	ui := url.UserPassword(user, pass).String() // escaped "user:pass"
	set[ui+"@"] = struct{}{}
	if pass != "" {
		set[ui] = struct{}{}
		set[user+":"+pass+"@"] = struct{}{}
		if len(pass) >= 3 {
			enc := ui[strings.IndexByte(ui, ':')+1:]
			for _, f := range []string{pass, enc, url.QueryEscape(pass), url.PathEscape(pass), strings.ToLower(enc)} {
				set[f] = struct{}{}
			}
		}
		// A server can reflect the Basic payload, or the password alone, in
		// base64. Cover both alphabets, with and without padding.
		raws := []string{user + ":" + pass}
		if len(pass) >= 3 {
			raws = append(raws, pass)
		}
		for _, raw := range raws {
			for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
				set[e.EncodeToString([]byte(raw))] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for f := range set {
		if f != "" {
			out = append(out, f)
		}
	}
	// Longest first so a short form cannot leave the rest of a longer one.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && len(out[j]) > len(out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// caseInsensitiveForms returns a matcher for the password in any letter case
// (so "SECRET" and "secret" are removed when "Secret" is configured), raw and
// userinfo-escaped. It is nil when the password is shorter than three bytes,
// which would shred ordinary text.
func caseInsensitiveForms(user, pass string) *regexp.Regexp {
	if len(pass) < 3 {
		return nil
	}
	ui := url.UserPassword(user, pass).String()
	enc := ui[strings.IndexByte(ui, ':')+1:]
	alts := []string{regexp.QuoteMeta(pass)}
	if enc != pass {
		alts = append(alts, regexp.QuoteMeta(enc))
	}
	re, err := regexp.Compile("(?i)" + strings.Join(alts, "|"))
	if err != nil {
		return nil
	}
	return re
}

// neverProbed reports whether host is a target onvif-mcp refuses to probe even
// for a camera that trusts its advertised hosts: unspecified, multicast,
// broadcast and link-local addresses (this covers the 169.254.169.254 cloud
// metadata address), IPv4-mapped forms of those, and numeric spellings that
// net/netip does not parse but a system resolver may.
func neverProbed(host string) bool {
	h := strings.TrimSuffix(host, ".")
	if a, err := netip.ParseAddr(h); err == nil {
		a = a.WithZone("").Unmap()
		return a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
			a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) ||
			(a.Is4() && a.As4()[0] == 0)
	}
	if net.ParseIP(h) != nil {
		return true // unexpected spelling of an IP; do not guess
	}
	last := h
	if i := strings.LastIndexByte(h, '.'); i >= 0 {
		last = h[i+1:]
	}
	if last == "" {
		return true
	}
	if strings.HasPrefix(strings.ToLower(last), "0x") {
		return true
	}
	for _, c := range last {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true // a final label of digits only is an address spelling, not a name
}
