package registry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/0x524a/onvif-mcp/internal/netguard"
	"github.com/0x524a/onvif-mcp/internal/redact"
)

// Why FetchSnapshot does not call onvif-go's (*Client).DownloadFile
// (github.com/0x524a/onvif-go v1.2.0, client.go):
//
//   - It sends HTTP Basic credentials on the first request, with no challenge,
//     to whatever URL it is given. The URL is the camera's GetSnapshotUri
//     answer, so a hostile camera chooses where the password goes. Under the
//     registry's guardTransport a foreign host is refused, but with
//     trust_advertised_hosts the Basic header would go to it.
//   - On a failure whose text contains "401" it retries through
//     downloadWithDigestAuth, which builds a brand new http.Client and
//     http.Transport that bypass the registry's guardTransport entirely, use
//     the default redirect policy (up to 10 redirects are followed) and answer
//     any Digest challenge, including one from the host a redirect led to.
//   - It resolves and dials without pinning and without the never-probed
//     address rule, so a name that resolves to a link-local or metadata
//     address is reached.
//   - It reads the body with io.ReadAll and no limit on the Digest path, and
//     with only the registry's 8 MiB SOAP bound on the Basic path, so a 2 GB
//     body is buffered (Digest) or a large one is accepted (Basic).
//   - It returns only the bytes: the status, Content-Type and size are lost.
//
// FetchSnapshot is therefore a separate, narrow implementation that keeps the
// credentials inside this package.

// SnapshotRefusalKind says why FetchSnapshot would not send any request.
type SnapshotRefusalKind int

// The refusal kinds. None carries the camera-supplied address, which is
// untrusted text and may itself hold a secret.
const (
	// RefusedSnapshotMalformed: not a usable http or https URL.
	RefusedSnapshotMalformed SnapshotRefusalKind = iota + 1
	// RefusedSnapshotForeignHost: the host is not the camera's configured host
	// and the camera has not set trust_advertised_hosts.
	RefusedSnapshotForeignHost
	// RefusedSnapshotBlockedAddress: an address that is never contacted, trust
	// or not; checked on the address the name resolves to as well.
	RefusedSnapshotBlockedAddress
	// RefusedSnapshotSchemeDowngrade: the camera is configured with an https
	// endpoint but advertised an http snapshot address on the same host. Its
	// credentials are never offered over plain http in that case.
	RefusedSnapshotSchemeDowngrade
)

// SnapshotRefusal is the error FetchSnapshot returns when it sent nothing
// because of the address. Its text is fixed.
type SnapshotRefusal struct{ Kind SnapshotRefusalKind }

func (r *SnapshotRefusal) Error() string {
	switch r.Kind {
	case RefusedSnapshotForeignHost:
		return "camera advertised a snapshot address on another host"
	case RefusedSnapshotBlockedAddress:
		return "camera advertised a snapshot address that is never contacted"
	case RefusedSnapshotSchemeDowngrade:
		return "camera is configured with an https endpoint but advertised an http snapshot address"
	default:
		return "camera advertised a snapshot address that is not a usable http or https URL"
	}
}

// SnapshotFailure is the class of a SnapshotError.
type SnapshotFailure int

// The failure classes of a request that was sent.
const (
	// SnapshotRedirected: a 3xx answer. Redirects are never followed.
	SnapshotRedirected SnapshotFailure = iota + 1
	// SnapshotUnauthorized: a 401 and no credentials were (or could be) offered.
	SnapshotUnauthorized
	// SnapshotCredentialsRejected: a 401 after the configured credentials were sent.
	SnapshotCredentialsRejected
	// SnapshotAuthUnsupported: the 401 asked for a scheme or algorithm this
	// client does not implement.
	SnapshotAuthUnsupported
	// SnapshotForbidden: a 403.
	SnapshotForbidden
	// SnapshotBadStatus: any other non-2xx status (see Status).
	SnapshotBadStatus
	// SnapshotTooLarge: the body is over the limit (see Size and Limit).
	SnapshotTooLarge
	// SnapshotBasicOverHTTP: the 401 offered only Basic on a plain http
	// request and the camera config does not set allow_basic_over_http. The
	// password was not sent.
	SnapshotBasicOverHTTP
	// SnapshotMalformedReply: the reply was not valid HTTP (bad framing, a
	// header block over the limit, a negative length, and the like).
	SnapshotMalformedReply
	// SnapshotUntrustedCertificate: the https snapshot address presented a
	// certificate that does not verify. There is no option to skip that check.
	SnapshotUntrustedCertificate
)

// SnapshotError is a snapshot request that was sent and did not produce a
// usable body. Its text is fixed: neither the URL nor anything the camera
// wrote is in it.
type SnapshotError struct {
	Kind   SnapshotFailure
	Status int   // the HTTP status, 0 when none
	Size   int64 // SnapshotTooLarge: the size when the camera declared it, else -1
	Limit  int64 // SnapshotTooLarge: the limit in force
	// Authenticated is true when the configured credentials were sent.
	Authenticated bool
}

func (e *SnapshotError) Error() string {
	switch e.Kind {
	case SnapshotRedirected:
		return "snapshot address answered with a redirect, which is not followed"
	case SnapshotUnauthorized:
		return "snapshot address requires authentication and none was offered"
	case SnapshotCredentialsRejected:
		return "snapshot address rejected the configured credentials"
	case SnapshotAuthUnsupported:
		return "snapshot address asked for an authentication method that is not supported"
	case SnapshotForbidden:
		return "snapshot address refused access (HTTP 403)"
	case SnapshotTooLarge:
		return "snapshot is larger than the size limit"
	case SnapshotBasicOverHTTP:
		return "snapshot address offers only HTTP Basic authentication over plain http, which is not used"
	case SnapshotMalformedReply:
		return "snapshot address sent a reply that is not valid HTTP"
	case SnapshotUntrustedCertificate:
		return "snapshot address presented a certificate that is not trusted"
	default:
		return "snapshot address answered with HTTP status " + strconv.Itoa(e.Status)
	}
}

// SnapshotBody is a fetched snapshot.
type SnapshotBody struct {
	// Data is at most the requested limit.
	Data []byte
	// Authenticated is true when the configured credentials were sent.
	Authenticated bool
}

const (
	maxSnapshotURIChars = 2048
	// hardSnapshotLimit bounds the limit a caller may ask for.
	hardSnapshotLimit = 64 << 20
	maxHeaderBytes    = 16 << 10
)

// lookupHost resolves a name for FetchSnapshot; tests replace it to prove the
// name is resolved once and the connection goes to that answer.
var lookupHost = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// FetchSnapshot downloads the snapshot at rawURI, a URI the camera reported
// for GetSnapshotUri, and returns at most limit bytes of it. rawURI is
// untrusted:
//
//   - the scheme must be http or https, the host non-empty, any port 1..65535;
//     userinfo in the URI is discarded;
//   - a host other than the configured endpoint's is refused, with nothing
//     sent, unless the camera sets trust_advertised_hosts; then it is fetched
//     without credentials;
//   - unspecified, multicast, broadcast and link-local addresses, numeric host
//     spellings, and any name that resolves to such an address, are refused
//     even with trust (netguard.NeverProbed);
//   - the host is resolved once and every connection goes to that address, and
//     to nothing else;
//   - redirects are never followed, so a 3xx is an error;
//   - the configured credentials are sent only to the configured host (a
//     trailing dot makes it another host), only after it answered 401, and
//     only by the scheme it asked for (Digest if offered, else Basic); Basic
//     is used over plain http only when the camera sets allow_basic_over_http;
//     an https endpoint with an http snapshot address is refused outright; a
//     second 401 is final;
//   - the body is read through a hard limit of limit+1 bytes, so an oversized
//     or endless body is never buffered; a declared length over the limit is
//     refused before any body byte is read;
//   - the request lives no longer than timeout and ctx; no keep-alive, no
//     proxy, no transparent decompression.
//
// The credentials never leave this package: there is no accessor. Errors are
// *SnapshotRefusal (nothing sent), *SnapshotError, or a transport error whose
// text carries neither the URL nor the credentials.
func (e Entry) FetchSnapshot(ctx context.Context, rawURI string, limit int64, timeout time.Duration) (SnapshotBody, error) {
	malformed := &SnapshotRefusal{Kind: RefusedSnapshotMalformed}
	if e.cred == nil {
		return SnapshotBody{}, malformed
	}
	if limit < 1 || limit > hardSnapshotLimit {
		return SnapshotBody{}, errors.New("snapshot size limit out of range")
	}
	e.cred.mu.RLock()
	cam := e.cred.cam
	e.cred.mu.RUnlock()

	if rawURI == "" || len(rawURI) > maxSnapshotURIChars {
		return SnapshotBody{}, malformed
	}
	u, err := url.Parse(rawURI)
	if err != nil {
		return SnapshotBody{}, malformed // the parse error quotes the URI
	}
	scheme := strings.ToLower(u.Scheme)
	host := u.Hostname()
	if (scheme != "http" && scheme != "https") || u.Opaque != "" || host == "" {
		return SnapshotBody{}, malformed
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if scheme == "https" {
			port = "443"
		}
	} else if n, perr := strconv.Atoi(port); perr != nil || n < 1 || n > 65535 {
		return SnapshotBody{}, malformed
	}

	epHost := endpointHostRaw(cam.Endpoint)
	// A trailing dot makes an absolute DNS name, which is not the name the
	// configured endpoint resolves through (a search domain may apply to it),
	// so it is the configured host only when both are spelled with the dot.
	same := sameHost(host, epHost) && strings.HasSuffix(host, ".") == strings.HasSuffix(epHost, ".")
	if same && cam.Username != "" && endpointScheme(cam.Endpoint) == "https" && scheme != "https" {
		return SnapshotBody{}, &SnapshotRefusal{Kind: RefusedSnapshotSchemeDowngrade}
	}
	if !same {
		if !cam.TrustAdvertisedHosts {
			return SnapshotBody{}, &SnapshotRefusal{Kind: RefusedSnapshotForeignHost}
		}
		if netguard.NeverProbed(host) {
			return SnapshotBody{}, &SnapshotRefusal{Kind: RefusedSnapshotBlockedAddress}
		}
	}
	if timeout <= 0 {
		timeout = cam.Timeout()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Resolve once. Every dial goes to this address, so a resolver that
	// answers differently the second time cannot move the connection.
	ip, err := resolveOnce(ctx, host)
	if err != nil {
		return SnapshotBody{}, cleanTransportErr(err)
	}
	// The refusal is on the resolved address, whatever the name was, and
	// before any connection exists.
	if netguard.NeverProbed(ip) {
		return SnapshotBody{}, &SnapshotRefusal{Kind: RefusedSnapshotBlockedAddress}
	}

	target := url.URL{Scheme: scheme, Host: u.Host, Path: u.Path, RawPath: u.RawPath, RawQuery: u.RawQuery}
	canAuth := same && cam.Username != ""

	tr := &http.Transport{
		DialContext:            pinnedDialer(host, port, net.JoinHostPort(ip, port)),
		DisableKeepAlives:      true,
		DisableCompression:     true, // no Accept-Encoding, and a gzip reply is never inflated
		MaxResponseHeaderBytes: maxHeaderBytes,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		// No Proxy: an HTTP_PROXY in the environment must not divert a
		// request that may carry credentials.
	}
	defer tr.CloseIdleConnections()
	hc := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	do := func(authz string) (*http.Response, error) {
		req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), http.NoBody)
		if rerr != nil {
			return nil, malformed
		}
		req.Header.Set("User-Agent", "onvif-mcp")
		req.Header.Set("Accept", "image/jpeg, image/png")
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		resp, derr := hc.Do(req)
		if derr != nil {
			return nil, classifyTransportErr(derr)
		}
		return resp, nil
	}

	resp, err := do("")
	if err != nil {
		return SnapshotBody{}, err
	}
	authed := false
	if resp.StatusCode == http.StatusUnauthorized {
		chs := parseChallenges(resp.Header.Values("Www-Authenticate"))
		_ = resp.Body.Close()
		if !canAuth {
			return SnapshotBody{}, &SnapshotError{Kind: SnapshotUnauthorized, Status: 401}
		}
		authz, aerr := authorize(chs, cam.Username, cam.Password, http.MethodGet, target.RequestURI(),
			scheme == "https" || cam.AllowBasicOverHTTP)
		if errors.Is(aerr, errBasicOverHTTP) {
			return SnapshotBody{}, &SnapshotError{Kind: SnapshotBasicOverHTTP, Status: 401}
		}
		if aerr != nil {
			return SnapshotBody{}, &SnapshotError{Kind: SnapshotAuthUnsupported, Status: 401}
		}
		// Cover the password in any later text, as PrepareStream does.
		redact.RegisterSecret(cam.Password)
		authed = true
		resp, err = do(authz)
		if err != nil {
			return SnapshotBody{}, err
		}
		if resp.StatusCode == http.StatusUnauthorized {
			_ = resp.Body.Close()
			return SnapshotBody{}, &SnapshotError{Kind: SnapshotCredentialsRejected, Status: 401, Authenticated: true}
		}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return SnapshotBody{}, statusError(resp.StatusCode, authed)
	}
	if resp.ContentLength > limit {
		return SnapshotBody{}, &SnapshotError{Kind: SnapshotTooLarge, Size: resp.ContentLength, Limit: limit, Authenticated: authed}
	}
	data, err := readBody(resp.Body, resp.ContentLength, limit)
	if err != nil {
		return SnapshotBody{}, classifyTransportErr(err)
	}
	if int64(len(data)) > limit {
		return SnapshotBody{}, &SnapshotError{Kind: SnapshotTooLarge, Size: -1, Limit: limit, Authenticated: authed}
	}
	return SnapshotBody{Data: data, Authenticated: authed}, nil
}

// readBody reads at most limit+1 bytes of r. With a declared length (already
// checked against limit) it fills one exact allocation. Without one it reads
// 64 KiB chunks and copies them once into the result, so a body is held at
// most twice and never through geometric re-growth.
func readBody(r io.Reader, declared, limit int64) ([]byte, error) {
	if declared >= 0 {
		buf := make([]byte, declared)
		n, err := io.ReadFull(r, buf)
		if err != nil {
			return nil, err
		}
		// The declared length is complete; one more byte would mean a lying
		// length, which net/http already turns into an error, so there is
		// nothing further to read.
		return buf[:n], nil
	}
	const chunk = 64 << 10
	var chunks [][]byte
	var total int64
	lr := io.LimitReader(r, limit+1)
	for {
		c := make([]byte, chunk)
		n, err := io.ReadFull(lr, c)
		total += int64(n)
		if n > 0 {
			chunks = append(chunks, c[:n])
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	out := make([]byte, 0, total)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out, nil
}

func statusError(code int, authed bool) *SnapshotError {
	switch {
	case code >= 300 && code <= 399:
		return &SnapshotError{Kind: SnapshotRedirected, Status: code, Authenticated: authed}
	case code == http.StatusForbidden:
		return &SnapshotError{Kind: SnapshotForbidden, Status: code, Authenticated: authed}
	}
	return &SnapshotError{Kind: SnapshotBadStatus, Status: code, Authenticated: authed}
}

// resolveOnce returns host as an IP literal, resolving it once if it is a name.
func resolveOnce(ctx context.Context, host string) (string, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap().String(), nil
	}
	addrs, err := lookupHost(ctx, host)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", errors.New("no such host")
	}
	return addrs[0].Unmap().String(), nil
}

// pinnedDialer returns the only dial function the transport may use: a
// connection for host:port goes to the already-resolved pinned address, and
// any other target is refused.
func pinnedDialer(host, port, pinned string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		h, p, err := net.SplitHostPort(addr)
		if err != nil || p != port || !strings.EqualFold(h, host) {
			return nil, errors.New("snapshot client refused to dial an address other than the snapshot host")
		}
		return (&net.Dialer{}).DialContext(ctx, network, pinned)
	}
}

// transportError carries a transport failure's text with the URL removed
// (net/http quotes it in *url.Error), scrubbed, and keeps the chain so
// errors.Is (context.DeadlineExceeded, net.Error) still classifies it.
type transportError struct {
	msg string
	err error
}

func (e *transportError) Error() string { return e.msg }
func (e *transportError) Unwrap() error { return e.err }

// classifyTransportErr turns a failed exchange into the error FetchSnapshot
// returns. A cancelled or timed-out context, a network error and a connection
// that ended early keep their chain, so they classify as unreachable or
// timeout. An untrusted certificate and a reply that is not valid HTTP get
// their own kinds: both are the camera's doing, and neither text is echoed.
func classifyTransportErr(err error) error {
	// *url.Error implements net.Error whatever it wraps, so look inside it.
	orig := err
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var (
		ref    *SnapshotRefusal
		uae    x509.UnknownAuthorityError
		he     x509.HostnameError
		cie    x509.CertificateInvalidError
		cve    *tls.CertificateVerificationError
		neterr net.Error
	)
	switch {
	case errors.As(err, &ref):
		return orig
	case errors.As(err, &uae), errors.As(err, &he), errors.As(err, &cie), errors.As(err, &cve):
		return &SnapshotError{Kind: SnapshotUntrustedCertificate}
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled),
		errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF),
		errors.As(err, &neterr):
		return cleanTransportErr(orig)
	}
	return &SnapshotError{Kind: SnapshotMalformedReply}
}

func cleanTransportErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var ref *SnapshotRefusal
	if errors.As(err, &ref) {
		return err
	}
	return &transportError{msg: redact.Scrub(fmt.Sprintf("snapshot request failed: %v", err)), err: err}
}
