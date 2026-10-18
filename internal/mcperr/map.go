package mcperr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/0x524A/rtspeek/pkg/rtspeek"
	onvif "github.com/0x524a/onvif-go"

	"github.com/0x524a/onvif-mcp/internal/redact"
)

// ErrResponseTooLarge is returned (wrapped) by the registry transport when a
// camera's reply exceeds the size bound.
var ErrResponseTooLarge = errors.New("camera response too large")

// ErrForeignHost is returned (wrapped) by the registry transport when a request
// would go to a host other than the configured endpoint's.
var ErrForeignHost = errors.New("camera advertised a service address on another host")

// classifier is reused rather than reimplemented: rtspeek exports its taxonomy
// but never applies it to the errors DescribeStream returns.
var classifier = rtspeek.NewErrorClassifier()

// isAuthSignal reports whether text indicates an authentication failure. It is
// used both for SOAP fault codes and for RTSP error text.
func isAuthSignal(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "notauthorized") ||
		strings.Contains(l, "not authorized") ||
		strings.Contains(l, "unauthorized") ||
		strings.Contains(l, "authentication failed") ||
		strings.Contains(l, "401")
}

// isAuthText is the stricter form used on onvif-go error text, where a bare
// "401" would also match a port or an address. HTTP 401 and 403 are handled
// separately through the parsed status.
func isAuthText(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "notauthorized") ||
		strings.Contains(l, "not authorized") ||
		strings.Contains(l, "unauthorized") ||
		strings.Contains(l, "authentication failed")
}

var (
	// httpFailedRe matches onvif-go's "HTTP request failed with status N:"
	// error prefix (internal/soap/soap.go), after which it appends the raw
	// response body when that body is not a parseable SOAP fault.
	httpFailedRe = regexp.MustCompile(`HTTP request failed with status \d{3}:`)
	statusRe     = regexp.MustCompile(`(?i)\bstatus(?: code)?[: ]+(\d{3})\b`)
)

// cutBody drops everything from the first '<' after an "HTTP request failed
// with status N:" prefix. A device may echo the request, WS-Security header
// included, in an error body; no raw XML body ever reaches an agent.
func cutBody(s string) string {
	loc := httpFailedRe.FindStringIndex(s)
	if loc == nil {
		return s
	}
	i := strings.IndexByte(s[loc[1]:], '<')
	if i < 0 {
		return s
	}
	return strings.TrimRight(s[:loc[1]+i], " ") + " [response body omitted]"
}

// withoutBody returns s with the camera's reply body removed, for use when
// classifying. The body is the camera's text, not evidence: a 500 page that
// says "unauthorized" or "not found" must not become auth_failed or not_found.
// Everything after the "HTTP request failed with status N:" prefix goes, plain
// text included (cutBody only hides XML for display). A parsed SOAP fault is
// the exception, because there onvif-go put the fault, not a raw body, after
// the prefix (with or without a bracketed code), so it is kept.
func withoutBody(s string) string {
	loc := httpFailedRe.FindStringIndex(s)
	if loc == nil || strings.Contains(s, "SOAP fault:") {
		return s
	}
	return s[:loc[1]]
}

// httpStatus returns the HTTP status named in err's text, or 0.
func httpStatus(s string) int {
	if m := statusRe.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

const (
	hintCredentials = "verify the username and password configured for this camera"
	hintEndpoint404 = "the configured endpoint path returned HTTP 404; check this camera's endpoint in the config (the path after host:port, usually /onvif/device_service)"
	hintRedirect    = "the camera redirected the request and onvif-mcp does not follow redirects; set the camera's endpoint to the redirect target, often the https:// form"
	hintGateway     = "the camera or a gateway in front of it is temporarily unavailable; retry shortly"
	hintTLS         = "endpoint scheme or certificate mismatch; check http vs https in the configured endpoint and the camera's certificate"
	hintGarbage     = "the endpoint answered with something that is not an ONVIF SOAP response; check the configured port and scheme"
	hintBadNumber   = "the camera sent a number that cannot be represented; its reply is malformed and the field cannot be read"
	hintCancelled   = "the call was cancelled before the camera answered"
)

// verdict is a code and hint chosen from transport or HTTP evidence.
type verdict struct {
	code Code
	hint string
}

func isTLSTyped(err error) bool {
	var rh tls.RecordHeaderError
	var cv *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	return errors.As(err, &rh) || errors.As(err, &cv) || errors.As(err, &ua) ||
		errors.As(err, &he) || errors.As(err, &ci)
}

// classifyTransport classifies failures onvif-go v1.2.0 returns as plain
// wrapped errors with no sentinel: transport errors, TLS errors and HTTP
// statuses. Taxonomy choices (spec section 9 has nine closed codes):
//
//   - TLS / scheme / certificate mismatch is invalid_argument: only an
//     operator fixing the configured endpoint or trusting the certificate
//     helps, so it must not be retryable (unreachable is).
//   - A reply that is not HTTP or not SOAP is device_fault: the host answered,
//     but not as an ONVIF device.
//   - 502/503/504 are unreachable (retryable); 404 and redirects point at the
//     configured endpoint, so invalid_argument.
//
// The HTTP status is read before any text heuristic so that a body such as
// "404 page not found" is never taken for a missing token.
func classifyTransport(err error) (verdict, bool) {
	text := withoutBody(err.Error())
	l := strings.ToLower(text)

	if isTLSTyped(err) {
		return verdict{CodeInvalidArgument, hintTLS}, true
	}
	switch httpStatus(text) {
	case 401, 403:
		return verdict{CodeAuthFailed, hintCredentials}, true
	case 404:
		return verdict{CodeInvalidArgument, hintEndpoint404}, true
	case 301, 302, 307, 308:
		return verdict{CodeInvalidArgument, hintRedirect}, true
	case 502, 503, 504:
		return verdict{CodeUnreachable, hintGateway}, true
	}
	if strings.Contains(l, "server gave http response to https client") || strings.Contains(l, "x509:") || strings.Contains(l, "tls:") || (strings.Contains(l, "tls handshake") && !strings.Contains(l, "timeout")) {
		return verdict{CodeInvalidArgument, hintTLS}, true
	}
	var ne0 *strconv.NumError
	if errors.Is(err, strconv.ErrRange) || errors.As(err, &ne0) {
		return verdict{CodeDeviceFault, hintBadNumber}, true
	}
	if strings.Contains(l, "malformed http") || strings.Contains(l, "readlooppeekfaillocked") || strings.Contains(l, "unmarshal soap envelope") {
		return verdict{CodeDeviceFault, hintGarbage}, true
	}
	var ne net.Error
	if (errors.As(err, &ne) && ne.Timeout()) || strings.Contains(l, "i/o timeout") ||
		strings.Contains(l, "timed out") || strings.Contains(l, "tls handshake timeout") {
		return verdict{CodeTimeout, "the camera did not answer in time; retry, or ask the operator to raise timeout_seconds for this camera in the config"}, true
	}
	var oe *net.OpError
	var de *net.DNSError
	unreachable := verdict{CodeUnreachable, "check power, network reachability, and the configured endpoint"}
	if errors.As(err, &oe) || errors.As(err, &de) {
		return unreachable, true
	}
	if isAuthText(text) {
		return verdict{CodeAuthFailed, hintCredentials}, true
	}
	for _, k := range []string{"connection refused", "no route to host", "network is unreachable",
		"no such host", "connection reset", "broken pipe", "closed idle connection", "connection closed"} {
		if strings.Contains(l, k) {
			return unreachable, true
		}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || strings.HasSuffix(l, "eof") {
		return verdict{CodeUnreachable, "the connection closed before the camera answered; check power, the configured port and scheme"}, true
	}
	return verdict{}, false
}

// rootCause returns the text of err with the library's wrapper stack removed.
// It descends through single-%w layers while a layer's text is its own prefix
// plus the next layer's text ("failed to send HTTP request: <next>"), which is
// pure wrapping. It stops at a layer that adds something the next one lacks
// (an HTTP status line over a sentinel) and at joined errors, so information
// is never dropped, only repeated context. Both texts are compared scrubbed,
// because a registry wrapper already holds scrubbed text.
func rootCause(err error) string {
	cur := err
	for {
		u, ok := cur.(interface{ Unwrap() error })
		if !ok {
			break
		}
		next := u.Unwrap()
		if next == nil {
			break
		}
		if !isPrefixWrapper(cur, next) {
			break
		}
		cur = next
	}
	return cur.Error()
}

// isPrefixWrapper reports whether outer's text is some prefix plus inner's. An
// inner error whose Error method panics (a zero-valued x509 error does) ends the
// descent rather than the call.
func isPrefixWrapper(outer, inner error) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return strings.HasSuffix(redact.Scrub(outer.Error()), redact.Scrub(inner.Error()))
}

// withOperation prefixes a message with the failed operation, so the line reads
// "GetProfiles failed: <root cause>".
func withOperation(operation, msg string) string {
	if operation == "" {
		return msg
	}
	return operation + " failed: " + msg
}

// FromError maps an onvif-go error onto the taxonomy.
//
// Order matters: *ONVIFError has no Unwrap method, so it can never match a
// sentinel through errors.Is. It is therefore checked first with errors.As.
func FromError(err error, camera, operation string) *ToolError {
	if err == nil {
		return nil
	}
	return sanitize(fromError(err, camera, operation))
}

// maxTextLen bounds every free-text field of a ToolError, in bytes.
const maxTextLen = 4096

const ellipsis = "\u2026"

// cleanText scrubs s and truncates the result to maxTextLen bytes with a
// trailing ellipsis. The input is bounded before Scrub runs, since Scrub is
// slow on huge strings, with the cut-straddling-a-secret guard that
// redact.ScrubBounded documents.
func cleanText(s string) string {
	return redact.ScrubBounded(s, maxTextLen, ellipsis)
}

// sanitize scrubs and length-caps every free-text field of te, as defence in
// depth: no constructor path may emit credentials regardless of where the
// text came from.
func sanitize(te *ToolError) *ToolError {
	te.Message = cleanText(te.Message)
	te.Hint = cleanText(te.Hint)
	te.Camera = cleanText(te.Camera)
	te.Operation = cleanText(te.Operation)
	if te.SOAP != nil {
		te.SOAP.Code = cleanText(te.SOAP.Code)
		te.SOAP.Reason = cleanText(te.SOAP.Reason)
	}
	return te
}

func fromError(err error, camera, operation string) *ToolError {
	if err == nil {
		return nil
	}
	root := rootCause(err)
	te := &ToolError{
		Camera:    camera,
		Operation: operation,
		Message:   withOperation(operation, redact.Scrub(cutBody(root))),
	}

	var oe *onvif.ONVIFError
	if errors.As(err, &oe) {
		te.SOAP = &SOAPFault{Code: oe.Code, Reason: oe.Reason}
		if isAuthSignal(oe.Code) || isAuthSignal(oe.Reason) {
			te.Code = CodeAuthFailed
			te.Hint = "verify the username and password configured for this camera"
		} else {
			te.Code = CodeDeviceFault
			te.Hint = "the device returned a SOAP fault; the operation may be advertised but not implemented"
		}
		te.Retryable = te.Code.Retryable()
		return te
	}

	switch {
	case errors.Is(err, ErrResponseTooLarge):
		// Fixed text: the wrapped chain quotes the request URL.
		te.Message = ErrResponseTooLarge.Error()
		te.Code = CodeDeviceFault
		te.Hint = "the camera sent a reply larger than onvif-mcp accepts; it is misbehaving or hostile"
	case errors.Is(err, ErrForeignHost):
		// Fixed text: the wrapped chain quotes the advertised URL, which can
		// carry a query secret.
		te.Message = ErrForeignHost.Error()
		te.Code = CodeDeviceFault
		te.Hint = "the request was refused; if this camera is NATed or multi-homed, the operator can set trust_advertised_hosts for it in the config"
	case errors.Is(err, onvif.ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		te.Code = CodeTimeout
		te.Hint = "the camera did not answer in time; retry, or ask the operator to raise timeout_seconds for this camera in the config"
	case errors.Is(err, context.Canceled):
		te.Code = CodeInternal
		te.Hint = hintCancelled
	case errors.Is(err, onvif.ErrConnectionFailed):
		te.Code = CodeUnreachable
		te.Hint = "check power, network reachability, and the configured endpoint"
	case errors.Is(err, onvif.ErrAuthenticationFailed),
		errors.Is(err, onvif.ErrAuthenticationRequired):
		te.Code = CodeAuthFailed
		te.Hint = "verify the username and password configured for this camera"
	case errors.Is(err, onvif.ErrServiceNotSupported),
		errors.Is(err, onvif.ErrPTZNotSupported),
		errors.Is(err, onvif.ErrSnapshotNotSupported):
		te.Code = CodeNotSupported
		te.Hint = "this camera does not implement the requested service"
	case errors.Is(err, onvif.ErrProfileNotFound),
		errors.Is(err, onvif.ErrPresetNotFound),
		errors.Is(err, onvif.ErrVideoSourceNotFound):
		te.Code = CodeNotFound
		te.Hint = "list the available tokens first, then pass one of them"
	case errors.Is(err, onvif.ErrInvalidParameter),
		errors.Is(err, onvif.ErrInvalidEndpoint),
		errors.Is(err, onvif.ErrInvalidEndpointFormat):
		te.Code = CodeInvalidArgument
	default:
		if f, prefix, ok := parseSOAPFault(err.Error()); ok {
			te.SOAP = &SOAPFault{Code: f.Code, Reason: f.Reason}
			if _, p, ok := parseSOAPFault(root); ok {
				prefix = p
			}
			te.Message = withOperation(operation, redact.Scrub(prefix+"SOAP fault: ["+f.Code+"] "+f.Reason))
			switch {
			case httpStatus(prefix) == 401 || httpStatus(prefix) == 403 || isAuthText(f.Code+" "+f.Reason):
				te.Code = CodeAuthFailed
				te.Hint = hintCredentials
			case isNotFoundText(f.Code + " " + f.Reason):
				te.Code = CodeNotFound
				te.Hint = "list the available tokens first, then pass one of them"
			default:
				te.Code = CodeDeviceFault
				te.Hint = "the device returned a SOAP fault; the operation may be advertised but not implemented"
			}
			break
		}
		if v, ok := classifyTransport(err); ok {
			te.Code, te.Hint = v.code, v.hint
			break
		}
		if isNotFoundText(withoutBody(err.Error())) {
			te.Code = CodeNotFound
			te.Hint = "list the available tokens first, then pass one of them"
			break
		}
		te.Code = CodeInternal
	}
	te.Retryable = te.Code.Retryable()
	return te
}

// soapFaultRe matches onvif-go v1.2.0's fault text (internal/soap/soap.go,
// faultError): "SOAP fault: [code] reason" with ": detail" appended when the
// device sent one. The library returns it as a plain wrapped error, so the
// text is all there is to parse.
var soapFaultRe = regexp.MustCompile(`(?s)SOAP fault: \[([^\]]*)\] ?(.*)`)

// parseSOAPFault extracts the fault code and reason from err text, and returns
// the text before the fault marker (which may carry "HTTP request failed with
// status N:"). Anything from the first '<' on is dropped: no raw XML body ever
// reaches an agent. Only the first marker counts, so a fault reason that
// itself mentions "status 404" cannot steer classification.
func parseSOAPFault(s string) (f SOAPFault, prefix string, ok bool) {
	loc := soapFaultRe.FindStringSubmatchIndex(s)
	if loc == nil {
		return SOAPFault{}, "", false
	}
	prefix = s[:loc[0]]
	f.Code = strings.TrimSpace(s[loc[2]:loc[3]])
	reason := s[loc[4]:loc[5]]
	if i := strings.IndexByte(reason, '<'); i >= 0 {
		reason = strings.TrimRight(reason[:i], " ") + " [xml omitted]"
	}
	f.Reason = strings.TrimSpace(reason)
	return f, prefix, true
}

// isNotFoundText reports whether an unclassified error's text says a token or
// entity does not exist, including the ONVIF fault subcodes NoEntity, NoProfile
// and NoToken.
func isNotFoundText(s string) bool {
	l := strings.ToLower(s)
	for _, k := range []string{"not found", "noentity", "noprofile", "notoken", "no such"} {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}

// FromStreamError maps an rtspeek error onto the taxonomy, reusing rtspeek's
// own classifier and then correcting for two ordering weaknesses in it.
func FromStreamError(err error, camera, operation string) *ToolError {
	if err == nil {
		return nil
	}
	return sanitize(fromStreamError(err, camera, operation))
}

func fromStreamError(err error, camera, operation string) *ToolError {
	if err == nil {
		return nil
	}
	te := &ToolError{
		Camera:    camera,
		Operation: operation,
		Message:   redact.Scrub(err.Error()),
	}

	if errors.Is(err, rtspeek.ErrInvalidURL) {
		te.Code = CodeInvalidArgument
		return te
	}

	reason := classifier.Classify(err)

	// Classify tests for "closed" before it tests for auth, so an error reading
	// "connection closed after 401 Unauthorized" returns connection_closed; and
	// a 401 carrying no WWW-Authenticate header returns other. Re-check auth
	// before accepting either verdict.
	if (reason == "connection_closed" || reason == "other") && isAuthSignal(err.Error()) {
		reason = "auth_required"
	}

	switch reason {
	case "connection_refused", "dns_error", "connection_closed":
		te.Code = CodeUnreachable
		te.Hint = "the stream endpoint is not reachable from this host"
	case "timeout":
		te.Code = CodeTimeout
	case "auth_required":
		te.Code = CodeAuthFailed
		te.Hint = "the stream rejected the camera's configured credentials"
	case "not_found":
		te.Code = CodeNotFound
	case "unsupported_scheme":
		te.Code = CodeInvalidArgument
	default:
		te.Code = CodeInternal
	}
	te.Retryable = te.Code.Retryable()
	return te
}

// Blocked builds the payload for a call refused by onvif-mcp's own policy
// rather than by the camera. A non-nil retryAfterSeconds marks it retryable.
func Blocked(camera, operation, message string, retryAfterSeconds *int) *ToolError {
	te := &ToolError{
		Code:      CodeBlockedByPolicy,
		Camera:    camera,
		Operation: operation,
		Message:   message,
	}
	if retryAfterSeconds != nil {
		te.Retryable = true
		te.RetryAfterSeconds = retryAfterSeconds
	}
	return sanitize(te)
}
