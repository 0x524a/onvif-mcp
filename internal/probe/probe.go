// Package probe runs the RTSP OPTIONS + DESCRIBE handshake behind an
// interface onvif-mcp can fake.
//
// The real prober drives a gortsplib client directly (see NewRTSP for why it
// does not use rtspeek.DescribeStream). rtspeek is still used for its error
// sentinel and error classifier.
//
// The real prober treats the stream server as hostile. Output is bounded
// (track count, string length, dimensions, latency), the call always returns
// within the timeout plus a small slack, nothing is written to stdout or
// stderr (stdout is the JSON-RPC channel), and no error it returns contains the
// URL or its userinfo.
package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/0x524A/rtspeek/pkg/rtspeek"
	"github.com/bluenviron/gortsplib/v5"
	"github.com/bluenviron/gortsplib/v5/pkg/base"
	"github.com/bluenviron/gortsplib/v5/pkg/description"
	"github.com/bluenviron/gortsplib/v5/pkg/format"
	"github.com/bluenviron/gortsplib/v5/pkg/liberrors"
	"github.com/bluenviron/mediacommon/v2/pkg/codecs/h264"
	"github.com/bluenviron/mediacommon/v2/pkg/codecs/h265"

	"github.com/0x524a/onvif-mcp/internal/netguard"
	"github.com/0x524a/onvif-mcp/internal/redact"
)

// Bounds applied to every Result the real prober returns.
const (
	// MaxTracks caps the tracks reported from one DESCRIBE.
	MaxTracks = 32
	// MaxStringBytes caps every string field, in bytes.
	MaxStringBytes = 64
	// MaxDimension caps a reported width or height.
	MaxDimension = 65535

	defaultTimeout = 10 * time.Second
	maxTimeout     = 60 * time.Second
	// guardSlack is how long past the timeout the outer guard waits for
	// rtspeek before giving up on it.
	guardSlack = 500 * time.Millisecond
	// maxErrorBytes bounds the error text taken from the library.
	maxErrorBytes = 512
)

// Track is one media track, reduced to what an agent needs.
type Track struct {
	Index  int    `json:"index"`
	Type   string `json:"type"`
	Format string `json:"format,omitempty"`
	Width  int    `json:"width,omitempty"`
	Height int    `json:"height,omitempty"`
}

// Result is a stream probe outcome.
type Result struct {
	Reachable  bool    `json:"reachable"`
	DescribeOK bool    `json:"describe_ok"`
	Protocol   string  `json:"protocol,omitempty"`
	LatencyMs  float64 `json:"latency_ms"`
	Tracks     []Track `json:"tracks"`
	// TotalTracks is how many tracks the stream described; Tracks holds at
	// most MaxTracks of them, and Truncated says whether some were left out.
	TotalTracks int  `json:"total_tracks"`
	Truncated   bool `json:"tracks_truncated"`
}

// Prober performs an RTSP OPTIONS + DESCRIBE handshake.
type Prober interface {
	Describe(ctx context.Context, rtspURL string, timeout time.Duration) (*Result, error)
}

type rtspProber struct{}

// NewRTSP returns a Prober that runs the RTSP OPTIONS + DESCRIBE handshake on
// a gortsplib client built here (gortsplib v5: Client.Start, Options,
// Describe). It does not call rtspeek.DescribeStream: that function drives a
// client that follows 3xx redirects to other hosts with the credentials
// attached and cannot be cancelled once a redirect loop starts, and rtspeek
// exposes neither a dialer nor a redirect switch. Track classification is
// reimplemented from the SDP media descriptions (rtspeek's classifier is
// unexported); H.264/H.265 resolution uses the mediacommon SPS parser, the
// same one rtspeek uses.
//
// The client may reach exactly one address: the host:port of the URL, resolved
// once up front. Any other dial, and any 3xx response, is an error. A
// non-positive timeout means 10s; it is capped at 60s.
func NewRTSP() Prober { return rtspProber{} }

// ErrEndedDuringDescribe is attached to the error returned when the stream
// server drops the connection (EOF or reset) while answering DESCRIBE.
var ErrEndedDuringDescribe = errors.New("stream ended the connection during DESCRIBE")

// ErrRedirected and errDialRefused are the errors for a 3xx and for a dial the
// client may not make.
var (
	ErrRedirected = errors.New("stream redirected; not followed")
	// ErrBlockedAddress is returned, before any connection, when the stream's
	// host resolves to an address that is never probed (unspecified,
	// multicast, broadcast or link-local).
	ErrBlockedAddress = errors.New("stream host resolves to an address that is never probed")
	errDialRefused    = errors.New("stream client refused to dial an address other than the probed one")
)

type outcome struct {
	res *Result
	err error
}

func (rtspProber) Describe(ctx context.Context, rtspURL string, timeout time.Duration) (*Result, error) {
	timeout = normaliseTimeout(timeout)
	secrets := secretsOf(rtspURL)

	u, err := base.ParseURL(rtspURL)
	if err != nil || (u.Scheme != "rtsp" && u.Scheme != "rtsps") || u.Hostname() == "" {
		return nil, newError("invalid rtsp url", rtspeek.ErrInvalidURL)
	}

	// A fresh context linked only by cancellation: values from the caller are
	// dropped.
	cctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	stop := context.AfterFunc(ctx, cancel)
	defer stop()

	lookup := lookupNetIP // read here: the probe goroutine can outlive this call
	done := make(chan outcome, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- outcome{err: errors.New("stream probe failed internally")}
			}
		}()
		res, err := describe(cctx, u, timeout, lookup)
		done <- outcome{res: res, err: err}
	}()

	guard := time.NewTimer(timeout + guardSlack)
	defer guard.Stop()

	var o outcome
	select {
	case o = <-done:
	case <-guard.C:
		return nil, newError("stream probe timed out", context.DeadlineExceeded)
	}
	if o.err != nil {
		return nil, wrapError(ctx, cctx, o.err, secrets)
	}
	return Bound(o.res), nil
}

// normaliseTimeout maps a non-positive timeout to the default and caps the rest.
func normaliseTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultTimeout
	}
	if d > maxTimeout {
		return maxTimeout
	}
	return d
}

// pinnedDial returns the only dial function the client may use: one
// connection, to want, made to the already-resolved pinned address, and none
// once a redirect has been seen.
func pinnedDial(want, pinned string, redirected *atomic.Bool) func(context.Context, string, string) (net.Conn, error) {
	var dials atomic.Int32
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != want || redirected.Load() || dials.Add(1) > 1 {
			return nil, errDialRefused
		}
		return (&net.Dialer{}).DialContext(ctx, network, pinned)
	}
}

// describe runs the handshake. It owns the client and always closes it, and
// closes it early when ctx ends, so a cancelled or timed-out probe leaves no
// connection or goroutine behind.
func describe(ctx context.Context, u *base.URL, timeout time.Duration, lookup lookupFunc) (*Result, error) {
	start := time.Now()
	addr := canonicalAddr(u)
	host, port, _ := net.SplitHostPort(addr)

	// Resolve once. Every dial goes to this IP, so a resolver that answers
	// differently the second time cannot move the connection.
	ip, err := resolveOnce(ctx, host, lookup)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	// The refusal is on the resolved address, whatever the name was, and
	// before any client exists, so nothing is dialled.
	if netguard.NeverProbed(ip) {
		return nil, ErrBlockedAddress
	}
	pinned := net.JoinHostPort(ip, port)

	var redirected atomic.Bool
	c := &gortsplib.Client{
		Scheme:       u.Scheme,
		Host:         u.Host,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
		DialContext:  pinnedDial(addr, pinned, &redirected),
		OnResponse: func(r *base.Response) {
			if r != nil && r.StatusCode >= 300 && r.StatusCode <= 399 {
				redirected.Store(true)
			}
		},
		// gortsplib logs through the standard logger by default, which writes
		// to stderr; nothing here may write there.
		OnTransportSwitch: func(error) {},
		OnPacketsLost:     func(uint64) {},
		OnDecodeError:     func(error) {},
	}
	if u.Scheme == "rtsps" {
		// Verify the certificate against the name in the URL, as gortsplib does
		// by default, though the TCP connection goes to the pinned IP.
		c.TLSConfig = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}
	if err := c.Start(); err != nil {
		return nil, fmt.Errorf("RTSP start failed: %w", err)
	}
	stop := context.AfterFunc(ctx, c.Close)
	defer func() { stop(); c.Close() }()

	res := &Result{Protocol: "rtsp"}
	if _, err := c.Options(u); err != nil {
		if redirected.Load() {
			return nil, ErrRedirected
		}
		if !isStatus(err, base.StatusUnauthorized) {
			return nil, fmt.Errorf("RTSP options failed: %w", err)
		}
	}
	res.Reachable = true

	desc, _, err := c.Describe(u)
	if redirected.Load() {
		return nil, ErrRedirected
	}
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) {
			return nil, fmt.Errorf("RTSP describe failed: %w (%w)", ErrEndedDuringDescribe, err)
		}
		return nil, fmt.Errorf("RTSP describe failed: %w", err)
	}
	res.DescribeOK = true
	res.LatencyMs = float64(time.Since(start)) / float64(time.Millisecond)
	res.TotalTracks = len(desc.Medias)
	for i, m := range desc.Medias {
		if i >= MaxTracks {
			break
		}
		res.Tracks = append(res.Tracks, classify(i, m))
	}
	return res, nil
}

func isStatus(err error, code base.StatusCode) bool {
	var bad liberrors.ErrClientBadStatusCode
	return errors.As(err, &bad) && bad.Code == code
}

// canonicalAddr is the host:port gortsplib dials for u, with the scheme's
// default port when the URL has none (gortsplib client.go canonicalAddr).
func canonicalAddr(u *base.URL) string {
	port := u.Port()
	if port == "" {
		port = "554"
		if u.Scheme == "rtsps" {
			port = "322"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// lookupNetIP is the resolver; tests replace it to prove the name is resolved
// once and the connection goes to that answer.
type lookupFunc = func(ctx context.Context, network, host string) ([]netip.Addr, error)

var lookupNetIP lookupFunc = net.DefaultResolver.LookupNetIP

// resolveOnce returns host as an IP literal, resolving it once if it is a name.
func resolveOnce(ctx context.Context, host string, lookup lookupFunc) (string, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return a.String(), nil
	}
	addrs, err := lookup(ctx, "ip", host)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", errors.New("no such host")
	}
	return addrs[0].String(), nil
}

// classify reduces one SDP media description to a Track. The first format
// names the track; resolution is read from the SPS the stream carries in its
// own SDP, for H.264 and H.265 only, and is left zero when absent or unparsable.
func classify(idx int, m *description.Media) Track {
	t := Track{Index: idx, Type: string(m.Type)}
	if len(m.Formats) == 0 {
		return t
	}
	f := m.Formats[0]
	t.Format = codecName(f)
	if m.Type != description.MediaTypeVideo {
		return t
	}
	switch ct := f.(type) {
	case *format.H264:
		var sps h264.SPS
		if len(ct.SPS) > 0 && sps.Unmarshal(ct.SPS) == nil {
			t.Width, t.Height = sps.Width(), sps.Height()
		}
	case *format.H265:
		var sps h265.SPS
		if len(ct.SPS) > 0 && sps.Unmarshal(ct.SPS) == nil {
			t.Width, t.Height = sps.Width(), sps.Height()
		}
	}
	if t.Width <= 0 || t.Height <= 0 {
		t.Width, t.Height = 0, 0
	}
	return t
}

// Bound returns a copy of r that is safe to hand to an agent: at most
// MaxTracks tracks, strings clipped and stripped of control characters,
// dimensions in [0, MaxDimension], and a finite non-negative latency.
func Bound(r *Result) *Result {
	if r == nil {
		return nil
	}
	out := &Result{
		Reachable:  r.Reachable,
		DescribeOK: r.DescribeOK,
		Protocol:   clean(r.Protocol),
		LatencyMs:  r.LatencyMs,
		Tracks:     []Track{},
	}
	if math.IsNaN(out.LatencyMs) || math.IsInf(out.LatencyMs, 0) || out.LatencyMs < 0 {
		out.LatencyMs = 0
	}
	for i, t := range r.Tracks {
		if i >= MaxTracks {
			break
		}
		out.Tracks = append(out.Tracks, Track{
			Index:  t.Index,
			Type:   clean(t.Type),
			Format: clean(t.Format),
			Width:  dim(t.Width),
			Height: dim(t.Height),
		})
	}
	out.TotalTracks = max(r.TotalTracks, len(r.Tracks), 0)
	out.Truncated = out.TotalTracks > len(out.Tracks)
	return out
}

func dim(n int) int {
	switch {
	case n < 0:
		return 0
	case n > MaxDimension:
		return MaxDimension
	}
	return n
}

// clean removes control, format and invalid characters, then clips to
// MaxStringBytes without splitting a rune.
func clean(s string) string {
	if len(s) > 4*MaxStringBytes {
		s = s[:4*MaxStringBytes]
	}
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 {
			return -1
		}
		return r
	}, s)
	for len(s) > MaxStringBytes {
		_, n := utf8.DecodeLastRuneInString(s[:MaxStringBytes])
		cut := MaxStringBytes
		if !utf8.ValidString(s[:cut]) {
			cut -= n
		}
		s = s[:cut]
	}
	return s
}

// secretsOf extracts the literal userinfo parts of rawURL so they can be
// removed from library error text even when no URL-shaped substring survives.
func secretsOf(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil || u.User == nil {
		return nil
	}
	var s []string
	if p, ok := u.User.Password(); ok && len(p) >= 3 { // same floor as registry scrubForms
		s = append(s, p)
	}
	if n := u.User.Username(); len(n) >= 3 {
		s = append(s, n)
	}
	return s
}

// sentinels are the error identities downstream classification relies on.
// They are re-attached by identity, never by carrying the library's error
// chain, which can hold text derived from the URL.
var sentinels = []error{rtspeek.ErrInvalidURL, context.DeadlineExceeded, context.Canceled, ErrEndedDuringDescribe, ErrRedirected, ErrBlockedAddress}

type probeError struct {
	msg   string
	kinds []error
}

func (e *probeError) Error() string   { return e.msg }
func (e *probeError) Unwrap() []error { return e.kinds }

func newError(msg string, kinds ...error) error { return &probeError{msg: msg, kinds: kinds} }

// wrapError converts a library error into one whose text carries no URL and
// no credential. The wording keeps the substrings mcperr.FromStreamError
// classifies on (it reuses rtspeek's text classifier), and the timeout and
// cancellation paths are normalised because rtspeek's own timeout text
// ("operation timed out") is not recognised by that classifier.
func wrapError(caller, probe context.Context, err error, secrets []string) error {
	switch {
	case caller.Err() != nil:
		return newError("stream probe canceled: "+caller.Err().Error(), caller.Err())
	case errors.Is(err, context.DeadlineExceeded) || probe.Err() != nil ||
		strings.Contains(strings.ToLower(err.Error()), "timed out"):
		return newError("stream probe timed out: context deadline exceeded", context.DeadlineExceeded)
	}
	msg := err.Error()
	if len(msg) > maxErrorBytes {
		msg = msg[:maxErrorBytes]
	}
	for _, s := range secrets {
		msg = strings.ReplaceAll(msg, s, "REDACTED")
	}
	msg = clean2(redact.Scrub(msg))
	var kinds []error
	for _, k := range sentinels {
		if errors.Is(err, k) {
			kinds = append(kinds, k)
		}
	}
	return newError(msg, kinds...)
}

// clean2 is clean with a larger bound, for error text.
func clean2(s string) string {
	s = strings.ToValidUTF8(s, "")
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}

// FakeProber returns a canned result. Exported for use in other packages' tests.
type FakeProber struct {
	Result *Result
	Err    error
}

// Describe returns the canned result or error.
func (f FakeProber) Describe(context.Context, string, time.Duration) (*Result, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return f.Result, nil
}

// codecName is the encoding name from the format's rtpmap ("H264" from
// "H264/90000"). gortsplib's Format.Codec is deprecated and slated for removal,
// so the name is read from the SDP attribute the camera sent instead.
func codecName(f format.Format) string {
	name, _, _ := strings.Cut(f.RTPMap(), "/")
	return name
}
