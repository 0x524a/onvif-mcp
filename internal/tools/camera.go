package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/0x524a/onvif-go/discovery"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/redact"
)

const (
	defaultDiscoverSeconds = 3
	maxDiscoverSeconds     = 10

	// wsDiscoveryGroup is the WS-Discovery multicast group and port.
	wsDiscoveryGroup = "239.255.255.250:3702"

	maxCandidates = 64
	maxXAddrs     = 4
	maxScopes     = 16
	maxFieldChars = 256
)

// DescribeData reports device identity and advertised services. The field
// names say "advertised" because ONVIF service lists are claims: a camera may
// list a service it does not implement.
type DescribeData struct {
	Manufacturer         string   `json:"manufacturer,omitempty"`
	Model                string   `json:"model,omitempty"`
	FirmwareVersion      string   `json:"firmware_version,omitempty"`
	SerialNumber         string   `json:"serial_number,omitempty"`
	HardwareID           string   `json:"hardware_id,omitempty"`
	AdvertisedServices   []string `json:"advertised_services"`
	CapabilitiesVerified bool     `json:"capabilities_verified"`
	CapabilitiesNote     string   `json:"capabilities_note"`
}

// Discoverer performs a WS-Discovery probe lasting at most timeout.
type Discoverer func(ctx context.Context, timeout time.Duration) ([]*discovery.Device, error)

// DefaultDiscoverer probes the WS-Discovery multicast group. Setting
// ProbeAddress makes onvif-go send the probe from an ephemeral local port
// instead of binding UDP 3702 (discovery/discovery.go, openProbeConn), so it
// does not collide with another discovery listener on the host. Replies come
// back unicast to that ephemeral port.
//
// onvif-go: discovery.DiscoverWithOptions, discovery/discovery.go.
func DefaultDiscoverer(ctx context.Context, timeout time.Duration) ([]*discovery.Device, error) {
	return discovery.DiscoverWithOptions(ctx, timeout, &discovery.DiscoverOptions{ProbeAddress: wsDiscoveryGroup})
}

// DiscoverIn controls a discovery probe. There is deliberately no credential
// field: discovery cannot authenticate anything.
type DiscoverIn struct {
	TimeoutSeconds int `json:"timeout_seconds,omitempty" jsonschema:"probe duration in seconds; default 3, maximum 10"`
}

// Candidate is a discovered device. It is not addressable: it has no
// credentials and no camera id, so no other tool accepts it.
type Candidate struct {
	EndpointRef   string   `json:"endpoint_ref,omitempty"`
	XAddrs        []string `json:"xaddrs"`
	Scopes        []string `json:"scopes,omitempty"`
	ConfigSnippet string   `json:"config_snippet"`
}

// DiscoverData is the camera.discover result.
type DiscoverData struct {
	Candidates []Candidate `json:"candidates"`
	// Ignored counts announcements dropped for having no usable http(s) address.
	Ignored int    `json:"ignored"`
	Note    string `json:"note"`
}

func scrubField(s string) string {
	return clip(redact.Scrub(strings.TrimSpace(s)))
}

// safeXAddr returns the redacted form of a device-announced address, or false
// if it is not an http(s) URL with a host. Announcements come from any device
// on the network and are treated as hostile.
func safeXAddr(raw string) (string, bool) {
	if len(raw) > 2048 {
		return "", false
	}
	r, err := redact.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	u, err := url.Parse(r.String())
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", false
	}
	// A device service address needs no query or fragment; dropping them also
	// removes the usual carrier of embedded secrets.
	u.RawQuery, u.Fragment, u.RawFragment = "", "", ""
	s := redact.Scrub(u.String())
	if len(s) > maxFieldChars {
		return "", false
	}
	return s, true
}

// snippet builds a config entry fragment for an endpoint, with no credentials. JSON
// encoding keeps a hostile endpoint from injecting fields.
func snippet(endpoint string) string {
	b, _ := json.Marshal(struct {
		Endpoint string `json:"endpoint"`
	}{endpoint})
	return `"<choose-an-id>": ` + string(b)
}

// candidatesFrom filters, redacts, dedupes and sorts raw announcements.
func candidatesFrom(devs []*discovery.Device) ([]Candidate, int) {
	seen := map[string]bool{}
	out := make([]Candidate, 0, len(devs))
	ignored := 0
	for _, dev := range devs {
		if dev == nil {
			continue
		}
		var xs []string
		have := map[string]bool{}
		for _, raw := range dev.XAddrs {
			x, ok := safeXAddr(raw)
			if !ok || have[x] || len(xs) >= maxXAddrs {
				continue
			}
			have[x] = true
			xs = append(xs, x)
		}
		if len(xs) == 0 {
			ignored++
			continue
		}
		sort.Strings(xs)
		key := strings.Join(xs, " ")
		if seen[key] {
			continue
		}
		seen[key] = true
		c := Candidate{EndpointRef: scrubField(dev.EndpointRef), XAddrs: xs, ConfigSnippet: snippet(xs[0])}
		for _, sc := range dev.Scopes {
			if len(c.Scopes) >= maxScopes {
				break
			}
			if s := scrubField(sc); s != "" {
				c.Scopes = append(c.Scopes, s)
			}
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].XAddrs[0] != out[j].XAddrs[0] {
			return out[i].XAddrs[0] < out[j].XAddrs[0]
		}
		return out[i].EndpointRef < out[j].EndpointRef
	})
	if len(out) > maxCandidates {
		out = out[:maxCandidates]
	}
	return out, ignored
}

// RegisterCamera registers camera.describe and camera.discover.
func RegisterCamera(srv *mcp.Server, d Deps) {
	// onvif-go: (*Client).GetDeviceInformation and (*Client).GetServices, device.go.
	mcp.AddTool(srv, &mcp.Tool{
		Name: "camera.describe",
		Description: "Read a camera's identity (manufacturer, model, firmware, serial) and the services it " +
			"advertises in advertised_services. Advertised services are the camera's claims, not verified " +
			"capabilities: an advertised service may still fail when used.",
		Annotations: ReadOnly("Describe camera"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in CameraIn) (*mcp.CallToolResult, mcperr.Out[DescribeData], error) {
		ctx, cancel := d.Scope(ctx)
		defer cancel()
		c, te := d.client(ctx, in.Camera, "GetDeviceInformation")
		if te != nil {
			return fail[DescribeData](te)
		}
		info, err := c.GetDeviceInformation(ctx)
		if err != nil {
			return fail[DescribeData](mcperr.FromError(err, in.Camera, "GetDeviceInformation"))
		}
		out := DescribeData{
			AdvertisedServices:   []string{},
			CapabilitiesVerified: false,
			CapabilitiesNote:     "services are advertised by the camera and not probed; an advertised service may still return a fault",
		}
		if info != nil {
			out.Manufacturer = scrubField(info.Manufacturer)
			out.Model = scrubField(info.Model)
			out.FirmwareVersion = scrubField(info.FirmwareVersion)
			out.SerialNumber = scrubField(info.SerialNumber)
			out.HardwareID = scrubField(info.HardwareID)
		}
		// GetServices is advisory: a camera may refuse it and still work.
		listed := false
		if svcs, serr := c.GetServices(ctx, false); serr == nil {
			listed = true
			seen := map[string]bool{}
			for _, s := range svcs {
				if s == nil || s.Namespace == "" {
					continue
				}
				ns := scrubField(s.Namespace)
				if !seen[ns] {
					seen[ns] = true
					out.AdvertisedServices = append(out.AdvertisedServices, ns)
				}
			}
			sort.Strings(out.AdvertisedServices)
		}
		msg := strings.TrimSpace(fmt.Sprintf("%s %s.", out.Manufacturer, out.Model))
		if out.Manufacturer == "" && out.Model == "" {
			msg = "Identity not reported."
		}
		if listed {
			msg += fmt.Sprintf(" %d advertised service(s), not verified.", len(out.AdvertisedServices))
		} else {
			out.CapabilitiesNote = "the camera did not report a service list; " + out.CapabilitiesNote
			msg += " Service list not reported."
		}
		return text(msg), mcperr.OK(out), nil
	})

	// onvif-go: discovery.DiscoverWithOptions, discovery/discovery.go.
	mcp.AddTool(srv, &mcp.Tool{
		Name: "camera.discover",
		Description: "Probe the local network (WS-Discovery) for ONVIF devices for timeout_seconds (default 3, " +
			"maximum 10). Results are candidates only: they have no camera id and no credentials, are never " +
			"added to the configured cameras, and no other tool accepts them. Each candidate carries a " +
			"config_snippet a human can paste into the config file and complete with credentials. An empty " +
			"candidates list means nothing answered, which is not an error.",
		Annotations: &mcp.ToolAnnotations{
			Title:           "Discover cameras",
			ReadOnlyHint:    true,
			DestructiveHint: boolPtr(false),
			IdempotentHint:  true,
			// Discovery reaches whatever answers on the network.
			OpenWorldHint: boolPtr(true),
		},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in DiscoverIn) (*mcp.CallToolResult, mcperr.Out[DiscoverData], error) {
		if in.TimeoutSeconds < 0 {
			return fail[DiscoverData](&mcperr.ToolError{
				Code: mcperr.CodeInvalidArgument, Operation: "Discover",
				Message: "timeout_seconds must not be negative",
				Hint:    fmt.Sprintf("omit it for the default of %ds, or pass 1 to %d", defaultDiscoverSeconds, maxDiscoverSeconds),
			})
		}
		secs := in.TimeoutSeconds
		if secs == 0 {
			secs = defaultDiscoverSeconds
		}
		if secs > maxDiscoverSeconds {
			secs = maxDiscoverSeconds
		}
		probe := time.Duration(secs) * time.Second
		ctx, cancel := d.Scope(ctx)
		defer cancel()
		// The library bounds itself with a read deadline; this is a backstop.
		ctx, cancelT := context.WithTimeout(ctx, probe+2*time.Second)
		defer cancelT()

		run := d.Discover
		if run == nil {
			run = DefaultDiscoverer
		}
		devs, err := run(ctx, probe)
		if err != nil && len(devs) == 0 {
			return fail[DiscoverData](mcperr.FromError(err, "", "Discover"))
		}
		// A late read error after some answers keeps what was found.
		cands, ignored := candidatesFrom(devs)
		out := DiscoverData{
			Candidates: cands,
			Ignored:    ignored,
			Note: "candidates are unauthenticated and not addressable; a human adds one to the config file " +
				"with credentials and restarts the server to make it usable",
		}
		return text(fmt.Sprintf("Found %d candidate device(s) in %ds. None are usable until added to the config with credentials.",
			len(cands), secs)), mcperr.OK(out), nil
	})
}
