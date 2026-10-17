package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/testcam"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// connectTo wires an in-memory client to srv. The server connects first.
func connectTo(t *testing.T, srv *mcp.Server) *mcp.ClientSession {
	t.Helper()
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	cs, err := c.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// harnessWith registers the read tools over a registry built from cams.
func harnessWith(t *testing.T, cams map[string]*config.Camera) *mcp.ClientSession {
	t.Helper()
	d := Deps{Reg: registry.New(&config.Config{Cameras: cams}), Log: quietLog()}
	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	RegisterMedia(srv, d)
	RegisterImaging(srv, d)
	return connectTo(t, srv)
}

// harness starts a virtual camera and returns a session addressing it as
// cam-a.
func harness(t *testing.T) (*mcp.ClientSession, *testcam.Cam) {
	t.Helper()
	cam := testcam.Start(t)
	cs := harnessWith(t, map[string]*config.Camera{
		"cam-a": {ID: "cam-a", Endpoint: cam.Endpoint(), Username: cam.Username(), Password: cam.Password()},
	})
	return cs, cam
}

// call invokes a tool and fails the test on a transport error.
func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool %s: %v", name, err)
	}
	return res
}

// wire returns everything an agent sees: structured and text content.
func wire(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	return string(b)
}

// errCode returns data.error.code from a result, or "".
func errCode(t *testing.T, res *mcp.CallToolResult) (code, hint string) {
	t.Helper()
	m, ok := res.StructuredContent.(map[string]any)
	if !ok {
		return "", ""
	}
	e, ok := m["error"].(map[string]any)
	if !ok {
		return "", ""
	}
	code, _ = e["code"].(string)
	hint, _ = e["hint"].(string)
	return code, hint
}

// dataMap returns the data object of a successful result.
func dataMap(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", wire(t, res))
	}
	m, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("no structured content: %s", wire(t, res))
	}
	d, ok := m["data"].(map[string]any)
	if !ok {
		t.Fatalf("no data object: %s", wire(t, res))
	}
	return d
}

const envelope = `<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>%s</s:Body></s:Envelope>`

// fixture is a hand-written SOAP device. It answers GetCapabilities with a
// media and imaging service at its own URL, and any other operation from
// bodies, keyed by the operation name found in the request.
func fixture(t *testing.T, bodies map[string]string) *httptest.Server {
	t.Helper()
	var url string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		req := string(raw)
		w.Header().Set("Content-Type", "application/soap+xml")
		if strings.Contains(req, "GetCapabilities") {
			_, _ = fmt.Fprintf(w, envelope, `<tds:GetCapabilitiesResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:Capabilities>`+
				`<tt:Media xmlns:tt="http://www.onvif.org/ver10/schema"><tt:XAddr>`+url+`/media</tt:XAddr></tt:Media>`+
				`<tt:Imaging xmlns:tt="http://www.onvif.org/ver10/schema"><tt:XAddr>`+url+`/imaging</tt:XAddr></tt:Imaging>`+
				`</tds:Capabilities></tds:GetCapabilitiesResponse>`)
			return
		}
		for op, body := range bodies {
			if strings.Contains(req, op) {
				_, _ = fmt.Fprintf(w, envelope, body)
				return
			}
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, envelope, `<s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code><s:Reason><s:Text xml:lang="en">unexpected operation</s:Text></s:Reason></s:Fault>`)
	}))
	url = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

func fixtureCamera(srv *httptest.Server) *config.Camera {
	return &config.Camera{ID: "fx", Endpoint: srv.URL + "/device_service", Username: "u", Password: "fixture-pw"}
}
