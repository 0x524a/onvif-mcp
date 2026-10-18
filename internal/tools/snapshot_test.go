package tools

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // the test camera verifies Digest, which is defined over MD5
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"hash/crc32"
	"html"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/testcam"
)

// ---- fixtures --------------------------------------------------------------

func rgba(w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for x := 0; x < w; x++ {
		for y := 0; y < h; y++ {
			img.Set(x, y, color.RGBA{R: uint8(x * 7), G: uint8(y * 5), B: 80, A: 255})
		}
	}
	return img
}

func jpegImage(t testing.TB, w, h int) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := jpeg.Encode(&b, rgba(w, h), nil); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func pngImage(t testing.TB, w, h int) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, rgba(w, h)); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// jpegWithDims rewrites the SOF0 dimensions of a real JPEG, giving a file whose
// header claims a huge image while the file stays tiny.
func jpegWithDims(t testing.TB, w, h int) []byte {
	t.Helper()
	b := jpegImage(t, 8, 8)
	i := bytes.Index(b, []byte{0xFF, 0xC0})
	if i < 0 {
		t.Fatal("no SOF0 marker")
	}
	binary.BigEndian.PutUint16(b[i+5:], uint16(h)) //nolint:gosec // test dimensions fit
	binary.BigEndian.PutUint16(b[i+7:], uint16(w)) //nolint:gosec // test dimensions fit
	return b
}

// pngWithDims is a PNG signature and a valid IHDR chunk declaring w x h.
func pngWithDims(w, h int) []byte {
	var b bytes.Buffer
	b.Write([]byte("\x89PNG\r\n\x1a\n"))
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], uint32(w)) //nolint:gosec // test dimensions fit
	binary.BigEndian.PutUint32(ihdr[4:], uint32(h)) //nolint:gosec // test dimensions fit
	ihdr[8], ihdr[9] = 8, 6                         // 8-bit RGBA
	_ = binary.Write(&b, binary.BigEndian, uint32(13))
	chunk := append([]byte("IHDR"), ihdr...)
	b.Write(chunk)
	_ = binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE(chunk))
	return b.Bytes()
}

func snapshotBody(uri string) map[string]string {
	return map[string]string{
		"GetSnapshotUri": `<trt:GetSnapshotUriResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl"><trt:MediaUri>` +
			`<tt:Uri xmlns:tt="http://www.onvif.org/ver10/schema">` + html.EscapeString(uri) + `</tt:Uri>` +
			`</trt:MediaUri></trt:GetSnapshotUriResponse>`,
	}
}

// snapServer serves h on 127.0.0.1, the camera's own host.
func snapServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// foreignServer serves h on 127.0.0.2, a host that is not the camera's.
func foreignServer(t *testing.T, h http.HandlerFunc) (addr string, conns *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.2: %v", err)
	}
	conns = new(atomic.Int32)
	srv := &httptest.Server{Listener: &connCounter{Listener: ln, n: conns}, Config: &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}}
	srv.Start()
	t.Cleanup(srv.Close)
	return ln.Addr().String(), conns
}

type connCounter struct {
	net.Listener
	n *atomic.Int32
}

func (c *connCounter) Accept() (net.Conn, error) {
	conn, err := c.Listener.Accept()
	if err == nil {
		c.n.Add(1)
	}
	return conn, err
}

type snapEnv struct {
	cs  *mcp.ClientSession
	log *bytes.Buffer
}

// snapSession serves camera.snapshot over a camera whose ONVIF service is a
// fixture advertising uri as the snapshot address of every profile.
func snapSession(t *testing.T, uri string, cam config.Camera, mod func(*Deps)) snapEnv {
	t.Helper()
	fx := fixture(t, snapshotBody(uri))
	return snapSessionOn(t, fx, cam, mod)
}

func snapSessionOn(t *testing.T, fx *httptest.Server, cam config.Camera, mod func(*Deps)) snapEnv {
	t.Helper()
	cam.ID = "fx"
	cam.Endpoint = fx.URL + "/device_service"
	if cam.Username == "" {
		cam.Username = canaryUser
	}
	if cam.Password == "" {
		cam.Password = canaryPass
	}
	var logBuf bytes.Buffer
	d := Deps{
		Reg: registry.New(&config.Config{Cameras: map[string]*config.Camera{"fx": &cam}}),
		Log: slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if mod != nil {
		mod(&d)
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	RegisterSnapshot(srv, d)
	return snapEnv{cs: connectTo(t, srv), log: &logBuf}
}

func snap(t *testing.T, cs *mcp.ClientSession, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	if _, ok := args["camera"]; !ok {
		args["camera"] = "fx"
	}
	if _, ok := args["profile"]; !ok {
		args["profile"] = "p1"
	}
	return call(t, cs, "camera.snapshot", args)
}

func imageOf(res *mcp.CallToolResult) *mcp.ImageContent {
	for _, c := range res.Content {
		if img, ok := c.(*mcp.ImageContent); ok {
			return img
		}
	}
	return nil
}

func wantFault(t *testing.T, res *mcp.CallToolResult, code, msg string) string {
	t.Helper()
	if !res.IsError {
		t.Fatalf("want %s error, got success: %.300s", code, wire(t, res))
	}
	if imageOf(res) != nil {
		t.Error("an error result carries image content")
	}
	got, hint := errCode(t, res)
	if got != code {
		t.Errorf("code = %q, want %q: %s", got, code, wire(t, res))
	}
	if msg != "" && !strings.Contains(wire(t, res), msg) {
		t.Errorf("result does not say %q: %s", msg, wire(t, res))
	}
	if hint == "" {
		t.Errorf("error has no hint: %s", wire(t, res))
	}
	return hint
}

func settleTools(t *testing.T, base int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > base {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			buf = buf[:runtime.Stack(buf, true)]
			t.Fatalf("goroutines = %d, want <= %d (leak)\n%s", runtime.NumGoroutine(), base, buf)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func stableTools(t *testing.T) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	last, since := runtime.NumGoroutine(), time.Now()
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		if n := runtime.NumGoroutine(); n != last {
			last, since = n, time.Now()
		} else if time.Since(since) >= 250*time.Millisecond {
			return n
		}
	}
	t.Fatalf("goroutine count never stabilised (last %d)", last)
	return 0
}

// ---- the virtual camera ----------------------------------------------------

func camSnapshot(t *testing.T, limit int) (*mcp.ClientSession, *testcam.Cam) {
	t.Helper()
	cam := testcam.Start(t)
	d := Deps{
		Reg: registry.New(&config.Config{Cameras: map[string]*config.Camera{
			"cam-a": {ID: "cam-a", Endpoint: cam.Endpoint(), Username: cam.Username(), Password: cam.Password()},
		}}),
		Log: quietLog(), SnapshotMaxBytes: limit,
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	RegisterSnapshot(srv, d)
	return connectTo(t, srv), cam
}

func TestSnapshotFromTestcamIsAnInlineImage(t *testing.T) {
	cs, cam := camSnapshot(t, 0)
	res := call(t, cs, "camera.snapshot", map[string]any{"camera": "cam-a", "profile": cam.ProfileToken()})
	d := dataMap(t, res)
	img := imageOf(res)
	if img == nil || img.MIMEType != "image/jpeg" {
		t.Fatalf("image content = %+v: %s", img, wire(t, res))
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(img.Data))
	if err != nil || format != "jpeg" {
		t.Fatalf("returned bytes are not a JPEG: %v %s", err, format)
	}
	if d["bytes"] != float64(len(img.Data)) || d["mime_type"] != "image/jpeg" || d["profile"] != cam.ProfileToken() ||
		d["width"] != float64(cfg.Width) || d["height"] != float64(cfg.Height) || d["truncated"] != false {
		t.Errorf("data = %v (image %dx%d, %d bytes)", d, cfg.Width, cfg.Height, len(img.Data))
	}
	want := fmt.Sprintf("JPEG %dx%d, %d bytes from profile %s.", cfg.Width, cfg.Height, len(img.Data), cam.ProfileToken())
	if txt := textOf(res); txt != want {
		t.Errorf("text = %q, want %q", txt, want)
	}
	// The snapshot address is the camera's, and is not output.
	if w := wire(t, res); strings.Contains(w, "snapshot?profile") || strings.Contains(w, cam.Password()) {
		t.Errorf("wire shows the snapshot address or password: %.200s", w)
	}
}

func TestSnapshotOverTheCapIsRefusedWithSizeLimitAndHint(t *testing.T) {
	cs, cam := camSnapshot(t, 1)
	res := call(t, cs, "camera.snapshot", map[string]any{"camera": "cam-a", "profile": cam.ProfileToken()})
	hint := wantFault(t, res, "invalid_argument", "")
	w := wire(t, res)
	if !regexp.MustCompile(`snapshot is \d+ bytes, over the 1 byte limit`).MatchString(w) {
		t.Errorf("message must state the size and the limit: %s", w)
	}
	if !strings.Contains(hint, "media.profiles") || !strings.Contains(hint, "lower-resolution profile") {
		t.Errorf("hint = %q", hint)
	}
}

func TestSnapshotUnknownProfileIsNotFoundWithHint(t *testing.T) {
	cs, _ := camSnapshot(t, 0)
	res := call(t, cs, "camera.snapshot", map[string]any{"camera": "cam-a", "profile": "no-such-profile"})
	hint := wantFault(t, res, "not_found", "")
	if !strings.Contains(hint, "media.profiles") {
		t.Errorf("hint = %q", hint)
	}
}

func TestSnapshotUnknownCameraIsNotFound(t *testing.T) {
	cs, cam := camSnapshot(t, 0)
	res := call(t, cs, "camera.snapshot", map[string]any{"camera": "nope", "profile": cam.ProfileToken()})
	hint := wantFault(t, res, "not_found", "")
	if !strings.Contains(hint, "camera.list") {
		t.Errorf("hint = %q", hint)
	}
}

func TestSnapshotCameraWithoutSnapshotSupportIsNotSupported(t *testing.T) {
	fx := faultFixture(t, "snapshot not supported for profile: p1")
	env := snapSessionOn(t, fx, config.Camera{}, nil)
	res := snap(t, env.cs, nil)
	wantFault(t, res, "not_supported", "")

	// An empty address is the camera's fault, not the caller's.
	env = snapSession(t, "", config.Camera{}, nil)
	wantFault(t, snap(t, env.cs, nil), "device_fault", "no snapshot address")
}

func TestSnapshotToolDeclaration(t *testing.T) {
	cs, _ := camSnapshot(t, 0)
	lt, err := cs.ListTools(t.Context(), nil)
	if err != nil || len(lt.Tools) != 1 {
		t.Fatalf("tools: %v %v", lt, err)
	}
	tool := lt.Tools[0]
	a := tool.Annotations
	if tool.Name != "camera.snapshot" || a == nil || !a.ReadOnlyHint || !a.IdempotentHint ||
		a.DestructiveHint == nil || *a.DestructiveHint || a.OpenWorldHint == nil || *a.OpenWorldHint {
		t.Errorf("annotations = %+v", a)
	}
	for _, want := range []string{"Use this after media.profiles", "1 MiB", "trust_advertised_hosts", "Does not record or stream video", "does not move the camera", "never appear"} {
		if !strings.Contains(tool.Description, want) {
			t.Errorf("description lacks %q", want)
		}
	}
	b := wireOf(t, tool.InputSchema)
	if strings.Contains(b, "password") || strings.Contains(b, "url") || !strings.Contains(b, `"minLength":1`) {
		t.Errorf("input schema = %s", b)
	}
}

func TestSnapshotRejectsSchemaInvalidInputBeforeAnyRequest(t *testing.T) {
	var n atomic.Int32
	srv := snapServer(t, func(w http.ResponseWriter, _ *http.Request) { n.Add(1); _, _ = w.Write(jpegImage(t, 4, 4)) })
	env := snapSession(t, srv.URL+"/s", config.Camera{}, nil)
	for name, args := range map[string]map[string]any{
		"missing profile": {"camera": "fx"},
		"empty profile":   {"camera": "fx", "profile": ""},
		"empty camera":    {"camera": "", "profile": "p1"},
		"extra url":       {"camera": "fx", "profile": "p1", "url": "http://127.0.0.1/x"},
		"extra password":  {"camera": "fx", "profile": "p1", "password": "x"},
		"wrong type":      {"camera": "fx", "profile": 7},
	} {
		res, err := env.cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "camera.snapshot", Arguments: args})
		if err == nil && !res.IsError {
			t.Errorf("%s: accepted", name)
		}
	}
	if n.Load() != 0 {
		t.Errorf("%d snapshot request(s) for invalid input", n.Load())
	}
}

// ---- content ---------------------------------------------------------------

func TestSnapshotReturnsJPEGAndPNGAndIgnoresTheContentType(t *testing.T) {
	cases := map[string]struct {
		body []byte
		ct   string
		mime string
		kind string
	}{
		"jpeg":                   {jpegImage(t, 40, 30), "image/jpeg", "image/jpeg", "JPEG 40x30"},
		"png":                    {pngImage(t, 33, 21), "image/png", "image/png", "PNG 33x21"},
		"jpeg labelled as html":  {jpegImage(t, 16, 16), "text/html", "image/jpeg", "JPEG 16x16"},
		"jpeg with no type":      {jpegImage(t, 16, 12), "", "image/jpeg", "JPEG 16x12"},
		"png labelled as binary": {pngImage(t, 9, 9), "application/octet-stream", "image/png", "PNG 9x9"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			srv := snapServer(t, func(w http.ResponseWriter, _ *http.Request) {
				if c.ct != "" {
					w.Header().Set("Content-Type", c.ct)
				}
				_, _ = w.Write(c.body)
			})
			res := snap(t, snapSession(t, srv.URL+"/s", config.Camera{}, nil).cs, nil)
			dataMap(t, res)
			img := imageOf(res)
			if img == nil || img.MIMEType != c.mime || !bytes.Equal(img.Data, c.body) {
				t.Fatalf("image = %v", img)
			}
			if txt := textOf(res); !strings.HasPrefix(txt, c.kind+", ") {
				t.Errorf("text = %q, want prefix %q", txt, c.kind)
			}
		})
	}
}

// Image bytes are binary and must come back exactly: they are not text, so the
// sanitiser's scrubbing must not touch them, even when they contain text that
// looks like a secret.
func TestSnapshotImageBytesAreNotScrubbed(t *testing.T) {
	jpg := jpegImage(t, 12, 12)
	com := []byte("password=hunter2 token=abcdef0123 api_key=zzzz")
	seg := append([]byte{0xFF, 0xFE, 0, byte(len(com) + 2)}, com...) //nolint:gosec // 49 fits a byte
	withComment := append(append(append([]byte{}, jpg[:2]...), seg...), jpg[2:]...)
	if _, _, err := image.DecodeConfig(bytes.NewReader(withComment)); err != nil {
		t.Fatal(err)
	}
	srv := snapServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(withComment) })
	res := snap(t, snapSession(t, srv.URL+"/s", config.Camera{}, nil).cs, nil)
	dataMap(t, res)
	if img := imageOf(res); img == nil || !bytes.Equal(img.Data, withComment) {
		t.Error("image bytes were altered")
	}
}

func TestSnapshotRefusesWhatIsNotAJPEGOrPNG(t *testing.T) {
	const marker = "LOGIN-PAGE-MARKER-9f3a"
	gifB := func() []byte {
		var b bytes.Buffer
		_ = gif.Encode(&b, rgba(8, 8), nil)
		return b.Bytes()
	}()
	bodies := map[string]struct {
		ct   string
		body []byte
	}{
		"html login page as image": {"image/jpeg", []byte("<html><body>" + marker + " please sign in</body></html>")},
		"html":                     {"text/html", []byte("<!DOCTYPE html><html>" + marker + "</html>")},
		"svg":                      {"image/svg+xml", []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>` + marker + `</script></svg>`)},
		"plain text":               {"text/plain", []byte(marker + " error 17")},
		"json":                     {"application/json", []byte(`{"error":"` + marker + `"}`)},
		"random octets":            {"application/octet-stream", bytes.Repeat([]byte{0x00, 0x13, 0x37, 0xC0}, 64)},
		"empty":                    {"image/jpeg", nil},
		"gif":                      {"image/gif", gifB},
		"jpeg magic, junk after":   {"image/jpeg", append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, []byte(marker)...)},
		"png magic, junk after":    {"image/png", append([]byte("\x89PNG\r\n\x1a\n"), []byte(marker)...)},
		"gzip":                     {"image/jpeg", []byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3}},
	}
	for name, c := range bodies {
		t.Run(name, func(t *testing.T) {
			srv := snapServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", c.ct)
				_, _ = w.Write(c.body)
			})
			res := snap(t, snapSession(t, srv.URL+"/s", config.Camera{}, nil).cs, nil)
			wantFault(t, res, "device_fault", "")
			if w := wire(t, res); strings.Contains(w, marker) || strings.Contains(w, "html") && strings.Contains(w, "<") {
				t.Errorf("the reply is echoed: %s", w)
			}
		})
	}
	// The plain refusal has a fixed, recognisable message.
	srv := snapServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) })
	res := snap(t, snapSession(t, srv.URL+"/s", config.Camera{}, nil).cs, nil)
	wantFault(t, res, "device_fault", "the snapshot address did not return an image")
}

func TestSnapshotRefusesImageBombHeaders(t *testing.T) {
	for name, body := range map[string][]byte{
		"jpeg 65535x65535":   jpegWithDims(t, 65535, 65535),
		"jpeg 16385x1":       jpegWithDims(t, 16385, 1),
		"jpeg 1x16385":       jpegWithDims(t, 1, 16385),
		"jpeg 9000x8000":     jpegWithDims(t, 9000, 8000), // 72 MP
		"png 65535x65535":    pngWithDims(65535, 65535),
		"png 100000x1":       pngWithDims(100000, 1),
		"png 10000x10000":    pngWithDims(10000, 10000),
		"png zero by zero":   pngWithDims(0, 0),
		"jpeg zero by zero":  jpegWithDims(t, 0, 0),
		"png 4294967295x1":   pngWithDims(1<<32-1, 1),
		"jpeg cut after SOI": {0xFF, 0xD8, 0xFF},
	} {
		t.Run(name, func(t *testing.T) {
			srv := snapServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
			res := snap(t, snapSession(t, srv.URL+"/s", config.Camera{}, nil).cs, nil)
			wantFault(t, res, "device_fault", "")
		})
	}
	// Just inside the limits is fine.
	srv := snapServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jpegWithDims(t, 8000, 8000)) }) // 64 MP
	res := snap(t, snapSession(t, srv.URL+"/s", config.Camera{}, nil).cs, nil)
	d := dataMap(t, res)
	if d["width"] != float64(8000) {
		t.Errorf("data = %v", d)
	}
}

// ---- size ------------------------------------------------------------------

func TestSnapshotCapBoundary(t *testing.T) {
	img := jpegImage(t, 64, 64)
	srv := snapServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(img) })
	at := func(limit int) *mcp.CallToolResult {
		return snap(t, snapSession(t, srv.URL+"/s", config.Camera{}, func(d *Deps) { d.SnapshotMaxBytes = limit }).cs, nil)
	}
	dataMap(t, at(len(img)))
	wantFault(t, at(len(img)-1), "invalid_argument", fmt.Sprintf("snapshot is %d bytes, over the %d byte limit", len(img), len(img)-1))
	// The default cap applies when none is set.
	if d := dataMap(t, at(0)); d["bytes"] != float64(len(img)) {
		t.Errorf("data = %v", d)
	}
}

func TestSnapshotNeverBuffersAnEndlessBody(t *testing.T) {
	const total = 50 << 20
	var written atomic.Int64
	done := make(chan struct{})
	srv := snapServer(t, func(w http.ResponseWriter, _ *http.Request) {
		defer close(done)
		chunk := bytes.Repeat([]byte{0xFF, 0xD8, 0xFF, 0}, 16<<10)
		for written.Load() < total {
			n, err := w.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	})
	env := snapSession(t, srv.URL+"/s", config.Camera{}, func(d *Deps) { d.SnapshotMaxBytes = MinSnapshotMaxBytes })
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	res := snap(t, env.cs, nil)
	runtime.ReadMemStats(&after)
	wantFault(t, res, "invalid_argument", fmt.Sprintf("more than %d bytes, over the %d byte limit", MinSnapshotMaxBytes, MinSnapshotMaxBytes))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the server was never cut off")
	}
	if w := written.Load(); w > 16<<20 {
		t.Errorf("server wrote %d of %d bytes: the client kept reading", w, total)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 24<<20 {
		t.Errorf("process allocated %d bytes for a 1 KiB cap", grew)
	}
}

func TestSnapshotDeclaredHugeLengthIsRefusedWithItsSize(t *testing.T) {
	srv := snapServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "2147483648")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		time.Sleep(200 * time.Millisecond)
	})
	res := snap(t, snapSession(t, srv.URL+"/s", config.Camera{}, nil).cs, nil)
	wantFault(t, res, "invalid_argument", "snapshot is 2147483648 bytes, over the 1048576 byte limit")
}

func TestCheckSnapshotMaxBytes(t *testing.T) {
	for n, ok := range map[int]bool{
		MinSnapshotMaxBytes - 1: false, MinSnapshotMaxBytes: true, DefaultSnapshotMaxBytes: true,
		MaxSnapshotMaxBytes: true, MaxSnapshotMaxBytes + 1: false, 0: false, -5: false,
	} {
		if err := CheckSnapshotMaxBytes(n); (err == nil) != ok {
			t.Errorf("%d: err = %v", n, err)
		}
	}
}

// ---- credentials -----------------------------------------------------------

func TestSnapshotBasicAuthWithSpecialCharPassword(t *testing.T) {
	img := jpegImage(t, 10, 10)
	var seen atomic.Int32
	srv := snapServer(t, func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		if u, p, ok := r.BasicAuth(); !ok || u != canaryUser || p != canaryPass {
			w.Header().Set("WWW-Authenticate", `Basic realm="cam"`)
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write(img)
	})
	env := snapSession(t, srv.URL+"/s", config.Camera{}, nil)
	res := snap(t, env.cs, nil)
	dataMap(t, res)
	if seen.Load() != 2 {
		t.Errorf("requests = %d, want a challenge and one authenticated retry", seen.Load())
	}
	assertNoLeak(t, "text", textOf(res))
	assertNoLeak(t, "log", env.log.String())
}

func TestSnapshotDigestAuthWithSpecialCharPassword(t *testing.T) {
	const realm, nonce = "cam", "5ccc069c403ebaf9f0171e9517f40e41"
	img := jpegImage(t, 10, 10)
	kvRe := regexp.MustCompile(`(\w+)=(?:"([^"]*)"|([^,\s]+))`)
	srv := snapServer(t, func(w http.ResponseWriter, r *http.Request) {
		kv := map[string]string{}
		for _, m := range kvRe.FindAllStringSubmatch(r.Header.Get("Authorization"), -1) {
			kv[m[1]] = m[2] + m[3]
		}
		md := func(s string) string { x := md5.Sum([]byte(s)); return hex.EncodeToString(x[:]) } //nolint:gosec // see import
		ha1 := md(canaryUser + ":" + realm + ":" + canaryPass)
		want := md(ha1 + ":" + nonce + ":" + kv["nc"] + ":" + kv["cnonce"] + ":auth:" + md("GET:"+r.URL.RequestURI()))
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Digest ") || kv["response"] != want {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Digest realm=%q, nonce=%q, qop="auth", algorithm=MD5`, realm, nonce))
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write(img)
	})
	dataMap(t, snap(t, snapSession(t, srv.URL+"/s?profile=p1&x=1", config.Camera{}, nil).cs, nil))
}

func TestSnapshotRejectedCredentialsAreAuthFailed(t *testing.T) {
	for name, status := range map[string]int{"401 after credentials": 401, "403": 403} {
		t.Run(name, func(t *testing.T) {
			var n atomic.Int32
			srv := snapServer(t, func(w http.ResponseWriter, _ *http.Request) {
				n.Add(1)
				if status == 401 {
					w.Header().Set("WWW-Authenticate", `Basic realm="cam"`)
				}
				http.Error(w, "nope "+canaryPass, status)
			})
			env := snapSession(t, srv.URL+"/s", config.Camera{}, nil)
			res := snap(t, env.cs, nil)
			hint := wantFault(t, res, "auth_failed", "")
			if !strings.Contains(hint, "password") && !strings.Contains(hint, "permission") {
				t.Errorf("hint = %q", hint)
			}
			assertNoLeak(t, "wire", wire(t, res))
			if status == 401 && n.Load() != 2 {
				t.Errorf("requests = %d, want exactly 2", n.Load())
			}
		})
	}
}

// Every channel the server writes, with a camera that reflects the request
// (including the Authorization header) in its reply bodies.
func TestSnapshotNeverLeaksCredentialsInAnyChannel(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte(canaryUser + ":" + canaryPass))
	reflect := func(status int, withChallenge bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if withChallenge && r.Header.Get("Authorization") == "" {
				w.Header().Set("WWW-Authenticate", `Basic realm="cam"`)
				w.WriteHeader(401)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(status)
			_, _ = fmt.Fprintf(w, "<html>Authorization: %s password=%s %s</html>", r.Header.Get("Authorization"), canaryPass, b64) //nolint:gosec // test camera reflecting the request on purpose
		}
	}
	for name, h := range map[string]http.HandlerFunc{
		"200 html reflecting the request": reflect(200, true),
		"500 html reflecting the request": reflect(500, true),
		"401 reflecting":                  reflect(401, true),
		"unauthenticated 502 reflecting":  reflect(502, false),
		"redirect with the password in Location": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "http://127.0.0.2:9/x?password="+canaryPass+"&auth="+b64)
			w.WriteHeader(302)
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv := snapServer(t, h)
			env := snapSession(t, srv.URL+"/s?token=QS-SECRET-77", config.Camera{}, nil)
			var res *mcp.CallToolResult
			std := captureStd(t, func() { res = snap(t, env.cs, nil) })
			if !res.IsError {
				t.Fatalf("expected an error: %.200s", wire(t, res))
			}
			for ch, s := range map[string]string{"wire": wire(t, res), "log": env.log.String(), "std": std} {
				assertNoLeak(t, ch, s)
				for _, bad := range []string{b64, "QS-SECRET-77", "127.0.0.2", "<html>"} {
					if strings.Contains(s, bad) {
						t.Errorf("%s contains %q: %s", ch, bad, s)
					}
				}
			}
		})
	}
}

// A profile token is the caller's input and is echoed in the summary text and
// the data; it passes through the same scrubbing as any other string.
func TestSnapshotEchoedProfileIsScrubbed(t *testing.T) {
	srv := snapServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jpegImage(t, 8, 8)) })
	env := snapSession(t, srv.URL+"/s", config.Camera{}, nil)
	res := snap(t, env.cs, map[string]any{"profile": "p1 password=hunter2xyz" + strings.Repeat("a", 400)})
	d := dataMap(t, res)
	w := wire(t, res)
	if strings.Contains(w, "hunter2xyz") {
		t.Errorf("secret echoed: %.300s", w)
	}
	if p, _ := d["profile"].(string); len([]rune(p)) > maxFieldRunes {
		t.Errorf("profile not clipped: %d runes", len([]rune(p)))
	}
	if imageOf(res) == nil {
		t.Error("no image")
	}
}

// ---- the snapshot address comes from the camera ----------------------------

func TestSnapshotForeignHostIsRefusedWithoutAnyRequest(t *testing.T) {
	faddr, conns := foreignServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jpegImage(t, 4, 4)) })
	for _, uri := range []string{
		"http://" + faddr + "/snap", "http://u:p@" + faddr + "/snap", "http://127.0.0.1@" + faddr + "/snap",
		"http://localhost.evil.example:" + faddr[strings.LastIndexByte(faddr, ':')+1:] + "/snap",
	} {
		env := snapSession(t, uri, config.Camera{}, nil)
		res := snap(t, env.cs, nil)
		hint := wantFault(t, res, "device_fault", "camera advertised a snapshot address on another host")
		if !strings.Contains(hint, "trust_advertised_hosts") {
			t.Errorf("hint does not name the opt-out: %q", hint)
		}
		if w := wire(t, res); strings.Contains(w, "127.0.0.2") || strings.Contains(w, "evil") || strings.Contains(w, "u:p") {
			t.Errorf("the address is echoed: %s", w)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if conns.Load() != 0 {
		t.Errorf("foreign host saw %d connection(s)", conns.Load())
	}
}

func TestSnapshotTrustedForeignHostIsFetchedWithoutCredentials(t *testing.T) {
	var auths atomic.Int32
	faddr, _ := foreignServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			auths.Add(1)
		}
		if r.URL.Path == "/needs-auth" {
			w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write(jpegImage(t, 20, 10))
	})
	cam := config.Camera{TrustAdvertisedHosts: true}
	res := snap(t, snapSession(t, "http://"+faddr+"/snap", cam, nil).cs, nil)
	if d := dataMap(t, res); d["width"] != float64(20) {
		t.Errorf("data = %v", d)
	}
	res = snap(t, snapSession(t, "http://"+faddr+"/needs-auth", cam, nil).cs, nil)
	hint := wantFault(t, res, "auth_failed", "")
	if !strings.Contains(hint, "never sends the camera's credentials to another host") {
		t.Errorf("hint = %q", hint)
	}
	if auths.Load() != 0 {
		t.Fatalf("%d request(s) with credentials reached the foreign host", auths.Load())
	}
}

func TestSnapshotRedirectToAForeignHostIsNeverFollowed(t *testing.T) {
	var fauth atomic.Int32
	faddr, fconns := foreignServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			fauth.Add(1)
		}
		_, _ = w.Write(jpegImage(t, 4, 4))
	})
	for _, trust := range []bool{false, true} {
		srv := snapServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "" {
				w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
				w.WriteHeader(401)
				return
			}
			http.Redirect(w, r, "http://"+faddr+"/steal", http.StatusFound)
		})
		res := snap(t, snapSession(t, srv.URL+"/s", config.Camera{TrustAdvertisedHosts: trust}, nil).cs, nil)
		hint := wantFault(t, res, "device_fault", "redirect")
		if !strings.Contains(hint, "never follows") {
			t.Errorf("hint = %q", hint)
		}
	}
	if fconns.Load() != 0 || fauth.Load() != 0 {
		t.Fatalf("redirect target saw %d connection(s), %d with credentials", fconns.Load(), fauth.Load())
	}
}

func TestSnapshotUnusableAddressesSendNothing(t *testing.T) {
	var n atomic.Int32
	srv := snapServer(t, func(_ http.ResponseWriter, _ *http.Request) { n.Add(1) })
	for _, uri := range []string{
		"file:///etc/passwd", "ftp://127.0.0.1/x", "rtsp://127.0.0.1/x", "gopher://127.0.0.1/", "//127.0.0.1/x", "/relative",
		"http://127.0.0.1:99999/x", "javascript:alert(1)", srv.URL + "/" + strings.Repeat("a", 3000),
	} {
		res := snap(t, snapSession(t, uri, config.Camera{TrustAdvertisedHosts: true}, nil).cs, nil)
		wantFault(t, res, "device_fault", "not a usable http or https URL")
	}
	for _, uri := range []string{"http://169.254.169.254/latest/meta-data", "http://[fe80::1]/x", "http://0.0.0.0/x", "http://224.0.0.1/x"} {
		res := snap(t, snapSession(t, uri, config.Camera{TrustAdvertisedHosts: true}, nil).cs, nil)
		wantFault(t, res, "device_fault", "never contacts")
	}
	if n.Load() != 0 {
		t.Errorf("%d request(s) were sent", n.Load())
	}
}

// ---- HTTP statuses and time ------------------------------------------------

func TestSnapshotStatusesAreClassifiedFromTheStatusNotTheBody(t *testing.T) {
	for status, want := range map[int]string{
		404: "device_fault", 410: "device_fault", 500: "device_fault", 501: "not_supported",
		502: "unreachable", 503: "unreachable", 504: "timeout", 408: "timeout", 429: "device_fault",
	} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			srv := snapServer(t, func(w http.ResponseWriter, _ *http.Request) {
				// Body text that would steer a text classifier.
				http.Error(w, "401 unauthorized: not found: no such profile", status)
			})
			res := snap(t, snapSession(t, srv.URL+"/s", config.Camera{}, nil).cs, nil)
			wantFault(t, res, want, "")
			if code, _ := errCode(t, res); (code == "unreachable" || code == "timeout") != retryable(t, res) {
				t.Errorf("retryable does not match code %s", code)
			}
		})
	}
}

func retryable(t *testing.T, res *mcp.CallToolResult) bool {
	t.Helper()
	m := res.StructuredContent.(map[string]any)["error"].(map[string]any)
	r, _ := m["retryable"].(bool)
	return r
}

func TestSnapshotHungServerTimesOutAndLeaksNothing(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	unstick := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unstick)
	hung := snapServer(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	slowBody := snapServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100000")
		_, _ = w.Write(jpegImage(t, 4, 4)[:20])
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
	})
	envs := map[string]snapEnv{
		"no headers":   snapSession(t, hung.URL+"/s", config.Camera{TimeoutSeconds: 1}, nil),
		"stalled body": snapSession(t, slowBody.URL+"/s", config.Camera{TimeoutSeconds: 1}, nil),
	}
	base := stableTools(t) // after the sessions exist: only the fetches are measured
	for name, env := range envs {
		start := time.Now()
		res := snap(t, env.cs, nil)
		wantFault(t, res, "timeout", "")
		if !retryable(t, res) {
			t.Errorf("%s: a timeout must be retryable", name)
		}
		if d := time.Since(start); d > 4*time.Second {
			t.Errorf("%s: took %v for a 1s timeout", name, d)
		}
	}
	unstick()
	settleTools(t, base)
}

func TestSnapshotStopsWhenTheServerShutsDown(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	hung := snapServer(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := snapSession(t, hung.URL+"/s", config.Camera{TimeoutSeconds: 30}, func(d *Deps) { d.Base = ctx })
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	start := time.Now()
	res := snap(t, env.cs, nil)
	if !res.IsError {
		t.Fatalf("expected an error: %.200s", wire(t, res))
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("shutdown took %v to stop the fetch", d)
	}
}

func TestSnapshotConcurrentCallsAreIndependent(t *testing.T) {
	jpgs := [][]byte{jpegImage(t, 16, 16), jpegImage(t, 24, 12), pngImage(t, 10, 10)}
	var n atomic.Int32
	srv := snapServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(jpgs[int(r.URL.Query().Get("i")[0]-'0')])
		n.Add(1)
	})
	// One session per profile index: the fixture's address is fixed per camera.
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for i := 0; i < 3; i++ {
		env := snapSession(t, fmt.Sprintf("%s/s?i=%d", srv.URL, i), config.Camera{}, nil)
		for j := 0; j < 8; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := env.cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "camera.snapshot", Arguments: map[string]any{"camera": "fx", "profile": "p1"}})
				img := (*mcp.ImageContent)(nil)
				if err == nil {
					img = imageOf(res)
				}
				if err != nil || res.IsError || img == nil || !bytes.Equal(img.Data, jpgs[i]) {
					errs <- fmt.Sprintf("session %d: err=%v", i, err)
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if n.Load() != 24 {
		t.Errorf("requests = %d, want 24", n.Load())
	}
}

// Only camera.snapshot may start a snapshot fetch, so no other tool can make
// the server issue a request to a camera-chosen address.
func TestOnlySnapshotToolCallsFetchSnapshot(t *testing.T) {
	root := filepath.Join("..", "..")
	allowed := map[string]bool{
		filepath.Join(root, "internal", "tools", "snapshot.go"):    true,
		filepath.Join(root, "internal", "registry", "snapshot.go"): true,
	}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if de.IsDir() {
			switch de.Name() {
			case ".git", "vendor", "docs":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || allowed[path] {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "FetchSnapshot" {
				t.Errorf("%s: FetchSnapshot used outside camera.snapshot", fset.Position(id.Pos()))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
