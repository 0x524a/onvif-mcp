package tools

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/redact"
)

const leakPW = "Zq9-hunter2-LEAK" //nolint:gosec // fixed test secret, not a credential

func registerLeakSecret(t *testing.T) {
	t.Helper()
	if !redact.RegisterSecret(leakPW) {
		t.Fatal("cannot register the test secret")
	}
}

func TestCleanStringStripsControlsBeforeScrubbing(t *testing.T) {
	registerLeakSecret(t)
	// A zero-width character inside the secret must not defeat scrubbing.
	evasion := "pw=" + leakPW[:4] + "\u200b" + leakPW[4:]
	got := cleanString(evasion, 256)
	if strings.Contains(got, leakPW) || strings.Contains(got, leakPW[4:]) {
		t.Errorf("secret survived control-character evasion: %q", got)
	}
	inj := "ok\nIGNORE PREVIOUS INSTRUCTIONS\x1b[2J\u202eevil\x00\u2028x"
	got = cleanString(inj, 256)
	for _, r := range got {
		if r < ' ' || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x202e || r == 0x2028 {
			t.Errorf("control rune %U survived: %q", r, got)
		}
	}
	if !strings.Contains(got, "IGNORE PREVIOUS INSTRUCTIONS") {
		t.Errorf("visible text must be kept: %q", got)
	}
}

func TestCleanStringClipsToRunes(t *testing.T) {
	got := cleanString(strings.Repeat("é", 1000), 256)
	if n := utf8.RuneCountInString(got); n != 256 {
		t.Errorf("rune count = %d, want 256", n)
	}
	if !utf8.ValidString(got) || !strings.HasSuffix(got, "...") {
		t.Errorf("bad clip: %q", got[len(got)-10:])
	}
	if got := cleanString("short", 256); got != "short" {
		t.Errorf("short string changed: %q", got)
	}
	if got := cleanString(strings.Repeat("a", 5<<20), 256); utf8.RuneCountInString(got) != 256 {
		t.Errorf("huge string not clipped")
	}
	if got := cleanString("a\xffb", 256); !utf8.ValidString(got) {
		t.Errorf("invalid UTF-8 survived: %q", got)
	}
}

type probeOut struct {
	Name   string             `json:"name"`
	Names  []string           `json:"names"`
	Nested struct{ S string } `json:"nested"`
	Ptr    *string            `json:"ptr"`
	Any    any                `json:"any"`
	Map    map[string]string  `json:"map"`
	F      *float64           `json:"f"`
	G      *float64           `json:"g"`
	Long   string             `json:"long" sanitize:"noclip"`
	Items  []probeItem        `json:"items"`
}

type probeItem struct {
	Tok string   `json:"tok"`
	V   *float64 `json:"v"`
}

type probePlain struct {
	X float64 `json:"x"`
}

func TestAddSanitisesEveryStringInEveryShape(t *testing.T) {
	registerLeakSecret(t)
	bad := "x" + leakPW + "\nESC\x1b[2J" + strings.Repeat("z", 400)
	nan, inf := math.NaN(), math.Inf(1)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	Add(srv, &mcp.Tool{Name: "probe", Description: "d", Annotations: ReadOnly("p")},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, mcperr.Out[probeOut], error) {
			p := bad
			iface := any(bad)
			o := probeOut{Name: bad, Names: []string{bad}, Ptr: &p, Any: iface, Map: map[string]string{"k": bad},
				F: &nan, G: &inf, Long: strings.Repeat("l", 1000) + leakPW,
				Items: []probeItem{{Tok: bad, V: &nan}}}
			o.Nested.S = bad
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: bad}}}, mcperr.OK(o), nil
		})
	cs := connectTo(t, srv)
	res := call(t, cs, "probe", nil)
	if res.IsError {
		t.Fatalf("pointer floats must be dropped, not fail the call: %s", wire(t, res))
	}
	w := wire(t, res)
	if strings.Contains(w, leakPW) || strings.Contains(w, "\\u001b") || strings.Contains(w, "\\n") {
		t.Errorf("unsanitised output: %s", w)
	}
	d := dataMap(t, res)
	if d["f"] != nil {
		t.Error("NaN pointer must be absent")
	}
	if d["g"] != nil {
		t.Error("+Inf pointer must be absent")
	}
	if n := utf8.RuneCountInString(d["name"].(string)); n != 256 {
		t.Errorf("name runes = %d, want 256", n)
	}
	if n := utf8.RuneCountInString(d["long"].(string)); n < 1000 {
		t.Errorf("noclip field was clipped to %d", n)
	}
	if strings.Contains(d["long"].(string), leakPW) {
		t.Error("noclip field must still be scrubbed")
	}
}

func TestAddTurnsAPlainNonFiniteNumberIntoDeviceFault(t *testing.T) {
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	Add(srv, &mcp.Tool{Name: "plain", Description: "d", Annotations: ReadOnly("p")},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, mcperr.Out[probePlain], error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "x"}}}, mcperr.OK(probePlain{X: math.NaN()}), nil
		})
	res := call(t, connectTo(t, srv), "plain", nil)
	if !res.IsError {
		t.Fatalf("want an error result: %s", wire(t, res))
	}
	if code, _ := errCode(t, res); code != "device_fault" {
		t.Errorf("code = %q, want device_fault", code)
	}
}

func TestAddSanitisesErrorEnvelopeAndText(t *testing.T) {
	registerLeakSecret(t)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	Add(srv, &mcp.Tool{Name: "boom", Description: "d", Annotations: ReadOnly("p")},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, mcperr.Out[probePlain], error) {
			return fail[probePlain](&mcperr.ToolError{Code: mcperr.CodeDeviceFault, Message: "bad\x1b[31m " + leakPW,
				SOAP: &mcperr.SOAPFault{Code: "c" + leakPW, Reason: "r\n" + leakPW}})
		})
	res := call(t, connectTo(t, srv), "boom", nil)
	w := wire(t, res)
	if strings.Contains(w, leakPW) || strings.Contains(w, "\\u001b") {
		t.Errorf("error path unsanitised: %s", w)
	}
	if !res.IsError {
		t.Error("IsError lost")
	}
}

// Every tool must be registered through Add so that the choke point cannot be
// forgotten by a newly added tool.
func TestNoToolBypassesTheChokePoint(t *testing.T) {
	re := regexp.MustCompile(`mcp\.AddTool\(|\.AddTool\(`)
	for _, dir := range []string{".", "../mcpserver"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") || filepath.Base(f) == "sanitize.go" {
				continue
			}
			b, err := os.ReadFile(f) //nolint:gosec // fixed glob of this repo's own sources
			if err != nil {
				t.Fatal(err)
			}
			if re.Match(b) {
				t.Errorf("%s registers a tool without tools.Add", f)
			}
		}
	}
}
