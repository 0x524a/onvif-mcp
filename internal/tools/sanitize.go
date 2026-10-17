package tools

import (
	"context"
	"math"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/redact"
)

const (
	// maxFieldRunes bounds every string in a tool's data, counted in runes.
	maxFieldRunes = 256
	// maxErrorRunes bounds strings in the error envelope; mcperr has already
	// capped them at 4096 bytes.
	maxErrorRunes = 4096
	// scrubInputBytes bounds how much of a device-supplied string is examined.
	// Only the first maxFieldRunes of the result is ever emitted, so a secret
	// beyond this offset can never reach the output.
	scrubInputBytes = 64 << 10
	maxWalkDepth    = 32
)

// cleanString makes one device-supplied string safe to hand to an agent. The
// order matters: control and format characters are removed first so that a
// zero-width character inside a secret cannot defeat Scrub, then Scrub runs
// over the whole string, and only then is it clipped, so a clip can never leave
// a fragment of a secret behind. maxRunes <= 0 means no clip.
func cleanString(s string, maxRunes int) string {
	if len(s) > scrubInputBytes {
		s = s[:scrubInputBytes]
	}
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r' || r == 0x2028 || r == 0x2029:
			return ' '
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r):
			// Cf covers bidi overrides, zero-width characters, the BOM and
			// the tag characters used to smuggle hidden text.
			return -1
		}
		return r
	}, s)
	s = redact.Scrub(s)
	if maxRunes > 3 && utf8.RuneCountInString(s) > maxRunes {
		s = string([]rune(s)[:maxRunes-3]) + "..."
	}
	return s
}

func finite(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }

// walker rewrites every string it reaches and drops non-finite floats. A
// pointer to a non-finite float becomes nil ("not reported"); a plain float
// has no absent form, so it sets bad and the caller fails the call instead of
// inventing a number.
type walker struct {
	maxRunes int
	bad      bool
}

func (w *walker) walk(v reflect.Value, noclip bool, depth int) {
	if depth > maxWalkDepth {
		return
	}
	limit := w.maxRunes
	if noclip {
		limit = 0
	}
	switch v.Kind() {
	case reflect.String:
		if v.CanSet() {
			v.SetString(cleanString(v.String(), limit))
		}
	case reflect.Float32, reflect.Float64:
		if !finite(v.Float()) {
			w.bad = true
		}
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		if k := v.Elem().Kind(); (k == reflect.Float32 || k == reflect.Float64) && !finite(v.Elem().Float()) {
			if v.CanSet() {
				v.Set(reflect.Zero(v.Type()))
			} else {
				w.bad = true
			}
			return
		}
		w.walk(v.Elem(), noclip, depth+1)
	case reflect.Interface:
		if v.IsNil() || !v.CanSet() {
			return
		}
		cp := reflect.New(v.Elem().Type()).Elem()
		cp.Set(v.Elem())
		w.walk(cp, noclip, depth+1)
		v.Set(cp)
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			if !t.Field(i).IsExported() {
				continue
			}
			w.walk(f, noclip || t.Field(i).Tag.Get("sanitize") == "noclip", depth+1)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			w.walk(v.Index(i), noclip, depth+1)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			cp := reflect.New(v.Type().Elem()).Elem()
			cp.Set(v.MapIndex(k))
			w.walk(cp, noclip, depth+1)
			v.SetMapIndex(k, cp)
		}
	}
}

// finishOut is the single place where tool output is made safe. It rewrites
// out in place and reports whether a non-finite number could not be dropped.
func finishOut[D any](out *mcperr.Out[D]) (bad bool) {
	if out.Data != nil {
		w := walker{maxRunes: maxFieldRunes}
		w.walk(reflect.ValueOf(out.Data).Elem(), false, 0)
		bad = w.bad
	}
	if out.Error != nil {
		w := walker{maxRunes: maxErrorRunes}
		w.walk(reflect.ValueOf(out.Error).Elem(), false, 0)
	}
	return bad
}

// finishText applies the same string rules to a result's text content.
func finishText(res *mcp.CallToolResult) {
	if res == nil {
		return
	}
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			tc.Text = clip(cleanString(tc.Text, 0))
		}
	}
}

// add registers a tool whose handler returns the mcperr envelope, passing
// every result through the one sanitising step: Scrub, control-character
// stripping and length clipping on every string, and removal of non-finite
// numbers.
//
// It is the only place in the module that calls the SDK's AddTool, and only
// GuardedTool calls it, so a tool cannot be registered without declaring a
// risk class (tests enforce both). It is always the generic free function
// mcp.AddTool underneath, never the srv.AddTool method: the method skips input
// validation and turns handler errors into protocol errors (go-sdk v1.7.0
// server.go).
func add[In, Data any](srv *mcp.Server, t *mcp.Tool, h mcp.ToolHandlerFor[In, mcperr.Out[Data]]) {
	mcp.AddTool(srv, t, func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, mcperr.Out[Data], error) {
		res, out, err := h(ctx, req, in)
		if err != nil {
			return res, out, err
		}
		if finishOut(&out) {
			return fail[Data](&mcperr.ToolError{
				Code:    mcperr.CodeDeviceFault,
				Message: "the camera reported a number that is not finite (NaN or infinity)",
				Hint:    "the camera firmware is misbehaving; try another operation or report it to the camera vendor",
			})
		}
		finishText(res)
		return res, out, nil
	})
}
