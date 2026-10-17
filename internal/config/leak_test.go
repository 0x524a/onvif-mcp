package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// TestNoPasswordLeaksThroughAnyFormatter exercises every ordinary way a
// Camera or Config reaches output: fmt verbs over values, pointers and maps of
// both, encoding/json, and both slog handlers.
func TestNoPasswordLeaksThroughAnyFormatter(t *testing.T) {
	const pw = "leakprobe-Zq81" //nolint:gosec // test fixture
	cam := Camera{ID: "c", Endpoint: "h", Username: "u", Password: pw}
	cfg := Config{Cameras: map[string]*Camera{"c": &cam}}
	subjects := map[string]any{
		"Camera":             cam,
		"*Camera":            &cam,
		"map[string]Camera":  map[string]Camera{"c": cam},
		"map[string]*Camera": map[string]*Camera{"c": &cam},
		"[]Camera":           []Camera{cam},
		"Config":             cfg,
		"*Config":            &cfg,
	}
	for name, v := range subjects {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
			if out := fmt.Sprintf(verb, v); strings.Contains(out, pw) { //nolint:revive
				t.Errorf("%s %s leaked: %s", verb, name, out)
			}
		}
		if b, err := json.Marshal(v); err != nil || bytes.Contains(b, []byte(pw)) {
			t.Errorf("json %s leaked or failed: %v %s", name, err, b)
		}
		for hname, mk := range map[string]func(*bytes.Buffer) slog.Handler{
			"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
			"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
		} {
			var buf bytes.Buffer
			slog.New(mk(&buf)).Info("x", slog.Any("v", v), "raw", v)
			if strings.Contains(buf.String(), pw) {
				t.Errorf("slog %s %s leaked: %s", hname, name, buf.String())
			}
		}
	}
}
