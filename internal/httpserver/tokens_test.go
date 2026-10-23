package httpserver

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0x524a/onvif-mcp/internal/config"
)

func digestOf(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// tok returns a well-formed (64 lowercase hex) token distinct per n.
func tok(n byte) string {
	return strings.Repeat(string([]byte{"0123456789abcdef"[n%16]}), 63) + string([]byte{"0123456789abcdef"[(n/16)%16]})
}

var fixedNow = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func parse(t *testing.T, json string) (*TokenStore, error) {
	t.Helper()
	return ParseTokens([]byte(json), func() time.Time { return fixedNow })
}

func entry(id, token string, extra string) string {
	return `{"id":"` + id + `","sha256":"` + digestOf(token) + `"` + extra + `}`
}

func TestParseDocumentedFormat(t *testing.T) {
	s, err := parse(t, `{"tokens":[`+entry("laptop-agent", tok(1), "")+`,`+
		entry("ops-agent", tok(2), `,"grant":["camera.snapshot","stream.inspect"],"expires":"2027-01-31T00:00:00Z"`)+`]}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.IDs(); len(got) != 2 || got[0] != "laptop-agent" || got[1] != "ops-agent" {
		t.Errorf("ids = %v", got)
	}
	if g := s.Grants("ops-agent"); len(g) != 2 || g[0] != "camera.snapshot" {
		t.Errorf("grants = %v", g)
	}
	if g := s.Grants("laptop-agent"); len(g) != 0 {
		t.Errorf("default token has grants %v", g)
	}
	if g := s.Grants("nobody"); g != nil {
		t.Errorf("unknown id has grants %v", g)
	}
}

func TestParseRejectsBadFiles(t *testing.T) {
	good := entry("a", tok(1), "")
	many := make([]string, 65)
	for i := range many {
		many[i] = entry("t"+strings.Repeat("a", i%5)+string(rune('a'+i%26))+string(rune('a'+i/26)), tok(byte(i+10)), "")
	}
	for name, tc := range map[string]struct{ doc, want string }{
		"unknown field control": {`{"tokens":[` + entry("a", tok(1), `,"control":true`) + `]}`, "control"},
		"unknown top field":     {`{"tokens":[` + good + `],"x":1}`, "x"},
		"zero entries":          {`{"tokens":[]}`, "1 to 64"},
		"65 entries":            {`{"tokens":[` + strings.Join(many, ",") + `]}`, "1 to 64"},
		"bad id upper":          {`{"tokens":[` + entry("Upper", tok(1), "") + `]}`, "entry 0"},
		"bad id empty":          {`{"tokens":[` + entry("", tok(1), "") + `]}`, "entry 0"},
		"bad id long":           {`{"tokens":[` + entry(strings.Repeat("a", 65), tok(1), "") + `]}`, "entry 0"},
		"duplicate id":          {`{"tokens":[` + good + `,` + entry("a", tok(2), "") + `]}`, "entry 1"},
		"duplicate digest":      {`{"tokens":[` + good + `,` + entry("b", tok(1), "") + `]}`, "entry 1"},
		"uppercase hex":         {`{"tokens":[{"id":"a","sha256":"` + strings.ToUpper(digestOf(tok(1))) + `"}]}`, "entry 0"},
		"short hex":             {`{"tokens":[{"id":"a","sha256":"abcd"}]}`, "entry 0"},
		"bad expires":           {`{"tokens":[` + entry("a", tok(1), `,"expires":"tomorrow"`) + `]}`, "entry 0"},
		"grant not opt-in":      {`{"tokens":[` + entry("a", tok(1), `,"grant":["ptz.stop"]`) + `]}`, "entry 0"},
		"grant read default":    {`{"tokens":[` + entry("a", tok(1), `,"grant":["camera.list"]`) + `]}`, "entry 0"},
		"duplicate grants":      {`{"tokens":[` + entry("a", tok(1), `,"grant":["camera.snapshot","camera.snapshot"]`) + `]}`, "entry 0"},
		"not json":              {`tokens`, "token file"},
		"trailing data":         {`{"tokens":[` + good + `]} {}`, "token file"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parse(t, tc.doc)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q lacks %q", err, tc.want)
			}
			for _, d := range []string{digestOf(tok(1)), digestOf(tok(2))} {
				if strings.Contains(err.Error(), d) {
					t.Errorf("error echoes a digest: %v", err)
				}
			}
		})
	}
}

func TestLoadTokensRefusesLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tokens.json")
	doc := `{"tokens":[` + entry("a", tok(1), "") + `]}`
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604} {
		if err := os.WriteFile(p, []byte(doc), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadTokens(p); !errors.Is(err, config.ErrConfigPermissions) {
			t.Errorf("mode %v: %v", mode, err)
		}
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTokens(p); err != nil {
		t.Fatalf("0600: %v", err)
	}
	if _, err := LoadTokens(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("missing file accepted")
	}
	if _, err := LoadTokens(dir); err == nil {
		t.Error("directory accepted")
	}
}

func TestVerify(t *testing.T) {
	s, err := parse(t, `{"tokens":[`+entry("a", tok(1), "")+`,`+
		entry("g", tok(2), `,"grant":["camera.snapshot"]`)+`,`+
		entry("old", tok(3), `,"expires":"2026-10-01T00:00:00Z"`)+`,`+
		entry("fresh", tok(4), `,"expires":"2026-11-01T00:00:00Z"`)+`,`+entry("letters", tok(11), "")+`]}`)
	if err != nil {
		t.Fatal(err)
	}
	if id, g, ok := s.Verify(tok(1)); !ok || id != "a" || len(g) != 0 {
		t.Errorf("a: %v %v %v", id, g, ok)
	}
	if id, g, ok := s.Verify(tok(2)); !ok || id != "g" || len(g) != 1 {
		t.Errorf("g: %v %v %v", id, g, ok)
	}
	if _, _, ok := s.Verify(tok(4)); !ok {
		t.Error("unexpired token refused")
	}
	for name, bad := range map[string]string{
		"wrong":             tok(9),
		"empty":             "",
		"1 MB":              strings.Repeat("a", 1<<20),
		"63 chars":          tok(1)[:63],
		"65 chars":          tok(1) + "0",
		"uppercase":         strings.ToUpper(tok(11)),
		"leading space":     " " + tok(1),
		"trailing space":    tok(1) + " ",
		"trailing newline":  tok(1) + "\n",
		"expired":           tok(3),
		"non-hex of len 64": strings.Repeat("g", 64),
	} {
		if id, g, ok := s.Verify(bad); ok || id != "" || g != nil {
			t.Errorf("%s: accepted (%q)", name, id)
		}
	}
}

// A well-formed token whose digest is absent is rejected after hashing, the same
// way as everything else.
func TestVerifyWellFormedButUnknown(t *testing.T) {
	s, _ := parse(t, `{"tokens":[`+entry("a", tok(1), "")+`]}`)
	if _, _, ok := s.Verify(tok(77)); ok {
		t.Fatal("unknown token accepted")
	}
}

func TestVerifyComparesEveryEntryWithoutEarlyExit(t *testing.T) {
	s, _ := parse(t, `{"tokens":[`+entry("a", tok(1), "")+`,`+entry("b", tok(2), "")+`,`+entry("c", tok(3), "")+`]}`)
	calls := 0
	orig := s.eq
	s.eq = func(a, b []byte) int { calls++; return orig(a, b) }
	for name, token := range map[string]string{"hit at index 0": tok(1), "miss": tok(9), "hit at last": tok(3)} {
		calls = 0
		s.Verify(token)
		if calls != 3 {
			t.Errorf("%s: %d comparisons, want exactly one per entry (3)", name, calls)
		}
	}
	calls = 0
	s.Verify("short") // rejected on format before hashing
	if calls != 0 {
		t.Errorf("malformed token reached the comparison (%d)", calls)
	}
}

func TestNewToken(t *testing.T) {
	token, ent, err := NewToken("ops")
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 64 || strings.Trim(token, "0123456789abcdef") != "" {
		t.Fatalf("token %q is not 64 lowercase hex", token)
	}
	if !strings.Contains(ent, digestOf(token)) || !strings.Contains(ent, `"id": "ops"`) && !strings.Contains(ent, `"id":"ops"`) {
		t.Errorf("entry %q", ent)
	}
	if strings.Contains(ent, token) {
		t.Error("the entry contains the token itself")
	}
	s, err := parse(t, `{"tokens":[`+ent+`]}`)
	if err != nil {
		t.Fatalf("generated entry does not parse: %v", err)
	}
	if id, _, ok := s.Verify(token); !ok || id != "ops" {
		t.Error("generated token not accepted by a store built from its entry")
	}
	other, _, _ := NewToken("ops")
	if other == token {
		t.Error("two tokens are equal")
	}
	if _, _, err := NewToken("Bad Id"); err == nil {
		t.Error("bad id accepted")
	}
}
