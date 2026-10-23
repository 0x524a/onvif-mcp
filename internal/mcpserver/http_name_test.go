package mcpserver

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestBoundedNameTruncatesLongToolNames(t *testing.T) {
	if got := boundedName("camera.list"); got != "camera.list" {
		t.Errorf("short name changed: %q", got)
	}
	got := boundedName(strings.Repeat("x", 60000))
	if len(got) > maxLoggedToolName+32 {
		t.Errorf("logged name is %d bytes", len(got))
	}
	// A multi-byte rune straddling the cut must not leave invalid UTF-8.
	got = boundedName(strings.Repeat("\u00e9", 100))
	if !utf8.ValidString(got) || len(got) > maxLoggedToolName+32 {
		t.Errorf("bad truncation: %q", got)
	}
}
