package redact

import (
	"strings"
	"testing"
)

func TestScrubNestedKeyValue(t *testing.T) {
	for _, in := range []string{
		"source=password=hunter2xyz",
		"a=b=c=token=hunter2xyz&x=1",
		"u?src=pass=hunter2xyz;k=v",
	} {
		if out := Scrub(in); strings.Contains(out, "hunter2xyz") {
			t.Errorf("Scrub(%q) = %q leaks", in, out)
		}
	}
	if got := Scrub("a=b=c"); got != "a=b=c" {
		t.Errorf("benign nested pair changed: %q", got)
	}
}
