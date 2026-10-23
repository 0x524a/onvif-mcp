package safety

import (
	"context"
	"strings"
	"testing"
)

// opCtx is a context carrying the stdio operator, for tests that exercise the
// guard's later gates.
func opCtx() context.Context {
	return WithCaller(context.Background(), StdioOperator())
}

func TestZeroCallerIsInvalidAndWithoutControl(t *testing.T) {
	var c Caller
	if c.Valid() || c.Control() || c.ID() != "" || c.Transport() != "" {
		t.Fatalf("zero Caller must be invalid and powerless: %+v", c)
	}
	if _, ok := CallerFrom(WithCaller(context.Background(), c)); ok {
		t.Fatal("CallerFrom must refuse a stored invalid Caller")
	}
}

func TestCallerFromBareContextIsFalse(t *testing.T) {
	if _, ok := CallerFrom(context.Background()); ok {
		t.Fatal("bare context must carry no caller")
	}
	//nolint:staticcheck // deliberately nil: must not panic
	if _, ok := CallerFrom(nil); ok {
		t.Fatal("nil context must carry no caller")
	}
}

func TestStdioOperatorIsValidWithControl(t *testing.T) {
	c := StdioOperator()
	if !c.Valid() || !c.Control() || c.Transport() != "stdio" || c.ID() != "stdio" {
		t.Fatalf("StdioOperator = %+v", c)
	}
	got, ok := CallerFrom(opCtx())
	if !ok || got != c {
		t.Fatalf("round trip: %+v %v", got, ok)
	}
}

func TestRemoteCallerNeverHasControl(t *testing.T) {
	c, err := RemoteCaller("laptop-agent", "http")
	if err != nil || !c.Valid() || c.Control() || c.ID() != "laptop-agent" || c.Transport() != "http" {
		t.Fatalf("RemoteCaller = %+v, %v", c, err)
	}
}

func TestRemoteCallerRefusesStdioAndBadInput(t *testing.T) {
	for _, tc := range []struct{ id, tr string }{
		{"x", "stdio"}, {"x", "STDIO"}, {"x", ""}, {"", "http"},
		{strings.Repeat("a", 65), "http"}, {"a\nb", "http"}, {"x", "http\nforged"},
	} {
		if c, err := RemoteCaller(tc.id, tc.tr); err == nil || c.Valid() {
			t.Errorf("RemoteCaller(%q,%q) = %+v, %v; want an error and an invalid Caller", tc.id, tc.tr, c, err)
		}
	}
}
