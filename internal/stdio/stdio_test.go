package stdio

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type buf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *buf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *buf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// run feeds input through the transport and returns the lines the SDK would
// have read, the replies written to stdout, and the read error (io.EOF at a
// clean end of input).
func run(t *testing.T, input string, limit int) (passed []string, replies []map[string]any, err error) {
	t.Helper()
	out := &buf{}
	tr := NewTransport(strings.NewReader(input), out, limit, quiet())
	sc := bufio.NewScanner(tr.Reader)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		passed = append(passed, sc.Text())
	}
	err = sc.Err()
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if e := json.Unmarshal([]byte(l), &m); e != nil {
			t.Fatalf("reply is not JSON: %q", l)
		}
		replies = append(replies, m)
	}
	return passed, replies, err
}

func code(t *testing.T, m map[string]any) float64 {
	t.Helper()
	if m["jsonrpc"] != "2.0" || m["id"] != nil {
		t.Fatalf("bad reply envelope: %v", m)
	}
	e, _ := m["error"].(map[string]any)
	if e == nil || e["message"] == "" {
		t.Fatalf("reply has no error: %v", m)
	}
	return e["code"].(float64)
}

const (
	req  = `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	note = `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	resp = `{"jsonrpc":"2.0","id":"a","result":{}}`
)

func TestValidMessagesPassThroughUnchanged(t *testing.T) {
	in := req + "\n\n" + note + "\r\n" + resp + "\n" + `[` + req + `,` + note + `]` + "\n"
	passed, replies, err := run(t, in, 1<<20)
	if err != nil || len(replies) != 0 {
		t.Fatalf("err=%v replies=%v", err, replies)
	}
	want := []string{req, note, resp, `[` + req + `,` + note + `]`}
	if len(passed) != len(want) {
		t.Fatalf("passed %d lines, want %d: %q", len(passed), len(want), passed)
	}
	for i := range want {
		if passed[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, passed[i], want[i])
		}
	}
}

func TestLastLineWithoutNewlineIsDelivered(t *testing.T) {
	passed, _, err := run(t, req, 1<<20)
	if err != nil || len(passed) != 1 || passed[0] != req {
		t.Fatalf("passed=%q err=%v", passed, err)
	}
}

func TestMalformedInputGetsAnErrorAndServingContinues(t *testing.T) {
	cases := []struct {
		name string
		line string
		code float64
	}{
		{"not json", `{not json`, -32700},
		{"binary", "\x00\xff\xfe", -32700},
		{"trailing data", req + ` ` + req, -32700},
		{"truncated", `{"jsonrpc":"2.0","id":1,`, -32700},
		{"wrong version", `{"jsonrpc":"1.0","id":1,"method":"x"}`, -32600},
		{"missing version", `{"id":1,"method":"x"}`, -32600},
		{"version case", `{"JSONRPC":"2.0","id":1,"method":"x"}`, -32600},
		{"scalar", `123`, -32600},
		{"string", `"hello"`, -32600},
		{"null", `null`, -32600},
		{"empty array", `[]`, -32600},
		{"bad batch element", `[` + req + `,{"jsonrpc":"1.0","method":"x"}]`, -32600},
		{"method not a string", `{"jsonrpc":"2.0","id":1,"method":5}`, -32600},
		{"id is an object", `{"jsonrpc":"2.0","id":{},"method":"x"}`, -32600},
		{"response without id", `{"jsonrpc":"2.0","result":{}}`, -32600},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			passed, replies, err := run(t, c.line+"\n"+req+"\n", 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			if len(passed) != 1 || passed[0] != req {
				t.Errorf("the bad line must be dropped and the good one kept: %q", passed)
			}
			if len(replies) != 1 || code(t, replies[0]) != c.code {
				t.Errorf("replies = %v, want one with code %v", replies, c.code)
			}
		})
	}
}

func TestReplyDoesNotEchoInput(t *testing.T) {
	_, replies, _ := run(t, "{not json SECRET-VALUE\n", 1<<20)
	b, _ := json.Marshal(replies)
	if strings.Contains(string(b), "SECRET-VALUE") {
		t.Errorf("reply echoes input: %s", b)
	}
}

func TestOversizeLineIsRejectedAndDiscarded(t *testing.T) {
	huge := `{"jsonrpc":"2.0","id":9,"method":"` + strings.Repeat("a", 5000) + `"}`
	passed, replies, err := run(t, req+"\n"+huge+"\n"+note+"\n", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(passed) != 2 || passed[0] != req || passed[1] != note {
		t.Errorf("passed = %q", passed)
	}
	if len(replies) != 1 || code(t, replies[0]) != -32600 {
		t.Errorf("replies = %v", replies)
	}
}

func TestOversizeLineAtEOFIsRejected(t *testing.T) {
	passed, replies, _ := run(t, strings.Repeat("x", 5000), 1024)
	if len(passed) != 0 || len(replies) != 1 {
		t.Errorf("passed=%q replies=%v", passed, replies)
	}
}

func TestLineExactlyAtCapPasses(t *testing.T) {
	line := `{"jsonrpc":"2.0","id":1,"method":"` + strings.Repeat("a", 100) + `"}`
	passed, replies, _ := run(t, line+"\n", len(line))
	if len(passed) != 1 || len(replies) != 0 {
		t.Errorf("passed=%d replies=%v", len(passed), replies)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestReadErrorReachesTheSDK(t *testing.T) {
	tr := NewTransport(errReader{}, io.Discard, 1024, quiet())
	_, err := io.ReadAll(tr.Reader)
	if err == nil || err.Error() != "boom" {
		t.Errorf("err = %v", err)
	}
}

func TestWritesAreSerialisedWithReplies(t *testing.T) {
	out := &buf{}
	tr := NewTransport(strings.NewReader(strings.Repeat("{bad\n", 200)), out, 1024, quiet())
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, _ = tr.Writer.Write([]byte(req + "\n"))
			}
		}()
	}
	_, _ = io.Copy(io.Discard, tr.Reader)
	wg.Wait()
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil {
			t.Fatalf("interleaved output line: %q", l)
		}
	}
}
