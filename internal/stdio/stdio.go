// Package stdio wraps the MCP stdio transport so that protocol-level garbage
// on stdin does not end the session.
//
// go-sdk v1.7.0 (mcp/transport.go, newIOConn) decodes stdin with a
// json.Decoder and treats any decode or message-shape error as fatal: one
// malformed line closes the connection and the process exits. JSON-RPC 2.0
// says a server answers such input with an error and keeps serving. This
// package sits between stdin and the SDK: it reads one line at a time, caps
// the line length, drops what the SDK would choke on and answers it with a
// -32700 (parse error) or -32600 (invalid request) response on stdout.
//
// Nothing else is written to stdout, and nothing the SDK would accept is
// altered.
package stdio

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// MaxLineBytes is the default cap on one inbound message.
const MaxLineBytes = 4 << 20

// JSON-RPC 2.0 error codes used for rejected input.
const (
	codeParse   = -32700
	codeInvalid = -32600
)

// lockedWriter serialises writes to out. The SDK writes each message with a
// single Write call, so holding a mutex across one call keeps replies from
// this package from interleaving with the SDK's own output.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// Close is a no-op: the process owns stdout.
func (l *lockedWriter) Close() error { return nil }

// NewTransport returns an mcp.IOTransport that reads newline-delimited
// JSON-RPC from in and writes to out, rejecting bad input as described in the
// package comment. maxLine <= 0 selects MaxLineBytes.
func NewTransport(in io.Reader, out io.Writer, maxLine int, log *slog.Logger) *mcp.IOTransport {
	if maxLine <= 0 {
		maxLine = MaxLineBytes
	}
	pr, pw := io.Pipe()
	lw := &lockedWriter{w: out}
	go pump(in, pw, lw, maxLine, log)
	return &mcp.IOTransport{Reader: pr, Writer: lw}
}

func pump(in io.Reader, pw *io.PipeWriter, out io.Writer, maxLine int, log *slog.Logger) {
	br := bufio.NewReaderSize(in, 64<<10)
	for {
		line, tooLong, err := readLine(br, maxLine)
		if tooLong || len(bytes.TrimSpace(line)) > 0 {
			if !handle(line, tooLong, maxLine, pw, out, log) {
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = nil
			}
			_ = pw.CloseWithError(err)
			return
		}
	}
}

// handle forwards a good line or answers a bad one. It returns false when the
// SDK side has gone away.
func handle(line []byte, tooLong bool, maxLine int, pw *io.PipeWriter, out io.Writer, log *slog.Logger) bool {
	line = bytes.TrimSpace(line)
	var code int
	var msg string
	switch {
	case tooLong:
		code, msg = codeInvalid, "Invalid request: message exceeds the size limit"
	default:
		code, msg = validate(line)
	}
	if code == 0 {
		_, err := pw.Write(append(line, '\n'))
		return err == nil
	}
	log.Warn("rejected inbound message", "code", code, "bytes", len(line), "limit", maxLine)
	reply, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      nil,
		"error":   map[string]any{"code": code, "message": msg},
	})
	_, _ = out.Write(append(reply, '\n'))
	return true
}

// readLine returns one line without its terminator. A line longer than limit is
// discarded as it is read, so memory stays bounded, and reported via tooLong.
func readLine(br *bufio.Reader, limit int) (line []byte, tooLong bool, err error) {
	for {
		chunk, e := br.ReadSlice('\n')
		if !tooLong {
			if len(line)+len(chunk) > limit+1 { // +1: the newline itself
				tooLong, line = true, nil
			} else {
				line = append(line, chunk...)
			}
		}
		if errors.Is(e, bufio.ErrBufferFull) {
			continue
		}
		if !tooLong {
			line = bytes.TrimRight(line, "\r\n")
			if len(line) > limit {
				tooLong, line = true, nil
			}
		}
		return line, tooLong, e
	}
}

// validate reports whether the SDK would accept line. It returns 0 for a line
// the SDK accepts, otherwise the JSON-RPC error code and message. It mirrors
// the SDK's checks (readBatch and jsonrpc2.DecodeMessage in v1.7.0) and no
// more: version "2.0", an id that is a string, number or null, and either a
// string method or a non-null id.
func validate(line []byte) (int, string) {
	if !json.Valid(line) {
		return codeParse, "Parse error: invalid JSON"
	}
	if line[0] == '[' {
		var batch []json.RawMessage
		if json.Unmarshal(line, &batch) != nil || len(batch) == 0 {
			return codeInvalid, "Invalid request: empty batch"
		}
		for _, raw := range batch {
			if !validMessage(raw) {
				return codeInvalid, "Invalid request: not a JSON-RPC 2.0 message"
			}
		}
		return 0, ""
	}
	if !validMessage(line) {
		return codeInvalid, "Invalid request: not a JSON-RPC 2.0 message"
	}
	return 0, ""
}

func validMessage(raw []byte) bool {
	var m map[string]json.RawMessage // case-sensitive keys, like the SDK
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return false
	}
	var ver string
	if json.Unmarshal(m["jsonrpc"], &ver) != nil || ver != "2.0" {
		return false
	}
	id, hasID := m["id"]
	idNull := !hasID || string(bytes.TrimSpace(id)) == "null"
	if hasID && !idNull {
		var s string
		var n json.Number
		if json.Unmarshal(id, &s) != nil && json.Unmarshal(id, &n) != nil {
			return false
		}
	}
	if method, ok := m["method"]; ok {
		var s string
		return json.Unmarshal(method, &s) == nil
	}
	return !idNull
}
