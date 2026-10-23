package httpserver

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/safety"
)

const (
	maxTokenFileBytes = 64 << 10
	maxTokens         = 64
	tokenLen          = 64 // hex characters of a 256-bit token
)

// TokenStore holds the SHA-256 digests of the accepted bearer tokens, never the
// tokens. It is immutable after load: rotation and revocation are a file edit
// and a restart.
type TokenStore struct {
	entries []tokenEntry
	now     func() time.Time
	eq      func(a, b []byte) int // constant-time compare; a field so tests can count calls
}

type tokenEntry struct {
	id      string
	digest  [sha256.Size]byte
	grants  []string
	expires time.Time // zero means never
}

type fileEntry struct {
	ID      string   `json:"id"`
	SHA256  string   `json:"sha256"`
	Grant   []string `json:"grant,omitempty"`
	Expires string   `json:"expires,omitempty"`
}

type tokenFile struct {
	Tokens []fileEntry `json:"tokens"`
}

// LoadTokens reads the token file. It must be a regular file readable only by
// its owner (the same check as the camera config).
func LoadTokens(path string) (*TokenStore, error) {
	b, err := config.ReadPrivateFile(path, maxTokenFileBytes, "token file")
	if err != nil {
		return nil, err
	}
	return ParseTokens(b, time.Now)
}

// ParseTokens validates a token document. Every error names the entry index and
// never a digest or any file content.
func ParseTokens(b []byte, now func() time.Time) (*TokenStore, error) {
	var f tokenFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		var se *json.SyntaxError
		if errors.As(err, &se) {
			return nil, fmt.Errorf("token file: not valid JSON (near byte %d)", se.Offset)
		}
		return nil, fmt.Errorf("token file: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("token file: unexpected data after the top-level object")
	}
	if n := len(f.Tokens); n < 1 || n > maxTokens {
		return nil, fmt.Errorf("token file: must define 1 to %d tokens, found %d", maxTokens, n)
	}
	s := &TokenStore{now: now, eq: func(a, b []byte) int { return subtle.ConstantTimeCompare(a, b) }}
	ids := map[string]struct{}{}
	digests := map[[sha256.Size]byte]struct{}{}
	for i, e := range f.Tokens {
		bad := func(why string) error { return fmt.Errorf("token file: entry %d: %s", i, why) }
		if !tokenIDRe.MatchString(e.ID) {
			return nil, bad("id must match [a-z0-9][a-z0-9._-]{0,63}")
		}
		if _, dup := ids[e.ID]; dup {
			return nil, bad("duplicate id")
		}
		var d [sha256.Size]byte
		if len(e.SHA256) != 2*sha256.Size || !isLowerHex(e.SHA256) {
			return nil, bad("sha256 must be 64 lowercase hex characters")
		}
		if _, err := hex.Decode(d[:], []byte(e.SHA256)); err != nil {
			return nil, bad("sha256 must be 64 lowercase hex characters")
		}
		if _, dup := digests[d]; dup {
			return nil, bad("duplicate sha256")
		}
		te := tokenEntry{id: e.ID, digest: d}
		seen := map[string]struct{}{}
		for _, g := range e.Grant {
			if !safety.IsOptInTool(g) {
				return nil, bad(fmt.Sprintf("grant must be one of %v", safety.OptInTools()))
			}
			if _, dup := seen[g]; dup {
				return nil, bad("duplicate grant")
			}
			seen[g] = struct{}{}
			te.grants = append(te.grants, g)
		}
		if e.Expires != "" {
			t, err := time.Parse(time.RFC3339, e.Expires)
			if err != nil {
				return nil, bad("expires must be an RFC 3339 timestamp")
			}
			te.expires = t
		}
		ids[e.ID] = struct{}{}
		digests[d] = struct{}{}
		s.entries = append(s.entries, te)
	}
	return s, nil
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// IDs returns the token ids in file order, for the startup line.
func (s *TokenStore) IDs() []string {
	out := make([]string, len(s.entries))
	for i, e := range s.entries {
		out[i] = e.id
	}
	return out
}

// Len is the number of tokens.
func (s *TokenStore) Len() int { return len(s.entries) }

// Grants returns the opt-in tools granted to the token id, nil for an unknown
// id. It implements mcpserver.GrantSource.
func (s *TokenStore) Grants(id string) []string {
	for _, e := range s.entries {
		if e.id == id {
			return slices.Clone(e.grants)
		}
	}
	return nil
}

// Verify checks a presented bearer token. It accepts only exactly 64 lowercase
// hex characters (the format the generator prints), so a hand-picked weak token
// cannot authenticate even if its digest were in the file. It hashes once and
// compares against every entry in constant time with no early exit, then checks
// expiry. Unknown, expired and malformed are indistinguishable to the caller.
func (s *TokenStore) Verify(token string) (id string, grants []string, ok bool) {
	if len(token) != tokenLen || !isLowerHex(token) {
		return "", nil, false
	}
	sum := sha256.Sum256([]byte(token))
	found := -1
	for i := range s.entries {
		if s.eq(sum[:], s.entries[i].digest[:]) == 1 && found < 0 {
			found = i
		}
	}
	if found < 0 {
		return "", nil, false
	}
	e := s.entries[found]
	if !e.expires.IsZero() && !s.now().Before(e.expires) {
		return "", nil, false
	}
	return e.id, slices.Clone(e.grants), true
}

// NewToken generates a token from 32 bytes of crypto/rand. It returns the token
// (64 lowercase hex characters, to be shown to the operator once) and the JSON
// entry for the token file, which holds the digest and never the token.
func NewToken(id string) (token, fileEntryJSON string, err error) {
	if !tokenIDRe.MatchString(id) {
		return "", "", errors.New("token id must match [a-z0-9][a-z0-9._-]{0,63}")
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", fmt.Errorf("generate token: %w", err)
	}
	token = hex.EncodeToString(raw[:])
	sum := sha256.Sum256([]byte(token))
	entry, err := json.Marshal(fileEntry{ID: id, SHA256: hex.EncodeToString(sum[:])})
	if err != nil {
		return "", "", err
	}
	return token, string(entry), nil
}
