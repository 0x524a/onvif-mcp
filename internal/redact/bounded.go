package redact

import (
	"strings"
	"unicode/utf8"
)

// tailGuard is how many bytes at the end of a cut input are never emitted. A
// secret that straddles the cut is only partly present, so Scrub cannot
// recognise it; its fragment sits at the very end of the scrubbed prefix. The
// guard is meant to exceed the longest secret that can straddle (a password).
const tailGuard = 512

// boundedPrefix is how much of an oversized input ScrubBounded examines.
func boundedPrefix(limit int) int { return limit*4 + tailGuard }

// ScrubBounded scrubs s and returns at most limit bytes of the result,
// ending in ellipsis when anything was cut. Unlike Scrub followed by a
// truncation, its cost does not grow with len(s): Scrub is slow (roughly
// 3 s per MB), so an agent-controlled string must be bounded first.
//
// The order is: cut the input to a bounded prefix at a rune boundary, scrub the
// prefix, then truncate the scrubbed text. Because the cut input may hold only
// the start of a secret, the last tailGuard bytes of a scrubbed prefix are
// dropped and ellipsis is always appended when the input was cut. A secret
// longer than tailGuard that straddles the cut can still leave a fragment in
// the part that is kept; that is the documented limit of pattern scrubbing.
//
// An input that fits in the bounded prefix is scrubbed whole and is cut only
// if the scrubbed text exceeds limit.
func ScrubBounded(s string, limit int, ellipsis string) string {
	if limit < len(ellipsis) {
		limit = len(ellipsis)
	}
	cut := false
	prefix := boundedPrefix(limit)
	if len(s) > prefix {
		s = strings.ToValidUTF8(s[:prefix], "")
		cut = true
	}
	s = Scrub(s)
	room := limit - len(ellipsis)
	if cut {
		if keep := len(s) - tailGuard; keep < room {
			room = keep
		}
		if room < 0 {
			room = 0
		}
	} else if len(s) <= limit {
		return s
	}
	for room > 0 && room < len(s) && !utf8.RuneStart(s[room]) {
		room--
	}
	if room > len(s) {
		room = len(s)
	}
	return s[:room] + ellipsis
}
