package mapx

// Package mapx provides a tiny, dependency‑free evaluator for jq‑style paths
// over generic JSON-like data (map[string]any, []any, primitives).
//
// Supported syntax (subset of jq):
//   .foo.bar           – object field access
//   .foo.bar[0]        – array index (negative indexes allowed)
//   .foo[1:4]          – array slice [start:end(:step)]
//   .foo[*] / .*       – wildcard over arrays / objects
//   ..                  – recursive descent (include self)
//   .. | .**           – use .. to flatten all descendants, then continue
//   .["complex key"]   – quoted keys
// You can combine these arbitrarily: e.g. .. | .items[*].name or ..items[0]
//
// Not supported: jq filters, arithmetic, comparisons, pipes, functions, etc.
// This is intentionally small but designed to be easy to extend.

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unicode"
)

type SegmentKind int

const (
	segField       SegmentKind = iota
	segWildcardObj             // .*
	segIndex                   // [n]
	segSlice                   // [start:end(:step)]
	segWildcardArr             // [*]
	segRecursive               // .. (recursive descent / flatten all descendants)
)

type segment struct {
	kind SegmentKind
	// for segField
	field string
	// for segIndex
	index int
	// for segSlice (nil => default)
	start *int
	end   *int
	step  *int
}

// Get returns all values matching the jq-like path. If the path is syntactically
// invalid, it returns an error. If parts of the path are missing at runtime, it
// simply yields zero results (no error).
func Get(root any, path string) ([]any, error) {
	segs, err := parse(path)
	if err != nil {
		return nil, err
	}
	frontier := []any{root}
	for _, s := range segs {
		var next []any
		for _, node := range frontier {
			vals := applySegment(node, s)
			next = append(next, vals...)
		}
		frontier = next
	}
	return frontier, nil
}

// GetOne is a convenience: it expects exactly one result.
func GetOne(root any, path string) (any, error) {
	vals, err := Get(root, path)
	if err != nil {
		return nil, err
	}
	switch len(vals) {
	case 0:
		return nil, errors.New("no value found for path")
	case 1:
		return vals[0], nil
	default:
		return nil, fmt.Errorf("path matched %d values; expected one", len(vals))
	}
}

func applySegment(node any, s segment) []any {
	switch s.kind {
	case segField:
		if m, ok := asMap(node); ok {
			if v, ok := m[s.field]; ok {
				return []any{v}
			}
		}
	case segWildcardObj:
		if m, ok := asMap(node); ok {
			out := make([]any, 0, len(m))
			for _, v := range m {
				out = append(out, v)
			}
			return out
		}
	case segIndex:
		if arr, ok := asSlice(node); ok {
			idx := normalizeIndex(s.index, len(arr))
			if idx >= 0 && idx < len(arr) {
				return []any{arr[idx]}
			}
		}
	case segSlice:
		if arr, ok := asSlice(node); ok {
			start, end, step := resolveSliceBounds(s, len(arr))
			if step == 0 {
				return nil
			}
			var out []any
			if step > 0 {
				for i := start; i < end && i < len(arr); i += step {
					if i >= 0 {
						out = append(out, arr[i])
					}
				}
			} else { // negative step
				for i := start; i > end && i >= 0 && i < len(arr); i += step {
					out = append(out, arr[i])
				}
			}
			return out
		}
	case segWildcardArr:
		if arr, ok := asSlice(node); ok {
			out := make([]any, 0, len(arr))
			out = append(out, arr...)
			return out
		}
	case segRecursive:
		// include self and all descendants
		return recursiveFlatten(node)
	}
	return nil
}

func asMap(v any) (map[string]any, bool) {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Map || rv.Type().Key().Kind() != reflect.String {
		return nil, false
	}

	out := make(map[string]any, rv.Len())
	for _, key := range rv.MapKeys() {
		out[key.String()] = rv.MapIndex(key).Interface()
	}
	return out, true
}

func asSlice(v any) ([]any, bool) {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice {
		return nil, false
	}

	n := rv.Len()
	out := make([]any, n)
	for i := 0; i < n; i++ {
		out[i] = rv.Index(i).Interface()
	}
	return out, true
}

func normalizeIndex(i, n int) int {
	if i < 0 {
		return n + i
	}
	return i
}

func resolveSliceBounds(s segment, n int) (start, end, step int) {
	// Defaults like jq/Python
	if s.step != nil {
		step = *s.step
	} else {
		step = 1
	}
	if s.start != nil {
		start = *s.start
	} else {
		if step > 0 {
			start = 0
		} else {
			start = n - 1
		}
	}
	if s.end != nil {
		end = *s.end
	} else {
		if step > 0 {
			end = n
		} else {
			end = -1
		}
	}
	// Handle negatives relative to n
	if start < 0 {
		start = n + start
	}
	if end < 0 {
		end = n + end
	}
	return
}

func recursiveFlatten(v any) []any {
	// DFS including self
	var out []any
	stack := []any{v}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		out = append(out, n)
		switch t := n.(type) {
		case map[string]any:
			for _, vv := range t {
				stack = append(stack, vv)
			}
		case []any:
			for i := len(t) - 1; i >= 0; i-- { // push reversed to keep natural order
				stack = append(stack, t[i])
			}
		}
	}
	return out
}

// ----------------- Parser -----------------

type scanner struct {
	s   string
	i   int
	len int
}

func parse(path string) ([]segment, error) {
	s := &scanner{s: strings.TrimSpace(path), len: len(strings.TrimSpace(path))}
	var segs []segment
	// Optional leading dot
	if s.peek() == '.' {
		// consume, but allow ".." to be handled in loop
	}
	for s.i < s.len {
		ch := s.peek()
		switch ch {
		case ' ':
			s.i++
		case '.':
			s.i++
			if s.peek() == '.' { // recursive
				s.i++
				segs = append(segs, segment{kind: segRecursive})
				continue
			}
			if s.peek() == '*' { // .*
				s.i++
				segs = append(segs, segment{kind: segWildcardObj})
				continue
			}
			if isIdentStart(s.peek()) {
				name := s.readIdent()
				segs = append(segs, segment{kind: segField, field: name})
				continue
			}
			// allow .["key"] right after a dot
			if s.peek() == '[' {
				// fallthrough to bracket handling below via continue to start of loop
				continue
			}
			return nil, fmt.Errorf("unexpected character after '.': %q at %d", s.peek(), s.i)
		case '[':
			s.i++ // consume '['
			// skip spaces
			s.skipSpaces()
			if s.peek() == '"' || s.peek() == '\'' { // quoted key: ["..."] or ['...']
				str, err := s.readQuoted()
				if err != nil {
					return nil, err
				}
				s.skipSpaces()
				if s.peek() != ']' {
					return nil, s.errf("] expected after quoted key")
				}
				s.i++
				segs = append(segs, segment{kind: segField, field: str})
				continue
			}
			if s.peek() == '*' { // wildcard array [*]
				s.i++
				s.skipSpaces()
				if s.peek() != ']' {
					return nil, s.errf("] expected after [*]")
				}
				s.i++
				segs = append(segs, segment{kind: segWildcardArr})
				continue
			}
			// slice or index
			startSet, startVal, startNeg, _ := s.tryReadInt()
			s.skipSpaces()
			if s.peek() == ':' { // slice
				s.i++
				skipSpaces := s.skipSpaces
				skipSpaces()
				endSet, endVal, endNeg, _ := s.tryReadInt()
				skipSpaces()
				var stepSet bool
				var stepVal int
				var stepNeg bool
				if s.peek() == ':' {
					s.i++
					skipSpaces()
					stepSet, stepVal, stepNeg, _ = s.tryReadInt()
				}
				skipSpaces()
				if s.peek() != ']' {
					return nil, s.errf("] expected to close slice")
				}
				s.i++
				seg := segment{kind: segSlice}
				if startSet {
					v := startVal
					if startNeg {
						v = -v
					}
					seg.start = &v
				}
				if endSet {
					v := endVal
					if endNeg {
						v = -v
					}
					seg.end = &v
				}
				if stepSet {
					v := stepVal
					if stepNeg {
						v = -v
					}
					seg.step = &v
				}
				segs = append(segs, seg)
				continue
			}
			// index
			if !startSet {
				return nil, s.errf("number, '*', or quoted key expected inside []")
			}
			if s.peek() != ']' {
				return nil, s.errf("] expected after index")
			}
			s.i++
			idx := startVal
			if startNeg {
				idx = -idx
			}
			segs = append(segs, segment{kind: segIndex, index: idx})
		default:
			// allow bare identifier at start (without dot)
			if isIdentStart(ch) && len(segs) == 0 {
				name := s.readIdent()
				segs = append(segs, segment{kind: segField, field: name})
				continue
			}
			return nil, fmt.Errorf("unexpected character %q at %d", ch, s.i)
		}
	}
	return segs, nil
}

func (s *scanner) peek() byte {
	if s.i >= s.len {
		return 0
	}
	return s.s[s.i]
}

func (s *scanner) skipSpaces() {
	for s.i < s.len {
		if s.s[s.i] == ' ' || s.s[s.i] == '\t' || s.s[s.i] == '\n' || s.s[s.i] == '\r' {
			s.i++
			continue
		}
		break
	}
}

func (s *scanner) readIdent() string {
	start := s.i
	// first char already known to be ident start
	for s.i < s.len && isIdentPart(s.s[s.i]) {
		s.i++
	}
	return s.s[start:s.i]
}

func isIdentStart(b byte) bool {
	r := rune(b)
	return b != 0 && (b == '_' || unicode.IsLetter(r))
}
func isIdentPart(b byte) bool {
	r := rune(b)
	return b != 0 && (b == '_' || b == '-' || unicode.IsLetter(r) || unicode.IsDigit(r))
}

func (s *scanner) readQuoted() (string, error) {
	quote := s.peek()
	if quote != '\'' && quote != '"' {
		return "", s.errf("expected quote, got %q", quote)
	}
	s.i++ // consume quote
	var b strings.Builder
	for s.i < s.len {
		ch := s.s[s.i]
		s.i++
		if ch == quote {
			return b.String(), nil
		}
		if ch == '\\' {
			if s.i >= s.len {
				return "", s.errf("unterminated escape")
			}
			esc := s.s[s.i]
			s.i++
			switch esc {
			case '\\', '\'', '"':
				b.WriteByte(esc)
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			default:
				return "", s.errf("unsupported escape: \\%c", esc)
			}
			continue
		}
		b.WriteByte(ch)
	}
	return "", s.errf("unterminated string literal")
}

func (s *scanner) tryReadInt() (set bool, val int, neg bool, err error) {
	start := s.i
	if s.peek() == '-' {
		neg = true
		s.i++
	}
	digitsStart := s.i
	for s.i < s.len && s.s[s.i] >= '0' && s.s[s.i] <= '9' {
		s.i++
	}
	if s.i == digitsStart { // no digits
		s.i = start
		return false, 0, false, nil
	}
	iv, perr := strconv.Atoi(s.s[digitsStart:s.i])
	if perr != nil {
		return false, 0, false, perr
	}
	return true, iv, neg, nil
}

func (s *scanner) errf(format string, a ...any) error {
	return fmt.Errorf("parse error at %d: "+format, append([]any{s.i}, a...)...)
}

// -------------- Helpers --------------

// MustGet is a helper that panics on error; convenient in tests.
func MustGet(root any, path string) []any {
	v, err := Get(root, path)
	if err != nil {
		panic(err)
	}
	return v
}
