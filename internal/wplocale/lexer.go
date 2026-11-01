package wplocale

import "bytes"

// SegKind classifies a lexical segment of PHP source.
type SegKind int

const (
	// SegCode is executable PHP code (outside strings and comments).
	SegCode SegKind = iota
	// SegString is a string literal: '...', "...", `...` (shell-exec),
	// heredoc <<<EOT or nowdoc <<<'EOT'.
	SegString
	// SegComment is a //, # or /* */ comment.
	SegComment
)

// Segment is a contiguous lexical region of PHP source. Start/End are byte
// offsets into the original source, half-open [Start, End).
type Segment struct {
	Kind SegKind
	// Start and End delimit the segment in the original source.
	Start, End int
	// Quote is the delimiter of string literals: '\'', '"' or '`'.
	Quote byte
	// Value is the decoded literal value for short strings ('...', "...",
	// `...`) and nowdoc bodies. Empty for interpolated double-quoted strings
	// and heredocs whose value would depend on runtime interpolation.
	Value string
	// Body is the raw body for heredoc/nowdoc segments.
	Body         string
	Heredoc      bool
	Nowdoc       bool
	Interpolated bool
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// isLabelChar reports whether c may appear in a PHP identifier (including
// heredoc labels): [A-Za-z0-9_\x80-\xff].
func isLabelChar(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c >= 0x80
}

func isSpaceByte(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

// Segments partitions PHP source into code, string and comment segments that
// cover the whole input in order. String contents and comments never leak
// into SegCode, so code-level scans are immune to false matches inside
// strings, comments, heredocs, nowdocs and shell-exec (backtick) strings.
func Segments(src []byte) []Segment {
	segs := make([]Segment, 0, 32)
	n := len(src)
	codeStart := 0

	i := 0

	emitCode := func(end int) {
		if end > codeStart {
			segs = append(segs, Segment{Kind: SegCode, Start: codeStart, End: end})
		}
	}
	push := func(s Segment) {
		emitCode(s.Start)
		segs = append(segs, s)
		codeStart = s.End
		i = s.End
	}

	for i < n {
		c := src[i]
		switch {
		case c == '\'':
			j := i + 1
			var val []byte
			for j < n {
				if src[j] == '\\' && j+1 < n {
					if src[j+1] == '\'' {
						val = append(val, '\'')
					} else if src[j+1] == '\\' {
						val = append(val, '\\')
					} else {
						val = append(val, '\\', src[j+1])
					}
					j += 2
					continue
				}
				if src[j] == '\'' {
					j++
					break
				}
				val = append(val, src[j])
				j++
			}
			push(Segment{Kind: SegString, Start: i, End: j, Quote: '\'', Value: string(val)})

		case c == '"' || c == '`':
			q := c
			j := i + 1
			var raw []byte
			interp := false
			for j < n {
				ch := src[j]
				if ch == '\\' && j+1 < n {
					nx := src[j+1]
					switch nx {
					case 'n':
						raw = append(raw, '\n')
					case 't':
						raw = append(raw, '\t')
					case 'r':
						raw = append(raw, '\r')
					case 'v':
						raw = append(raw, '\v')
					case 'f':
						raw = append(raw, '\f')
					case 'e':
						raw = append(raw, 0x1b)
					case '\\':
						raw = append(raw, '\\')
					case '"':
						raw = append(raw, '"')
					case '`':
						raw = append(raw, '`')
					case '$':
						raw = append(raw, '$')
					case 'x':
						if j+3 < n && isHexDigit(src[j+2]) && isHexDigit(src[j+3]) {
							raw = append(raw, hexVal(src[j+2])<<4|hexVal(src[j+3]))
							j += 4
							continue
						}
						raw = append(raw, '\\', 'x')
					default:
						raw = append(raw, '\\', nx)
					}
					j += 2
					continue
				}
				if ch == q {
					j++
					break
				}
				if ch == '$' {
					interp = true
				}
				raw = append(raw, ch)
				j++
			}
			push(Segment{Kind: SegString, Start: i, End: j, Quote: q,
				Value: string(raw), Interpolated: interp})

		case c == '/' && i+1 < n && src[i+1] == '/':
			end := i + 2
			for end < n && src[end] != '\n' {
				if src[end] == '?' && end+1 < n && src[end+1] == '>' {
					break // ?> terminates a line comment in PHP
				}
				end++
			}
			push(Segment{Kind: SegComment, Start: i, End: end})

		case c == '#' && !(i+1 < n && src[i+1] == '['):
			// '#' starts a line comment unless it introduces a PHP 8
			// attribute #[...].
			end := i + 1
			for end < n && src[end] != '\n' {
				if src[end] == '?' && end+1 < n && src[end+1] == '>' {
					break
				}
				end++
			}
			push(Segment{Kind: SegComment, Start: i, End: end})

		case c == '/' && i+1 < n && src[i+1] == '*':
			rel := bytes.Index(src[i+2:], []byte("*/"))
			var end int
			if rel < 0 {
				end = n
			} else {
				end = i + 2 + rel + 2
			}
			push(Segment{Kind: SegComment, Start: i, End: end})

		case c == '<' && i+2 < n && src[i+1] == '<' && src[i+2] == '<':
			seg, ok := scanHeredoc(src, i)
			if !ok {
				i++ // not a heredoc opener; treat '<' as plain code
				continue
			}
			push(seg)

		default:
			i++
		}
	}
	emitCode(n)
	return segs
}

// scanHeredoc parses a heredoc (<<<EOT) or nowdoc (<<<'EOT') opening at src[
// start:]. It returns the covering segment (opening through the closing
// label) and whether the opener was valid.
func scanHeredoc(src []byte, start int) (Segment, bool) {
	p := start + 3
	for p < len(src) && isSpaceByte(src[p]) && src[p] != '\n' && src[p] != '\r' {
		p++
	}
	var q byte
	if p < len(src) && (src[p] == '\'' || src[p] == '"') {
		q = src[p]
		p++
	}
	lblStart := p
	for p < len(src) && isLabelChar(src[p]) && src[p] < 0x80 {
		p++
	}
	if p == lblStart {
		return Segment{}, false
	}
	label := string(src[lblStart:p])
	if q != 0 {
		if p >= len(src) || src[p] != q {
			return Segment{}, false
		}
		p++
	}
	// The opener must be terminated by a newline (optionally after
	// whitespace).
	e := p
	for e < len(src) && (src[e] == ' ' || src[e] == '\t') {
		e++
	}
	if e >= len(src) {
		return Segment{}, false
	}
	if src[e] == '\r' {
		if e+1 >= len(src) || src[e+1] != '\n' {
			return Segment{}, false
		}
		e++
	}
	if src[e] != '\n' {
		return Segment{}, false
	}
	bodyStart := e + 1

	segEnd, bodyEnd, found := findHeredocClose(src, bodyStart, label)
	if !found {
		// Unterminated heredoc: consume to EOF as a string segment.
		return Segment{Kind: SegString, Start: start, End: len(src),
			Quote:        q,
			Body:         string(src[bodyStart:]),
			Value:        string(src[bodyStart:]),
			Heredoc:      q != '\'',
			Nowdoc:       q == '\'',
			Interpolated: q != '\'',
		}, true
	}
	return Segment{Kind: SegString, Start: start, End: segEnd,
		Quote:        q,
		Body:         string(src[bodyStart:bodyEnd]),
		Value:        string(src[bodyStart:bodyEnd]),
		Heredoc:      q != '\'',
		Nowdoc:       q == '\'',
		Interpolated: q != '\'',
	}, true
}

// findHeredocClose locates the closing label line beginning at or after
// from. It returns the offset just past the closing label (the segment end),
// the offset of the start of the closing line's indentation (the body end
// before the trailing newline), and whether the closer was found.
func findHeredocClose(src []byte, from int, label string) (segEnd, bodyEnd int, found bool) {
	lbl := []byte(label)
	i := from
	for i < len(src) {
		j := i
		for j < len(src) && (src[j] == ' ' || src[j] == '\t') {
			j++
		}
		if j < len(src) && bytes.HasPrefix(src[j:], lbl) {
			k := j + len(lbl)
			if k >= len(src) || !isLabelChar(src[k]) {
				// The body excludes the newline immediately before the
				// closing line.
				be := i
				if be > from && src[be-1] == '\n' {
					be--
					if be > from && src[be-1] == '\r' {
						be--
					}
				}
				return k, be, true
			}
		}
		nl := bytes.IndexByte(src[i:], '\n')
		if nl < 0 {
			return len(src), len(src), false
		}
		i += nl + 1
	}
	return len(src), len(src), false
}

// MaskSource returns a copy of src in which every byte belonging to a
// non-code segment is replaced with NUL. Offsets are preserved, so positions
// computed on the masked buffer index the original source, while string
// literals, comments, heredocs, nowdocs and backtick strings are invisible
// to code-level pattern matching.
func MaskSource(src []byte, segs []Segment) []byte {
	m := append([]byte(nil), src...)
	for _, s := range segs {
		if s.Kind != SegCode {
			for k := s.Start; k < s.End && k < len(m); k++ {
				m[k] = 0
			}
		}
	}
	return m
}

// StringSegmentAt returns the string segment covering the byte offset off,
// or nil if the offset is outside any segment or inside a code/comment
// segment.
func StringSegmentAt(segs []Segment, off int) *Segment {
	for idx := range segs {
		s := &segs[idx]
		if off >= s.Start && off < s.End {
			if s.Kind == SegString {
				return s
			}
			return nil
		}
	}
	return nil
}
