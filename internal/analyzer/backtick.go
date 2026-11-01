package analyzer

import (
	"bytes"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// Byte code points for the PHP lexical scanner. Numeric constants keep the
// source free of fragile characters (backtick, backslash, dollar, underscore)
// that a transport layer could otherwise corrupt.
const (
	btTick   = byte(96)
	btSlash  = byte(47)
	btStar   = byte(42)
	btHash   = byte(35)
	btSQ     = byte(39)
	btDQ     = byte(34)
	btBS     = byte(92)
	btLT     = byte(60)
	btGT     = byte(62)
	btQ      = byte(63)
	btNL     = byte(10)
	btTab    = byte(9)
	btSpace  = byte(32)
	btLBr    = byte(91)
	btDollar = byte(36)
	btUnder  = byte(95)
)

// backtickFindings statically locates PHP backtick execution operators. It walks
// the source with a small lexer so that backticks inside comments, strings,
// heredoc/nowdoc blocks and non-PHP inline text are never treated as execution.
// The scanned bytes are never executed.
func backtickFindings(path string, src []byte) []finding.Finding {
	var out []finding.Finding
	n := len(src)
	i := 0
	inPHP := false
	for i < n {
		if !inPHP {
			if src[i] == btLT && i+1 < n && src[i+1] == btQ {
				// Opening tags mirror the phpOpen gate: only the canonical
				// tag and the short echo tag start PHP code. Anything else
				// after the question mark (including the legacy short tag
				// and processing instructions like "<?xml") stays inline
				// text, because the legacy tag is disabled by default in
				// PHP and must not silently widen detection.
				if i+4 < n && src[i+2] == 112 && src[i+3] == 104 && src[i+4] == 112 {
					inPHP = true
					i += 5
				} else if i+2 < n && src[i+2] == 61 {
					inPHP = true
					i += 3
				} else {
					i += 2
				}
				continue
			}
			i++
			continue
		}

		c := src[i]
		if c == btSlash && i+1 < n && src[i+1] == btSlash {
			i += 2
			for i < n && src[i] != btNL {
				i++
			}
			continue
		}
		if c == btHash {
			if i+1 < n && src[i+1] == btLBr {
				i++
				continue
			}
			i++
			for i < n && src[i] != btNL {
				i++
			}
			continue
		}
		if c == btSlash && i+1 < n && src[i+1] == btStar {
			i += 2
			for i+1 < n && !(src[i] == btStar && src[i+1] == btSlash) {
				i++
			}
			if i+1 < n {
				i += 2
			} else {
				i = n
			}
			continue
		}
		if c == btSQ {
			i = skipQuoted(src, i, btSQ)
			continue
		}
		if c == btDQ {
			i = skipQuoted(src, i, btDQ)
			continue
		}
		if c == btLT && i+2 < n && src[i+1] == btLT && src[i+2] == btLT {
			i = skipHeredoc(src, i)
			continue
		}
		if c == btTick {
			end, content := readBacktick(src, i)
			out = append(out, classifyBacktick(path, content, lineOfSource(src, i)))
			i = end
			continue
		}
		if c == btQ && i+1 < n && src[i+1] == btGT {
			inPHP = false
			i += 2
			continue
		}
		i++
	}
	return out
}

// skipQuoted advances past a single or double quoted string, honouring backslash
// escapes so an escaped quote does not terminate the string early.
func skipQuoted(src []byte, start int, quote byte) int {
	i := start + 1
	n := len(src)
	for i < n {
		if src[i] == btBS && i+1 < n {
			i += 2
			continue
		}
		if src[i] == quote {
			return i + 1
		}
		i++
	}
	return n
}

// readBacktick reads a backtick expression beginning at start. It returns the
// index just past the closing backtick and the raw content between backticks.
func readBacktick(src []byte, start int) (int, []byte) {
	i := start + 1
	n := len(src)
	cs := i
	for i < n {
		if src[i] == btBS && i+1 < n {
			i += 2
			continue
		}
		if src[i] == btTick {
			return i + 1, src[cs:i]
		}
		i++
	}
	return n, src[cs:n]
}

// skipHeredoc advances past a heredoc or nowdoc block starting at <<<.
func skipHeredoc(src []byte, start int) int {
	i := start + 3
	n := len(src)
	for i < n && (src[i] == btSpace || src[i] == btTab) {
		i++
	}
	var quote byte
	if i < n && (src[i] == btSQ || src[i] == btDQ) {
		quote = src[i]
		i++
	}
	idStart := i
	for i < n && isIdentByte(src[i]) {
		i++
	}
	if i == idStart {
		return start + 3
	}
	id := src[idStart:i]
	if quote != 0 {
		if i < n && src[i] == quote {
			i++
		} else {
			return start + 3
		}
	}
	for i < n && src[i] != btNL {
		i++
	}
	if i < n {
		i++
	}
	for i <= n {
		lineStart := i
		j := i
		for j < n && src[j] != btNL {
			j++
		}
		line := src[lineStart:j]
		k := 0
		for k < len(line) && (line[k] == btSpace || line[k] == btTab) {
			k++
		}
		if bytes.HasPrefix(line[k:], id) {
			after := line[k+len(id):]
			if len(after) == 0 || !isIdentByte(after[0]) {
				end := j
				if end < n {
					end++
				}
				return end
			}
		}
		if j >= n {
			return n
		}
		i = j + 1
	}
	return n
}

func isIdentByte(c byte) bool {
	if c >= 48 && c <= 57 {
		return true
	}
	if c >= 65 && c <= 90 {
		return true
	}
	if c >= 97 && c <= 122 {
		return true
	}
	return c == btUnder
}

// classifyBacktick turns one backtick expression into a finding. The finding
// reports the execution mechanism separately from any malware verdict.
func classifyBacktick(path string, content []byte, line int) finding.Finding {
	sev := finding.High
	reason := "PHP backtick shell execution of a static command"
	if hasSuperglobal(content) {
		sev = finding.Critical
		reason = "PHP backtick shell execution with user-controlled input"
	} else if bytes.IndexByte(content, btDollar) >= 0 {
		sev = finding.High
		reason = "PHP backtick shell execution with variable interpolation"
	}
	return finding.Finding{
		Status:   finding.Suspicious,
		Severity: sev,
		Title:    "PHP backtick shell execution",
		Path:     path,
		Rule:     "php-backtick",
		Line:     line,
		Evidence: reason + ": " + snippet(content),
	}
}

func hasSuperglobal(b []byte) bool {
	names := []string{"POST", "GET", "REQUEST", "COOKIE", "SERVER", "FILES"}
	for i := 0; i < len(names); i++ {
		if bytes.Contains(b, []byte(dollar+under+names[i])) {
			return true
		}
	}
	return false
}

// snippet renders printable content for evidence and caps its length.
func snippet(b []byte) string {
	const limit = 60
	var out []byte
	for i := 0; i < len(b) && len(out) < limit; i++ {
		c := b[i]
		if c == btNL || c == btTab || c == 13 {
			out = append(out, btSpace)
			continue
		}
		if c < 32 || c > 126 {
			continue
		}
		out = append(out, c)
	}
	if len(b) > limit {
		return string(out) + " ..."
	}
	return string(out)
}
