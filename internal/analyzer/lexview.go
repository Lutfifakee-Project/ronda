package analyzer

// lexview.go implements a single-pass lexical profiler for PHP source. It
// mirrors the state machine that backs backtickFindings (opening tags,
// comments, quoted strings, heredoc/nowdoc, backticks, closing tags) and
// classifies every byte of the input into one context class. From that
// classification three aligned byte views are derived:
//
//      codeView    — only code bytes visible; string contents, comments,
//                    backtick contents and inline HTML are blanked. Call-shaped
//                    signals are matched here so a function name inside a
//                    comment, a string literal or documentation can never
//                    produce a PHP invocation signal.
//      runtimeView — comments, non-PHP text, single-quoted strings and nowdoc
//                    bodies are blanked; code plus double-quoted strings and
//                    heredoc bodies stay visible, because those interpolate and
//                    their contents can become executable values at runtime.
//                    Signals whose argument text legitimately lives inside a
//                    string literal (remote URLs, ".php" write targets, the /e
//                    modifier of preg_replace, superglobal reads inside
//                    interpolated strings) are matched here.
//      blobView    — comments and inline HTML blanked; every string body stays
//                    visible. Used for the long-base64-blob signal and for
//                    quoted dynamic-dispatch names.
//
// The views have the same length as the source plus one sentinel space byte
// prepended at offset 0 so identifier-boundary patterns can match a function
// call at the very start of the file without special cases. View index i
// corresponds to source index i-1.
//
// The profiler never executes anything; it only reads bytes.

// Byte code points reused from backtick.go (btTick, btSlash, ...).
const (
	lvDQ      = btDQ
	lvSQ      = btSQ
	lvBS      = btBS
	lvTick    = btTick
	lvHash    = btHash
	lvLBr     = btLBr
	lvNL      = btNL
	lvTab     = btTab
	lvSpace   = btSpace
	lvLT      = btLT
	lvQ       = btQ
	lvGT      = btGT
	lvDollar  = btDollar
	lvCR      = byte(13)
	lvLBrace  = byte(123)
	lvRBrace  = byte(125)
	lvMinus   = byte(45)
	lvHyphen  = lvMinus
	lvPercent = byte(37)
)

// lexClass enumerates the lexical context of a byte.
type lexClass uint8

const (
	classCode     lexClass = iota // PHP code position
	classTag                      // opening/closing tag marker bytes
	classComment                  // // # /* */ docblock comment
	classSQ                       // single-quoted string body
	classDQ                       // double-quoted string body (interpolates)
	classHeredoc                  // heredoc body (interpolates)
	classNowdoc                   // nowdoc body (literal)
	classBacktick                 // backtick command body
	classNonPHP                   // inline HTML outside PHP tags
)

// lexProfile is the result of one lexical pass.
type lexProfile struct {
	classes []lexClass // one per source byte
	inPHP   bool       // whether any PHP region exists
}

// profileLex walks src and records the lexical class of every byte. It uses
// the same opening-tag policy as backtickFindings and the phpOpen gate: only
// "<?php" and "<?=" start PHP mode; the legacy short tag stays inline text.
func profileLex(src []byte) lexProfile {
	n := len(src)
	classes := make([]lexClass, n)
	inPHP := false
	anyPHP := false
	i := 0
	for i < n {
		if !inPHP {
			classes[i] = classNonPHP
			if src[i] == btLT && i+1 < n && src[i+1] == btQ {
				if i+4 < n && src[i+2] == 112 && src[i+3] == 104 && src[i+4] == 112 {
					inPHP = true
					anyPHP = true
					for k := 0; k < 5; k++ {
						classes[i+k] = classTag
					}
					i += 5
					continue
				}
				if i+2 < n && src[i+2] == 61 {
					inPHP = true
					anyPHP = true
					classes[i] = classTag
					classes[i+1] = classTag
					classes[i+2] = classTag
					i += 3
					continue
				}
			}
			i++
			continue
		}

		c := src[i]
		switch {
		case c == btSlash && i+1 < n && src[i+1] == btSlash:
			for i < n && src[i] != btNL {
				classes[i] = classComment
				i++
			}
		case c == btHash && i+1 < n && src[i+1] == btLBr:
			// "#[" starts a PHP attribute, not a comment.
			classes[i] = classCode
			i++
		case c == btHash:
			for i < n && src[i] != btNL {
				classes[i] = classComment
				i++
			}
		case c == btSlash && i+1 < n && src[i+1] == btStar:
			classes[i] = classComment
			classes[i+1] = classComment
			i += 2
			for i < n {
				if src[i] == btStar && i+1 < n && src[i+1] == btSlash {
					classes[i] = classComment
					classes[i+1] = classComment
					i += 2
					break
				}
				classes[i] = classComment
				i++
			}
		case c == btSQ:
			classes[i] = classCode // opening quote is code
			i = lexQuoted(src, i, btSQ, classes, classSQ)
		case c == btDQ:
			classes[i] = classCode
			i = lexQuoted(src, i, btDQ, classes, classDQ)
		case c == btLT && i+2 < n && src[i+1] == btLT && src[i+2] == btLT:
			i = lexHeredoc(src, i, classes)
		case c == btTick:
			classes[i] = classCode
			i = lexQuoted(src, i, btTick, classes, classBacktick)
		case c == btQ && i+1 < n && src[i+1] == btGT:
			classes[i] = classTag
			classes[i+1] = classTag
			inPHP = false
			i += 2
		default:
			classes[i] = classCode
			i++
		}
	}
	return lexProfile{classes: classes, inPHP: anyPHP}
}

// lexQuoted walks a quoted region starting at the opening byte (quote or
// backtick), honouring backslash escapes, and marks every body byte with cls.
// It returns the index just past the closing byte (or the end of input).
func lexQuoted(src []byte, start int, quote byte, classes []lexClass, cls lexClass) int {
	i := start + 1
	n := len(src)
	for i < n {
		if src[i] == btBS && i+1 < n {
			classes[i] = cls
			classes[i+1] = cls
			i += 2
			continue
		}
		if src[i] == quote {
			classes[i] = classCode // closing quote is code
			return i + 1
		}
		classes[i] = cls
		i++
	}
	return n
}

// lexHeredoc walks a heredoc or nowdoc body beginning at "<<<". Nowdoc
// (<<<'ID') is marked classNowdoc, heredoc (<<<ID or <<<"ID") classHeredoc.
// The terminator scan mirrors skipHeredoc: the closing identifier must appear
// at the start of a line, optionally indented, not followed by an identifier
// byte. Malformed start markers leave everything as code, matching skipHeredoc.
func lexHeredoc(src []byte, start int, classes []lexClass) int {
	n := len(src)
	classes[start] = classCode
	classes[start+1] = classCode
	classes[start+2] = classCode
	i := start + 3
	for i < n && (src[i] == btSpace || src[i] == btTab) {
		classes[i] = classCode
		i++
	}
	var quote byte
	if i < n && (src[i] == btSQ || src[i] == btDQ) {
		quote = src[i]
		classes[i] = classCode
		i++
	}
	idStart := i
	for i < n && isIdentByte(src[i]) {
		classes[i] = classCode
		i++
	}
	if i == idStart {
		return start + 3
	}
	id := src[idStart:i]
	nowdoc := quote == btSQ
	if quote != 0 {
		if i < n && src[i] == quote {
			classes[i] = classCode
			i++
		} else {
			return start + 3
		}
	}
	for i < n && src[i] != btNL {
		classes[i] = classCode
		i++
	}
	if i < n {
		i++
	}
	body := classHeredoc
	if nowdoc {
		body = classNowdoc
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
		if bytesHasPrefix(line[k:], id) {
			after := line[k+len(id):]
			if len(after) == 0 || !isIdentByte(after[0]) {
				// Terminator line: identifier bytes stay code.
				for x := lineStart + k; x < lineStart+k+len(id) && x < n; x++ {
					classes[x] = classCode
				}
				end := j
				if end < n {
					end++
				}
				return end
			}
		}
		for x := lineStart; x < j; x++ {
			classes[x] = body
		}
		if j >= n {
			return n
		}
		classes[j] = classCode // the newline itself
		i = j + 1
	}
	return n
}

func bytesHasPrefix(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}

// viewKind selects which derived view to build.
type viewKind uint8

const (
	viewCode viewKind = iota
	viewRuntime
	viewBlob
)

// buildView renders the profile into a byte slice of len(src)+1. Visible
// bytes are copied; everything else becomes a space so regex indices stay
// aligned with the source (shifted by the sentinel). A sentinel space is
// always written at index 0. Newline bytes are preserved even inside blanked
// regions: line numbers derived from a view must equal the real source line
// numbers, and preserving newlines does not change what call patterns can
// match (\s already spans newlines).
func buildView(src []byte, p lexProfile, kind viewKind) []byte {
	out := make([]byte, len(src)+1)
	out[0] = btSpace
	for i := 0; i < len(src); i++ {
		c := src[i]
		visible := false
		switch p.classes[i] {
		case classCode, classTag:
			visible = true
		case classComment, classNonPHP:
			visible = false
		case classSQ:
			visible = kind == viewBlob
		case classNowdoc:
			visible = kind == viewBlob
		case classDQ, classHeredoc:
			visible = kind == viewRuntime || kind == viewBlob
		case classBacktick:
			visible = false
		}
		if !visible {
			if c == btNL {
				c = btNL
			} else {
				c = btSpace
			}
		}
		if c == 0 {
			// Null bytes never participate in pattern matching; blanking
			// them keeps binary garbage from producing pseudo-matches.
			c = btSpace
		}
		out[i+1] = c
	}
	return out
}
