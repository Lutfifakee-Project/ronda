package analyzer

import (
	"bytes"
	"unicode/utf8"
)

// classify.go turns the lexical profile into the five file classes RONDA
// distinguishes:
//
//      ClassPHPSource             — analyzable PHP without binary data.
//      ClassPHPWithEmbeddedBinary — real PHP source whose string literals (or
//                                   comments) contain NUL bytes, e.g. Symfony
//                                   character-set tables. The PHP sections stay
//                                   analyzable; the binary data is reported as
//                                   an embedded-data note, not as malware.
//      ClassBinaryResource        — a file that carries a PHP opening tag but has
//                                   no meaningful PHP structure; most likely a
//                                   binary resource with accidental PHP-like
//                                   bytes. Never parsed as PHP source.
//      ClassTextDoc               — text documentation without any PHP opening
//                                   tag; not executable PHP, nothing to analyze.
//      ClassUnknown               — PHP structure present but NUL bytes appear in
//                                   code position or inline HTML; the file is
//                                   malformed, truncated or deliberately
//                                   obfuscated. Reported with the full
//                                   binary-data severity and analyzed anyway.
//
// Classification never claims a file is clean: callers translate every
// non-PHPSource class into a finding whose status or severity reflects the
// residual uncertainty.

type fileClass uint8

const (
	classUnknown fileClass = iota
	classPHPSource
	classPHPWithEmbeddedBinary
	classPHPWithAppendedBinary
	classBinaryResource
	classTextDoc
)

func (c fileClass) String() string {
	switch c {
	case classPHPSource:
		return "php-source"
	case classPHPWithEmbeddedBinary:
		return "php-with-embedded-binary"
	case classPHPWithAppendedBinary:
		return "php-with-appended-binary"
	case classBinaryResource:
		return "binary-resource"
	case classTextDoc:
		return "text-document"
	}
	return "unknown"
}

// binaryStats records where NUL bytes and non-text bytes sit inside a
// classified file. Non-text means neither ASCII printable/whitespace nor part
// of a valid UTF-8 sequence: raw legacy-charset data (Big5, EBCDIC) and
// binary garbage. Valid UTF-8 text (Greek, Chinese, Arabic source files) is
// never counted as binary.
type binaryStats struct {
	nulTotal        int // all NUL bytes in the file
	nulInString     int // inside string literals or comments
	nulInCode       int // in code position or inline HTML (suspicious)
	nonTextTotal    int // all non-text bytes
	nonTextInString int // non-text bytes inside string literals or comments
	nonTextInCode   int // non-text bytes in code position or backticks
	nonTextInHTML   int // non-text bytes in inline HTML (outside PHP tags)
	nonPHPBytes     int // all inline-HTML bytes outside PHP regions
	firstNULAt      int // index of the first NUL byte, -1 when none
	firstNonTextAt  int // index of the first non-text byte, -1 when none
}

// phpStructureStats measures how much real PHP code a file carries.
type phpStructureStats struct {
	codeBytes      int     // bytes in code position (inside PHP regions)
	codePrintable  int     // printable code bytes (incl. whitespace)
	printableRatio float64 // codePrintable / codeBytes (1.0 when empty)
	structureIsPHP bool    // ratio and volume thresholds both met
}

// phpStructureMinBytes is the smallest amount of code-position bytes required
// before a file is credited with real PHP structure. The threshold stays low
// because legitimate PHP templates can be tiny; the printable-ratio test does
// the real work of rejecting binary garbage (random bytes are only ~37%
// printable, real PHP code is ~100%).
const phpStructureMinBytes = 4

// phpStructureMinRatio is the minimum printable share of the code-position
// bytes for a file to count as PHP source. Random binary garbage around an
// accidental "<?php" stays far below it.
const phpStructureMinRatio = 0.80

func isPrintableByte(c byte) bool {
	return (c >= 32 && c <= 126) || c == btNL || c == btTab || c == byte(13)
}

// classifyBytes profiles src and returns one of the five classes plus the
// binary and structure statistics that justify the decision. It is the
// convenience entry point used by tests; AnalyzeBytes reuses a single lexical
// profile through classifyFromProfile.
func classifyBytes(src []byte) (fileClass, binaryStats, phpStructureStats) {
	return classifyFromProfile(src, profileLex(src))
}

// classifyFromProfile applies the classification rules over an existing
// lexical profile:
//
//   - no PHP opening tag and no NUL             -> TextDoc
//   - no PHP opening tag, mostly binary         -> BinaryResource
//     (a PHP-named file that is really a binary blob; it cannot execute)
//   - real PHP structure + NUL in code position -> Unknown
//   - real PHP structure + NUL in strings only  -> PHPWithEmbeddedBinary
//   - tag without PHP structure + binary evidence -> BinaryResource
//   - tag without PHP structure, all text        -> PHPSource (tiny stub)
//   - everything else                            -> PHPSource
func classifyFromProfile(src []byte, prof lexProfile) (fileClass, binaryStats, phpStructureStats) {
	st := binaryStats{firstNULAt: -1}

	text := utf8TextBytes(src)
	for i := 0; i < len(src); i++ {
		c := src[i]
		isText := isPrintableByte(c) || text[i]
		switch prof.classes[i] {
		case classSQ, classDQ, classHeredoc, classNowdoc, classComment:
			if c == 0 {
				if st.nulTotal == 0 {
					st.firstNULAt = i
				}
				st.nulTotal++
				st.nulInString++
			} else if !isText {
				if st.nonTextTotal == 0 {
					st.firstNonTextAt = i
				}
				st.nonTextTotal++
				st.nonTextInString++
			}
		case classCode:
			if c == 0 {
				if st.nulTotal == 0 {
					st.firstNULAt = i
				}
				st.nulTotal++
				st.nulInCode++
			} else if !isText {
				if st.nonTextTotal == 0 {
					st.firstNonTextAt = i
				}
				st.nonTextTotal++
				st.nonTextInCode++
			}
		case classNonPHP:
			// Inline HTML outside the PHP regions: NUL bytes keep the
			// historical nulInCode treatment (code position or inline HTML),
			// non-text bytes are counted separately so appended binary data
			// after a closing tag can be reported conservatively without
			// confusing it with malformed code.
			st.nonPHPBytes++
			if c == 0 {
				if st.nulTotal == 0 {
					st.firstNULAt = i
				}
				st.nulTotal++
				st.nulInCode++
			} else if !isText {
				if st.nonTextTotal == 0 {
					st.firstNonTextAt = i
				}
				st.nonTextTotal++
				st.nonTextInHTML++
			}
		case classBacktick:
			// Backtick bodies are code-adjacent command strings.
			if c == 0 {
				if st.nulTotal == 0 {
					st.firstNULAt = i
				}
				st.nulTotal++
				st.nulInCode++
			} else if !isText {
				if st.nonTextTotal == 0 {
					st.firstNonTextAt = i
				}
				st.nonTextTotal++
				st.nonTextInCode++
			}
		}
	}

	// PHP structure is judged on code-position bytes only: string literals
	// may legitimately carry binary data (charset tables), so they must not
	// lower the structure verdict. Comment-only files are real PHP through
	// the default branch below; binary garbage after an accidental tag has
	// a printable share near 37% and fails the ratio test.
	ps := phpStructureStats{}
	for i := 0; i < len(src); i++ {
		if prof.classes[i] == classCode {
			ps.codeBytes++
			if isPrintableByte(src[i]) || text[i] {
				ps.codePrintable++
			}
		}
	}
	if ps.codeBytes > 0 {
		ps.printableRatio = float64(ps.codePrintable) / float64(ps.codeBytes)
	}
	ps.structureIsPHP = ps.codeBytes >= phpStructureMinBytes && ps.printableRatio >= phpStructureMinRatio

	hasTag := prof.inPHP

	switch {
	case !hasTag && st.nulTotal == 0:
		return classTextDoc, st, ps
	case !hasTag:
		// A PHP-named file without any opening tag cannot execute as PHP:
		// text documentation when it is mostly text, otherwise a binary
		// resource. Neither produces findings (the historical behavior for
		// untagged files is preserved).
		if ps.printableRatio >= phpStructureMinRatio {
			return classTextDoc, st, ps
		}
		return classBinaryResource, st, ps
	case ps.structureIsPHP:
		// Real PHP content. The position of the binary evidence decides.
		if st.nulInCode > 0 || nonTextShareInCode(st, ps) {
			// NUL bytes anywhere in code position, or substantial non-text
			// bytes in code position: malformed, truncated or deliberately
			// obfuscated PHP (closes the Phase 3.2 non-NUL limitation).
			// The share test matters because legacy multi-byte encodings
			// desync the string lexer (a 0x5C follow byte escapes the
			// closing quote) and scatter a few non-text bytes into code
			// position: measured 11 bytes / 2.8% on a 40-row Big5 table.
			// Genuinely appended binary is far above both thresholds.
			return classUnknown, st, ps
		}
		if st.nulInString > 0 || nonTextShareInStrings(st, ps) {
			return classPHPWithEmbeddedBinary, st, ps
		}
		if appendedBinarySignificant(st) {
			// Substantial non-text data outside the PHP regions: polyglot
			// indicator, reported conservatively, file stays fully
			// analyzed.
			return classPHPWithAppendedBinary, st, ps
		}
		return classPHPSource, st, ps
	default:
		// Tagged but below the structure threshold: binary evidence (NUL or
		// non-text bytes anywhere) makes it a binary resource. A tiny
		// all-text stub such as "<?php\n" is PHP source that simply has
		// nothing to analyze — historical behavior stays silent.
		if st.nulTotal > 0 || st.nonTextTotal > 0 {
			return classBinaryResource, st, ps
		}
		return classPHPSource, st, ps
	}
}

// nonTextStringShare is the minimum share of non-text bytes inside the PHP
// content before string-borne data alone classifies a file as PHP with
// embedded binary data. Scattered legacy-encoding characters in an otherwise
// ASCII file stay far below it and keep the historical silent behavior;
// genuine charset tables (raw Big5, EBCDIC) are far above it.
const nonTextStringShare = 0.05

func nonTextShareInStrings(st binaryStats, ps phpStructureStats) bool {
	if ps.codeBytes == 0 {
		return false
	}
	return float64(st.nonTextInString)/float64(ps.codeBytes) >= nonTextStringShare
}

// nonTextCodeShare is the minimum non-text share of the code-position
// bytes before non-NUL binary evidence raises the unknown class. It mirrors
// nonTextStringShare so both positions use the same evidentiary bar.
const nonTextCodeShare = 0.05

// nonTextCodeMinBytes is the absolute floor for code-position non-text
// bytes (mirrors appendedBinaryMinBytes).
const nonTextCodeMinBytes = 16

// nonTextShareInCode reports whether the non-text bytes in code position
// are substantial enough to classify the file as unknown/malformed.
func nonTextShareInCode(st binaryStats, ps phpStructureStats) bool {
	if ps.codeBytes == 0 {
		return false
	}
	return st.nonTextInCode >= nonTextCodeMinBytes &&
		float64(st.nonTextInCode)/float64(ps.codeBytes) >= nonTextCodeShare
}

// appendedBinaryShare is the minimum non-text share of the inline-HTML
// bytes before appended data counts as a polyglot indicator. A handful of
// stray legacy-encoding bytes in an old template stays far below it; raw
// appended binary is close to 100%.
const appendedBinaryShare = 0.05

// appendedBinaryMinBytes is the absolute floor: below this many non-text
// bytes the share test never fires, so single-byte mojibake is never
// reported.
const appendedBinaryMinBytes = 16

// appendedBinarySignificant reports whether the non-text bytes outside the
// PHP regions are substantial enough to report as appended binary data.
func appendedBinarySignificant(st binaryStats) bool {
	if st.nonTextInHTML < appendedBinaryMinBytes || st.nonPHPBytes == 0 {
		return false
	}
	return float64(st.nonTextInHTML)/float64(st.nonPHPBytes) >= appendedBinaryShare
}

// appendedHTMLShare returns the non-text percentage of the inline-HTML
// bytes for evidence strings (0 when there are no inline bytes).
func appendedHTMLShare(st binaryStats) float64 {
	if st.nonPHPBytes == 0 {
		return 0
	}
	return float64(st.nonTextInHTML) / float64(st.nonPHPBytes) * 100
}

// utf8TextBytes marks every byte that belongs to a valid UTF-8 multi-byte
// sequence. Text written in any UTF-8 language is therefore never treated as
// binary data; raw legacy-charset bytes and binary garbage stay unmarked.
func utf8TextBytes(src []byte) []bool {
	marks := make([]bool, len(src))
	n := len(src)
	for i := 0; i < n; {
		if src[i] < 0x80 {
			i++
			continue
		}
		r, size := utf8.DecodeRune(src[i:])
		if r == utf8.RuneError && size <= 1 {
			i++
			continue
		}
		for k := 0; k < size && i+k < n; k++ {
			marks[i+k] = true
		}
		i += size
	}
	return marks
}

// lineOfView converts a view index (views carry one sentinel byte at offset 0)
// into a 1-based source line number.
func lineOfView(view []byte, idx int) int {
	if idx <= 0 {
		return 1
	}
	if idx >= len(view) {
		idx = len(view) - 1
	}
	return 1 + bytes.Count(view[1:idx], []byte{btNL})
}

// isDefinitionSite reports whether the code position just before the match at
// viewIdx is the `function` keyword, i.e. the match is a function definition
// rather than a call. Whitespace between the keyword and the name is skipped.
func isDefinitionSite(view []byte, nameStart int) bool {
	i := nameStart - 1 // view[nameStart-1] is the boundary byte
	for i > 0 && (view[i] == btSpace || view[i] == btNL || view[i] == btTab || view[i] == byte(13)) {
		i--
	}
	if i < 8 {
		return false
	}
	end := i + 1
	start := end - 8
	if view[start] != 102 { // 'f'
		return false
	}
	if string(view[start:end]) != "function" {
		return false
	}
	// The character before the keyword must not extend an identifier
	// (e.g. "macrofunction" would be a different name).
	if start-1 > 0 && isIdentByte(view[start-1]) {
		return false
	}
	return true
}
