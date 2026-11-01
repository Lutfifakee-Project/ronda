// Package analyzer performs read-only static analysis of PHP source files.
//
// RONDA never executes scanned PHP. This package reads bytes and matches
// structural signals. A dangerous function name alone is never treated as
// malware: findings require combinations of behaviour and are always reported
// with evidence so an operator can judge them.
//
// Files are classified before analysis (classify.go): genuine PHP source,
// PHP source with embedded binary data, binary resources that merely carry a
// PHP opening tag, text documentation and unknown formats are handled
// differently, and signals are matched against lexical views (lexview.go) so
// that names inside comments, string literals or binary garbage cannot
// produce invocation evidence.
package analyzer

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// MaxAnalyzeBytes caps how much of a file is inspected.
const MaxAnalyzeBytes = 2 * 1024 * 1024

// maxSignalMatches caps how many matches of one signal are inspected when
// separating invocations from definitions. The first matches in file order
// decide; deterministic and bounded.
const maxSignalMatches = 64

// Character fragments are built from code points so the source contains no
// fragile characters inside string literals.
var (
	dollar   = string(rune(36))
	star     = string(rune(42))
	under    = string(rune(95))
	bslash   = string(rune(92))
	sq       = string(rune(39))
	dq       = string(rune(34))
	quotes   = sq + dq
	dollarRE = bslash + dollar
)

func rx(parts ...string) *regexp.Regexp {
	return regexp.MustCompile(strings.Join(parts, ""))
}

var (
	ws          = "[[:space:]]" + star
	open        = "[(]"
	superglobal = dollarRE + under + "?(?:POST|GET|REQUEST|COOKIE|SERVER|FILES)"
	// idBoundary refuses an identifier byte immediately before a call-shaped
	// signal, so "curl_exec(" can never satisfy the bare "exec(" pattern and
	// "shellexec(" can never satisfy "exec(". The lexical views carry one
	// sentinel space at offset 0, so a call at the very start of the file
	// still has a boundary byte.
	idBoundary = "[^A-Za-z0-9" + bslash + dollar + "_]"
)

// signalScope selects the lexical view a signal is matched against.
type signalScope uint8

const (
	scopeCode    signalScope = iota // invocation position only
	scopeRuntime                    // code plus interpolating strings
	scopeBlob                       // code plus all string bodies
)

type signal struct {
	name     string
	re       *regexp.Regexp
	severity finding.Severity
	weight   int
	why      string
	scope    signalScope
	// boundary marks call-shaped patterns whose match starts with one
	// identifier-boundary byte; the function name begins one byte later.
	boundary bool
}

// decodeSignals are obfuscation primitives, common in legitimate code; each
// carries low weight. They match only in code position: documentation,
// comments and string contents are not invocations.
var decodeSignals = []signal{
	{"eval", rx(idBoundary, "eval", ws, open), finding.Medium, 2, "dynamic code execution via eval()", scopeCode, true},
	// assert() is split by argument kind. PHP's assert() only evaluates a
	// STRING argument as PHP code (deprecated since PHP 7.2, removed
	// semantics in PHP 8), so the static signal must distinguish what the
	// argument is: a quoted string is definitely code; a direct superglobal
	// read is user-controlled input reaching that path; a bare variable
	// could hold a string at runtime; a boolean expression such as
	// assert(count($parts) >= 2) can never evaluate as code and is benign.
	{"assert_string", rx(idBoundary, "assert", ws, open, ws, "[", quotes, "]"), finding.Medium, 2, "assert() with a string argument evaluates it as PHP code (deprecated since PHP 7.2)", scopeCode, true},
	{"assert_superglobal", rx(idBoundary, "assert", ws, open, ws, superglobal), finding.Critical, 5, "assert() evaluates user-controlled input as PHP code", scopeCode, true},
	{"assert_dynamic", rx(idBoundary, "assert", ws, open, ws, dollarRE, "[A-Za-z_][A-Za-z0-9_]*", ws, "[),]"), finding.Low, 1, "assert() with a bare variable argument may evaluate it as PHP code when it holds a string", scopeCode, true},
	{"base64_decode", rx(idBoundary, "base64_decode", ws, open), finding.Low, 1, "base64 decoding is commonly used to hide payloads", scopeCode, true},
	{"gzinflate", rx(idBoundary, "gzinflate", ws, open), finding.Low, 1, "compressed payload expansion", scopeCode, true},
	{"gzuncompress", rx(idBoundary, "gzuncompress", ws, open), finding.Low, 1, "compressed payload expansion", scopeCode, true},
	{"str_rot13", rx(idBoundary, "str_rot13", ws, open), finding.Low, 1, "string obfuscation via ROT13", scopeCode, true},
	{"create_function", rx(idBoundary, "create_function", ws, open), finding.Medium, 2, "runtime function creation", scopeCode, true},
}

// behaviorSignals are shell, network and file-write behaviours. Weights are kept
// below the decision threshold so a single generic call never fires alone.
var behaviorSignals = []signal{
	{"shell_exec", rx(idBoundary, "(?:shell_exec|passthru|system|exec|popen|proc_open)", ws, open), finding.Medium, 2, "operating-system command execution", scopeCode, true},
	// remote_fetch and write_php keep their original whole-file matching
	// breadth by using the blob view: their argument text (URL schemes,
	// ".php" targets) lives inside string literals of any quote style, and
	// narrowing them to interpolating strings would weaken existing
	// detection. Only comments and inline HTML are excluded.
	{"remote_fetch", rx(idBoundary, "(?:file_get_contents|fopen|curl_exec|fsockopen)", ws, open, ws, "", quotes, "://"), finding.Medium, 2, "remote payload retrieval", scopeBlob, true},
	{"write_php", rx(idBoundary, "f(?:write|puts)", ws, open, "."+star+"?[.]php"), finding.Medium, 2, "writes PHP files at runtime", scopeBlob, true},
	{"request_input", rx(dollarRE, under, "?(?:POST|GET|REQUEST|COOKIE|SERVER|FILES)"), finding.Info, 1, "reads user-controlled input", scopeRuntime, false},
	// extract/parse_str of request input injects arbitrary variables; the
	// correlation engine decides whether a sink is reachable, this signal
	// keeps the primitive itself visible.
	{"variable_injection", rx(idBoundary, "(?:extract|parse_str|mb_parse_str)", ws, open), finding.Info, 1, "variable injection primitive (extract/parse_str)", scopeCode, true},
}

// webshellSignals are strong, specific indicators of an interactive backdoor.
var webshellSignals = []signal{
	{"superglobal_eval", rx(idBoundary, "eval", ws, open, ws, superglobal), finding.Critical, 5, "evaluates user-controlled input", scopeCode, true},
	{"superglobal_shell", rx(idBoundary, "(?:system|exec|shell_exec|passthru)", ws, open, ws, superglobal), finding.Critical, 5, "runs user-controlled shell commands", scopeCode, true},
	{"encoded_eval", rx(idBoundary, "eval", ws, open, ws, "(?:base64_decode|gzinflate|str_rot13|gzuncompress)"), finding.Critical, 5, "evaluates a decoded blob", scopeCode, true},
	{"long_base64", rx("[", quotes, "][A-Za-z0-9+/]{300,}[", quotes, "]"), finding.Medium, 2, "large embedded base64 blob", scopeBlob, false},
	// dynamic_ref preserves the obfuscation visibility that raw string
	// matching incidentally provided: a dangerous function name stored as a
	// complete quoted literal is how dynamic dispatch hides a call from
	// call-position analysis. Capability probes (function_exists and
	// friends) are excluded by definitionSite-style context checks below.
	{"dynamic_ref", rx("[", quotes, "](?:base64_decode|gzinflate|gzuncompress|str_rot13|shell_exec|passthru|system|exec|popen|proc_open|file_get_contents|fsockopen|create_function)[", quotes, "]"), finding.Info, 1, "dangerous function name as a quoted string literal (possible dynamic dispatch)", scopeBlob, false},
}

// capabilityProbes are functions whose string arguments legitimately name
// other functions; a quoted name inside them is not dispatch evidence.
var capabilityProbes = []string{
	"function_exists(",
	"method_exists(",
	"is_callable(",
	"class_exists(",
}

// pregReplaceE needs the /e modifier inside a string literal of any quote
// style, so it matches the blob view; a definition context is impossible for
// it.
var pregReplaceESignal = signal{
	"preg_replace_e",
	rx(idBoundary, "preg_replace", ws, open, ws, "[", quotes, "][^", quotes, "]+[/]e"),
	finding.High, 3, "preg_replace with the /e modifier executes code", scopeBlob, true,
}

// phpOpen matches the PHP opening tags RONDA treats as analyzable PHP source:
// the canonical tag ("<?php") and the short echo tag ("<?="), which the PHP
// manual defines as shorthand for "<?php echo" and which is always available,
// independent of the short_open_tag ini setting, since PHP 5.4. The legacy
// short tag ("<?" followed by anything else) is deliberately not matched: it
// only works when short_open_tag is enabled and that is disabled by default,
// so a file whose only opening tags are the legacy tag is not analyzable PHP.
var phpOpen = rx("[<][?](?:php|=)")

type fileSignal struct {
	path     string
	score    int
	count    int
	severity finding.Severity
	reasons  []string
	matchAt  int // view index of the strongest matched signal, -1 when none
	// bestSev/bestWeight carry the strength of the evidence at matchAt so
	// the aggregate line points at the strongest security evidence
	// (severity first, then weight, then earliest position).
	bestSev    finding.Severity
	bestWeight int
}

// AnalyzeFile inspects one PHP file on disk.
func AnalyzeFile(path string) ([]finding.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, MaxAnalyzeBytes)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}
	return AnalyzeBytes(path, buf[:n]), nil
}

// AnalyzeBytes inspects already-loaded PHP source. It never touches the disk,
// which makes it the entry point for tests that must avoid writing known-malware
// signatures to the filesystem.
func AnalyzeBytes(path string, src []byte) []finding.Finding {
	if len(src) < 6 {
		return nil
	}
	hasTag := phpOpen.Match(src)
	hasNUL := bytes.IndexByte(src, 0) >= 0
	if !hasTag && !hasNUL {
		// No PHP opening tag and no binary marker: text documentation or a
		// non-executable file. It cannot run as PHP; nothing to analyze.
		return nil
	}

	prof := profileLex(src)
	cls, st, ps := classifyFromProfile(src, prof)

	switch cls {
	case classTextDoc, classBinaryResource:
		// Text documentation cannot run as PHP. A binary resource without a
		// real PHP opening tag (or with only accidental tag bytes inside the
		// garbage) must not be parsed as PHP source either — signal matching
		// over binary garbage yields garbage, so nothing runs and nothing is
		// claimed. When the file does carry an opening tag the uncertainty
		// is reported as an UNVERIFIED classification instead of silence.
		if cls == classBinaryResource && hasTag {
			return []finding.Finding{{
				Status:   finding.Unverified,
				Severity: finding.Low,
				Title:    "Binary resource with PHP opening tag",
				Path:     path,
				Rule:     "php-binary-resource",
				Line:     lineOfSource(src, st.firstNULAt),
				Evidence: fmt.Sprintf(
					"file carries PHP opening tag bytes but only %d of %d code-position bytes are printable (ratio %.2f); "+
						"no analyzable PHP structure, so the content was not parsed as PHP source; "+
						"nul bytes: %d; classification uncertain, not proven clean",
					ps.codePrintable, ps.codeBytes, ps.printableRatio, st.nulTotal),
			}}
		}
		return nil
	}

	// PHP structure is present: build the lexical views and score signals.
	codeView := buildView(src, prof, viewCode)
	runtimeView := buildView(src, prof, viewRuntime)
	blobView := buildView(src, prof, viewBlob)
	views := [3][]byte{codeView, runtimeView, blobView}

	fs := &fileSignal{path: path, matchAt: -1, severity: finding.Info}
	scoreGroup(views, decodeSignals, fs)
	scoreGroup(views, behaviorSignals, fs)
	scoreGroup(views, webshellSignals, fs)
	scoreSignal(views, pregReplaceESignal, fs)

	bt := backtickFindings(path, src)

	out := make([]finding.Finding, 0, 2+len(bt))
	switch cls {
	case classPHPWithEmbeddedBinary:
		// Real PHP source whose string literals contain binary data (the
		// Symfony character-set table pattern). Report the embedded data
		// honestly at low severity and keep analyzing the PHP sections —
		// a tampered table must still surface its injected code.
		out = append(out, finding.Finding{
			Status:   finding.Suspicious,
			Severity: finding.Low,
			Title:    "PHP file contains embedded binary data",
			Path:     path,
			Rule:     "php-embedded-binary",
			Line:     lineOfSource(src, firstEvidenceIndex(st)),
			Evidence: fmt.Sprintf(
				"%d nul bytes and %d non-text bytes inside string literals or comments, %d nul bytes in code position; "+
					"classified as PHP source with embedded non-text data (e.g. character-set tables); "+
					"PHP sections remain analyzed; embedded data alone is not a malware indicator",
				st.nulInString, st.nonTextInString, st.nulInCode),
			Category: "POLYGLOT_OR_BINARY_ANOMALY",
		})
	case classPHPWithAppendedBinary:
		// Real PHP source plus substantial non-text data OUTSIDE the PHP
		// regions (typically after the closing tag): the Phase 3.2 known
		// limitation, now reported conservatively instead of silently
		// accepted. The PHP sections stay fully analyzed.
		out = append(out, finding.Finding{
			Status:   finding.Unverified,
			Severity: finding.Low,
			Title:    "PHP source with appended non-text data",
			Path:     path,
			Rule:     "php-appended-binary",
			Line:     lineOfSource(src, firstEvidenceIndex(st)),
			Evidence: fmt.Sprintf(
				"%d non-text bytes outside the PHP regions (%.1f%% of the %d inline bytes); "+
					"the appended data is not parsed as code and the PHP sections remain fully analyzed; "+
					"polyglot indicator, classification uncertain, not proven clean",
				st.nonTextInHTML, appendedHTMLShare(st), st.nonPHPBytes),
			Category: "POLYGLOT_OR_BINARY_ANOMALY",
		})
	case classUnknown:
		// NUL bytes in code position: malformed, truncated or deliberately
		// obfuscated PHP. The original binary-data detection strength is
		// preserved, with a more precise evidence line, and analysis
		// continues so recoverable PHP code is still inspected.
		out = append(out, finding.Finding{
			Status:   finding.Suspicious,
			Severity: finding.High,
			Title:    "PHP file contains binary data",
			Path:     path,
			Rule:     "php-binary-data",
			Line:     lineOfSource(src, st.firstNULAt),
			Evidence: fmt.Sprintf(
				"%d nul bytes in code position or inline HTML, %d non-text bytes in code position, %d inside string literals; "+
					"malformed or obfuscated PHP source; analysis continued over the readable PHP sections",
				st.nulInCode, st.nonTextInCode, st.nulInString),
			Category: "POLYGLOT_OR_BINARY_ANOMALY",
		})
	}

	// Phase 4 correlation runs on EVERY analyzed PHP source file, not only
	// on files reaching the aggregate threshold: a single request-to-sink
	// flow is reportable even when the individual signals are weak. The
	// correlation engine deduplicates internally and caps its own output.
	flow := correlate(path, src, prof)

	if fs.severity != finding.Critical {
		if fs.count < 2 || fs.score < 3 {
			out = append(out, bt...)
			return append(out, flow...)
		}
	}
	aggregate := finding.Finding{
		Status:   finding.Suspicious,
		Severity: fs.severity,
		Title:    "Suspicious PHP code",
		Path:     path,
		Rule:     "php-signals",
		Evidence: strings.Join(uniq(fs.reasons), "; "),
		Category: "BROAD_SIGNAL",
	}
	if fs.matchAt >= 0 {
		aggregate.Line = lineOfView(codeView, fs.matchAt)
	}
	out = append(out, aggregate)
	out = append(out, bt...)
	out = append(out, flow...)
	return out
}

// firstEvidenceIndex returns the source index of the first binary-evidence
// byte (NUL preferred, otherwise the first non-text byte) for Line metadata.
func firstEvidenceIndex(st binaryStats) int {
	if st.firstNULAt >= 0 {
		return st.firstNULAt
	}
	return st.firstNonTextAt
}

// scoreGroup scores one signal group against the lexical views.
func scoreGroup(views [3][]byte, group []signal, fs *fileSignal) {
	for i := 0; i < len(group); i++ {
		scoreSignal(views, group[i], fs)
	}
}

// scoreSignal evaluates a single signal. Call-shaped boundary signals are
// separated into invocations and definitions: a match directly preceded by
// the "function" keyword records an informational capability_definition
// instead of the invocation signal, because a definition alone is a
// capability, not an executed behaviour.
func scoreSignal(views [3][]byte, s signal, fs *fileSignal) {
	view := views[s.scope]
	if !s.boundary {
		locs := s.re.FindAllIndex(view, maxSignalMatches)
		for _, loc := range locs {
			if isCapabilityProbe(view, loc[0]) {
				continue
			}
			record(s, loc[0], fs)
			return
		}
		return
	}
	locs := s.re.FindAllIndex(view, maxSignalMatches)
	if len(locs) == 0 {
		return
	}
	firstCall := -1
	for _, loc := range locs {
		nameStart := loc[0] + 1 // skip the identifier-boundary byte
		if isDefinitionSite(view, nameStart) {
			continue
		}
		if firstCall < 0 {
			firstCall = loc[0]
		}
	}
	if firstCall >= 0 {
		// firstCall is the boundary byte; the call name starts one byte
		// later, and line numbers must point at the call itself.
		record(s, firstCall+1, fs)
		return
	}
	// Every match is a definition: honest capability note, low weight.
	defs := uniqNames(views, s, locs)
	if len(defs) == 0 {
		return
	}
	fs.score++
	fs.count++
	fs.reasons = append(fs.reasons,
		"capability_definition: dangerous function name defined (not invoked here): "+strings.Join(defs, ", "))
	fs.severity = maxSeverity(fs.severity, finding.Info)
	if fs.matchAt < 0 || locs[0][0]+1 < fs.matchAt {
		fs.matchAt = locs[0][0] + 1
	}
}

// record applies one non-definition signal hit.
func record(s signal, at int, fs *fileSignal) {
	fs.score += s.weight
	fs.count++
	fs.reasons = append(fs.reasons, s.name+": "+s.why)
	fs.severity = maxSeverity(fs.severity, s.severity)
	// Primary evidence line selection (Phase 4 §8): the aggregate line must
	// point at the strongest security evidence, not the earliest match.
	// Strength ordering: severity rank first, then signal weight, then the
	// earliest position among equally strong evidence (deterministic).
	if fs.matchAt < 0 ||
		s.severity.Rank() > fs.bestSev.Rank() ||
		(s.severity.Rank() == fs.bestSev.Rank() && s.weight > fs.bestWeight) {
		fs.matchAt = at
		fs.bestSev = s.severity
		fs.bestWeight = s.weight
	}
}

// isCapabilityProbe reports whether the quoted string starting at quoteIdx
// sits inside a function_exists()/method_exists()/is_callable() argument.
func isCapabilityProbe(view []byte, quoteIdx int) bool {
	lo := quoteIdx - 64
	if lo < 0 {
		lo = 0
	}
	window := view[lo:quoteIdx]
	for _, probe := range capabilityProbes {
		if bytes.HasSuffix(bytes.TrimRight(window, " \t\n\r"), []byte(probe)) {
			return true
		}
	}
	return false
}

// uniqNames extracts the defined function names from definition matches.
func uniqNames(views [3][]byte, s signal, locs [][]int) []string {
	seen := make(map[string]bool, len(locs))
	out := make([]string, 0, len(locs))
	for _, loc := range locs {
		start := loc[0] + 1
		end := start
		for end < len(views[s.scope]) && isIdentByte(views[s.scope][end]) {
			end++
		}
		name := string(views[s.scope][start:end])
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

func maxSeverity(a, b finding.Severity) finding.Severity {
	if b.Rank() > a.Rank() {
		return b
	}
	return a
}

// lineOfSource converts a source index into a 1-based line number.
func lineOfSource(src []byte, idx int) int {
	if idx < 0 {
		return 0
	}
	if idx >= len(src) {
		idx = len(src) - 1
	}
	return 1 + bytes.Count(src[:idx], []byte{btNL})
}

func uniq(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for i := 0; i < len(in); i++ {
		if seen[in[i]] {
			continue
		}
		seen[in[i]] = true
		out = append(out, in[i])
	}
	return out
}

// IsPHP reports whether a path looks like a PHP source file.
func IsPHP(path string) bool {
	e := strings.ToLower(path)
	return strings.HasSuffix(e, ".php") ||
		strings.HasSuffix(e, ".phtml") ||
		strings.HasSuffix(e, ".php5") ||
		strings.HasSuffix(e, ".php7")
}
