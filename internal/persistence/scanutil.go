package persistence

import (
	"regexp"
	"strings"
)

// CommandTraits summarizes the static, execution-relevant characteristics of
// a command line found in a persistence artifact. Nothing here is ever run.
type CommandTraits struct {
	// URLs mentioned in the command.
	URLs []string
	// Downloaders present (curl, wget, fetch, python urllib, nc).
	Downloads bool
	// PipeIntoExec reports a fetch piped or chained into a shell/interpreter.
	PipeIntoExec bool
	// ChainedExec reports `cmd1 && cmd2`-style execution of a second stage
	// after a download or decode.
	ChainedExec bool
	// Encoded reports base64/xxd/openssl decode feeding an interpreter.
	Encoded bool
	// Interpreter is the shell or language interpreter invoked, if any.
	Interpreter string
	// Paths lists absolute or home-relative paths referenced by the command.
	Paths []string
	// HiddenPaths lists referenced paths with dot-prefixed components that
	// are not well-known tooling directories.
	HiddenPaths []string
	// WritablePaths lists referenced paths inside temporary or writable
	// locations (/tmp, /var/tmp, /dev/shm, /run/shm, world-writable dirs
	// found on disk).
	WritablePaths []string
	// HomePaths lists referenced paths inside a user home directory.
	HomePaths []string
	// ReverseShell reports /dev/tcp-style interactive shell redirection.
	ReverseShell bool
	// Paths the command WRITES output to (-O/-o/--output downloader flags,
	// `>` redirections, tee). Recorded for write-then-exec correlation;
	// a write alone is never a finding.
	Writes []string
	// ExecPath is the inspectable primary execution target: the first
	// executable token of a plain command, or of the innermost supported
	// `sh -c` payload. Absolute and home-relative paths are kept verbatim;
	// PATH-resolved bare names return "" because they cannot be inspected
	// statically.
	ExecPath string
	// Raw is the redacted command text (safe for evidence).
	Raw string
}

// Chain-analysis bounds (Phase 5 §3). Every limit keeps the static command
// analyzer bounded no matter how deeply a hostile artifact nests shell
// wrappers or how long the embedded strings are.
const (
	maxShellNestingDepth = 4        // `sh -c "bash -c ..."` levels analyzed
	maxEmbeddedCommand   = 16 << 10 // 16 KiB per embedded command string
	maxChainExtractions  = 32       // shell -c extractions per top-level command
	maxTraitPaths        = 32       // union cap for referenced paths per command
)

// posixShells are the shells whose `-c` invocation form RONDA extracts
// statically. Anything outside this set is analyzed as an opaque outer line.
var posixShells = []string{"sh", "bash", "dash", "zsh", "ksh", "ash"}

// chainBudget bounds the total work one top-level AnalyzeCommand call may
// spend on nested shell extraction.
type chainBudget struct {
	remaining int
}

var urlRe = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s'"<>|&;]{1,512}`)
var b64BlobRe = regexp.MustCompile(`[A-Za-z0-9+/]{48,}={0,2}`)

// downloadTokens are process names that fetch remote content.
var downloadTokens = []string{"curl", "wget", "fetch", "http_get", "nc", "netcat"}

// execInterpreters are shells and language interpreters a second stage can
// be chained into.
var execInterpreters = []string{"sh", "bash", "dash", "zsh", "ksh", "ash", "python", "python3", "perl", "ruby", "php", "powershell", "tcsh", "fish"}

// decodeTokens mark decoding of encoded payloads.
var decodeTokens = []string{"base64 -d", "base64 --decode", "base64 -D", "base64 -d0", "openssl enc -d", "xxd -r", "python -c 'import base64", "certutil -decode"}

// knownToolDotDirs are dot directories that legitimately contain
// executables sourced by startup files; they must not trigger hidden-path
// rules by themselves.
var knownToolDotDirs = []string{
	"/.nvm/", "/.sdkman/", "/.rbenv/", "/.pyenv/", "/.cargo/", "/.goenv/",
	"/.asdf/", "/.local/bin/", "/.npm-global/", "/.rvm/", "/.condabin/",
}

// tempPrefixes are locations where a referenced payload is user-writable by
// design and therefore untrusted for persistence execution.
var tempPrefixes = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/var/run/shm/"}

// pseudoDevices are sink targets that can never carry a payload: output
// redirection to them is disposal, not a write-then-exec primitive.
var pseudoDevices = []string{
	"/dev/null", "/dev/zero", "/dev/urandom", "/dev/random", "/dev/full",
	"/dev/tty", "/dev/stdout", "/dev/stderr", "/dev/stdin",
}

// isPseudoDevice reports whether p is a device or pseudo-filesystem
// location that never carries executable payload semantics.
func isPseudoDevice(p string) bool {
	for _, d := range pseudoDevices {
		if p == d {
			return true
		}
	}
	return strings.HasPrefix(p, "/proc/") || strings.HasPrefix(p, "/sys/") ||
		strings.HasPrefix(p, "/run/") || strings.HasPrefix(p, "/var/run/")
}

// splitCommandChain splits a shell command line on `&&`, `||` and `;`
// separators (quoted-aware) so each stage can be analyzed.
func splitCommandChain(cmd string) []string {
	var parts []string
	var cur strings.Builder
	var quote byte
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			cur.WriteByte(c)
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			cur.WriteByte(c)
		case '&':
			if i+1 < len(cmd) && cmd[i+1] == '&' {
				parts = append(parts, cur.String())
				cur.Reset()
				i++
				continue
			}
			cur.WriteByte(c)
		case '|':
			if i+1 < len(cmd) && cmd[i+1] == '|' {
				parts = append(parts, cur.String())
				cur.Reset()
				i++
				continue
			}
			cur.WriteByte(c)
		case ';':
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	parts = append(parts, cur.String())
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// stripComment removes a shell-style trailing comment outside quotes and
// reports whether the remaining line is still non-empty.
func stripComment(line string) string {
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '#':
			if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
				return strings.TrimRight(line[:i], " \t")
			}
		}
	}
	return line
}

// firstWordTokens splits a command into whitespace-separated tokens.
func tokens(cmd string) []string {
	return strings.FieldsFunc(cmd, func(r rune) bool {
		return r == ' ' || r == '\t'
	})
}

// baseName returns the last path element of a token, stripping a leading
// "exec " or "env ".
func baseName(tok string) string {
	if i := strings.LastIndexAny(tok, "/"); i >= 0 {
		return tok[i+1:]
	}
	return tok
}

// normalizeCommandWord strips the quoting and shell-expansion wrappers a
// token can carry inside command substitutions ("$(curl ...), ${x}, (cmd)
// ...) and returns the bare command word.
func normalizeCommandWord(tok string) string {
	s := strings.Trim(tok, "\"'`")
	for changed := true; changed; {
		s = strings.TrimPrefix(s, "$(")
		s = strings.TrimPrefix(s, "${")
		s = strings.TrimPrefix(s, "$")
		s = strings.TrimPrefix(s, "(")
		s = strings.TrimSuffix(s, ")")
		s = strings.TrimSuffix(s, "}")
		s = strings.Trim(s, "\"'`")
		changed = strings.HasPrefix(s, "$") || strings.HasPrefix(s, "(") ||
			strings.HasSuffix(s, ")") || strings.ContainsAny(s[:min(len(s), 1)], "\"'`$")
	}
	return baseName(s)
}

// min returns the smaller of two ints.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// AnalyzeCommand statically classifies a command line. The command is never
// executed and its text is redacted before storage. Shell `-c` wrappers are
// extracted and analyzed recursively within the chain-analysis bounds;
// unsupported syntax keeps the outer-line result.
func AnalyzeCommand(cmd string) CommandTraits {
	budget := &chainBudget{remaining: maxChainExtractions}
	return analyzeCommand(cmd, 0, budget)
}

func analyzeCommand(cmd string, depth int, budget *chainBudget) CommandTraits {
	redacted := RedactSecrets(cmd)
	t := CommandTraits{Raw: redacted}

	t.URLs = urlRe.FindAllString(cmd, 16)
	// A downloader token combined with a URL in the same command is a fetch,
	// wherever the token sits in the chain (sh -c "...", eval "$(...)").
	if len(t.URLs) > 0 {
		for _, tok := range tokens(cmd) {
			name := normalizeCommandWord(tok)
			for _, dl := range downloadTokens {
				if name == dl {
					t.Downloads = true
					break
				}
			}
			if t.Downloads {
				break
			}
		}
	}
	if !t.Downloads {
		for _, tok := range downloadTokens {
			if hasCommandToken(cmd, tok) {
				t.Downloads = true
				break
			}
		}
	}

	stages := splitCommandChain(cmd)
	pipeStages := splitPipes(cmd)
	// A pipe into a shell/interpreter: every stage AFTER the first whose
	// first executable token is an interpreter receives the pipe.
	for i := 1; i < len(pipeStages); i++ {
		w := firstExecutableToken(pipeStages[i])
		if isInterpreterWord(w) {
			t.PipeIntoExec = true
			if t.Interpreter == "" {
				t.Interpreter = w
			}
		}
	}
	// A single-stage `sh` (e.g. `curl ... > payload.sh; sh payload.sh` is a
	// chain, but a bare trailing interpreter with no input makes no sense)
	// is handled by the chain logic below.
	if !t.PipeIntoExec {
		// `bash -c "..."`, `sh -s`, `<(...)`, and download followed by a
		// second stage executing something.
		for _, stage := range stages {
			toks := tokens(stage)
			if len(toks) > 0 && isInterpreterWord(baseName(toks[0])) {
				if t.Interpreter == "" {
					t.Interpreter = baseName(toks[0])
				}
			}
		}
	}

	for _, dec := range decodeTokens {
		if strings.Contains(cmd, dec) {
			t.Encoded = true
			break
		}
	}
	// `echo <blob> | base64 -d` style is covered; also catch bare
	// `base64 -d` inside any stage feeding a pipe.
	if !t.Encoded {
		for _, stage := range pipeStages {
			if strings.Contains(stage, "base64") && (strings.Contains(stage, "-d") || strings.Contains(stage, "--decode")) {
				t.Encoded = true
				break
			}
		}
	}

	if t.Downloads && (t.PipeIntoExec || t.Encoded) {
		t.PipeIntoExec = true
	}
	if t.Downloads && len(stages) > 1 {
		// download && exec-something
		for _, stage := range stages[1:] {
			first := firstExecutableToken(stage)
			if first != "" && (isInterpreterWord(first) || strings.HasSuffix(first, ".sh")) {
				t.ChainedExec = true
				break
			}
		}
	}
	// `eval "$(curl ...)"`, `source <(wget -qO- ...)` and `. <(curl ...)`
	// are download-and-execute without a literal pipe to a shell.
	if t.Downloads && !t.PipeIntoExec {
		lower := strings.ToLower(cmd)
		if strings.Contains(lower, "eval ") || strings.Contains(lower, "eval(") ||
			strings.Contains(lower, "source <(") || strings.Contains(lower, ". <(") {
			t.PipeIntoExec = true
		}
	}
	if t.Encoded && t.PipeIntoExec {
		t.Encoded = true
	}

	// Path extraction from the raw (unredacted) command for target checks.
	// Quoted strings stay single tokens (quote-aware) so path fragments
	// inside documentation strings never become evidence.
	seen := make(map[string]bool, 8)
	for _, tok := range shellTokens(cmd) {
		tok = strings.Trim(tok, `"`+`'`+`"`)
		if tok == "" {
			continue
		}
		var logical string
		switch {
		case strings.HasPrefix(tok, "/"):
			logical = tok
		case strings.HasPrefix(tok, "~/"):
			logical = tok // home-relative, caller expands per user
		case strings.HasPrefix(tok, "$HOME/"):
			logical = "~/" + strings.TrimPrefix(tok, "$HOME/")
		default:
			continue
		}
		if !seen[logical] {
			seen[logical] = true
			t.Paths = append(t.Paths, logical)
			if isHiddenPath(logical) {
				t.HiddenPaths = append(t.HiddenPaths, logical)
			}
			if isTempPath(logical) {
				t.WritablePaths = append(t.WritablePaths, logical)
			}
			if strings.HasPrefix(logical, "~/") || strings.HasPrefix(logical, "/home/") || strings.HasPrefix(logical, "/root/") {
				t.HomePaths = append(t.HomePaths, logical)
			}
		}
	}

	if strings.Contains(cmd, "/dev/tcp/") || strings.Contains(cmd, "/dev/udp/") {
		t.ReverseShell = true
	}
	// nc -e /bin/sh and nc -c patterns are reverse-shell primitives.
	if !t.ReverseShell {
		lower := strings.ToLower(cmd)
		for _, nct := range []string{"nc ", "ncat ", "netcat "} {
			if strings.Contains(lower, nct) && (strings.Contains(lower, " -e ") || strings.Contains(lower, " -c ")) {
				t.ReverseShell = true
				break
			}
		}
	}

	// Write targets of this command line: downloader output flags, shell
	// redirections and tee arguments (quote-aware so strings never become
	// evidence).
	var writes []string
	seenWrite := make(map[string]bool, 4)
	for _, stage := range stages {
		for _, w := range append(scanRedirections(stage), downloaderOutputTargets(stage)...) {
			if w != "" && !seenWrite[w] && !isPseudoDevice(w) && len(writes) < maxTraitPaths {
				seenWrite[w] = true
				writes = append(writes, w)
			}
		}
		if w := teeOutputTarget(stage); w != "" && !seenWrite[w] && !isPseudoDevice(w) && len(writes) < maxTraitPaths {
			seenWrite[w] = true
			writes = append(writes, w)
		}
	}
	t.Writes = writes

	// Write-then-exec within one command line (Phase 5 §4): a download that
	// writes a file a later chain stage then executes is a fetch-and-run
	// chain even without a pipe. Static path equality only.
	if t.Downloads && !t.ChainedExec && chainStageExecutes(stages, t.Writes) {
		t.ChainedExec = true
	}

	// Primary inspectable execution target of this command line.
	t.ExecPath = firstExecutablePath(cmd)

	// Chained shell analysis (Phase 5 §3): extract `sh -c "<command>"`
	// payloads and analyze them with the same rules. Strictly bounded by
	// nesting depth, string size and an extraction budget; nothing is ever
	// executed and unsupported syntax keeps the outer-line result above.
	if depth < maxShellNestingDepth && budget.remaining > 0 {
		if inner, _, ok := extractShellCommand(cmd); ok && inner != "" && len(inner) <= maxEmbeddedCommand {
			budget.remaining--
			merged := analyzeCommand(inner, depth+1, budget)
			mergeTraits(&t, merged)
			// The wrapper shell (/bin/sh) is the runner, not the payload:
			// the inner command's inspectable target (if any) replaces it so
			// missing-target evidence never points at the wrapper.
			t.ExecPath = merged.ExecPath
		}
	}
	return t
}

// mergeTraits unions the traits of an embedded command into its wrapper.
// Evidence stays the outer redacted line, which already contains the inner
// text, so both the invocation and the payload remain visible.
func mergeTraits(dst *CommandTraits, src CommandTraits) {
	for _, u := range src.URLs {
		if len(dst.URLs) >= 32 {
			break
		}
		if !containsString(dst.URLs, u) {
			dst.URLs = append(dst.URLs, u)
		}
	}
	dst.Downloads = dst.Downloads || src.Downloads
	dst.PipeIntoExec = dst.PipeIntoExec || src.PipeIntoExec
	dst.ChainedExec = dst.ChainedExec || src.ChainedExec
	dst.Encoded = dst.Encoded || src.Encoded
	dst.ReverseShell = dst.ReverseShell || src.ReverseShell
	if dst.Interpreter == "" {
		dst.Interpreter = src.Interpreter
	}
	dst.Paths = unionStrings(dst.Paths, src.Paths)
	dst.HiddenPaths = unionStrings(dst.HiddenPaths, src.HiddenPaths)
	dst.WritablePaths = unionStrings(dst.WritablePaths, src.WritablePaths)
	dst.HomePaths = unionStrings(dst.HomePaths, src.HomePaths)
	dst.Writes = unionStrings(dst.Writes, src.Writes)
	if dst.ExecPath == "" {
		dst.ExecPath = src.ExecPath
	}
}

// unionStrings appends new elements up to the trait path cap.
func unionStrings(dst, src []string) []string {
	for _, s := range src {
		if len(dst) >= maxTraitPaths {
			return dst
		}
		if !containsString(dst, s) {
			dst = append(dst, s)
		}
	}
	return dst
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// isPosixShellName reports whether name is one of the explicitly supported
// shells whose -c form is extracted.
func isPosixShellName(name string) bool {
	for _, s := range posixShells {
		if name == s {
			return true
		}
	}
	return false
}

// shortFlagWithC matches single-dash flag clusters that turn a shell
// invocation into a command runner: -c, -lc, -cx. Long options (--rcfile,
// --command) deliberately do not match; they stay outer-line analysis.
var shortFlagWithC = regexp.MustCompile(`^-[a-zA-Z]*c[a-zA-Z]*$`)

// extractShellCommand recognizes `<shell> [flags] -c <command>` for the
// supported POSIX shells and returns the embedded command string. Quoted
// commands are unquoted once; unquoted commands are the single following
// token (everything after it would be positional parameters, not part of
// the command). Pathological quoting forms may be reconstructed
// imperfectly; they then simply keep the outer-line analysis.
func extractShellCommand(cmd string) (inner, shell string, ok bool) {
	toks := tokens(cmd)
	for i := 0; i < len(toks); i++ {
		name := baseName(strings.Trim(toks[i], `"'`))
		if !isPosixShellName(name) {
			continue
		}
		for j := i + 1; j < len(toks); j++ {
			flag := strings.Trim(toks[j], `"'`)
			if !strings.HasPrefix(flag, "-") {
				break // non-flag argument before -c: not a -c invocation
			}
			if !shortFlagWithC.MatchString(flag) {
				continue // -l, -x, ... before -c
			}
			// Found the -c flag; the next token begins the command.
			if j+1 >= len(toks) {
				return "", "", false
			}
			rest := toks[j+1:]
			first := rest[0]
			trimmedFirst := strings.Trim(first, `"'`)
			if first[0] == '"' || first[0] == '\'' {
				qc := first[0]
				parts := []string{first}
				// A complete quoted string closes within its first token; otherwise
				// tokens are collected until the closing quote appears.
				if !(len(first) >= 2 && first[len(first)-1] == qc) {
					closed := false
					for _, tok := range rest[1:] {
						parts = append(parts, tok)
						if strings.HasSuffix(tok, string(qc)) {
							closed = true
							break
						}
					}
					if !closed {
						return "", "", false // unterminated quote: unsupported
					}
				}
				joined := strings.Join(parts, " ")
				inner = strings.Trim(joined, string(qc))
				return inner, name, inner != ""
			}
			// Unquoted: only the first token is the command string.
			return trimmedFirst, name, trimmedFirst != ""
		}
	}
	return "", "", false
}

// scanRedirections extracts `>` and `>>` redirect targets from a command
// stage, honoring quotes so string contents never become evidence. Only
// absolute paths are returned; fd duplication (2>&1) and /dev/null-style
// targets are returned like any other path — whether anything EXECUTES a
// written path is decided by chainStageExecutes.
func scanRedirections(stage string) []string {
	var out []string
	var quote byte
	for i := 0; i < len(stage); i++ {
		c := stage[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '>':
			j := i + 1
			if j < len(stage) && stage[j] == '>' {
				j++
			}
			if j < len(stage) && stage[j] == '&' {
				i = j // fd duplication, not a file write
				continue
			}
			for j < len(stage) && (stage[j] == ' ' || stage[j] == '\t') {
				j++
			}
			start := j
			for j < len(stage) && stage[j] != ' ' && stage[j] != '\t' {
				j++
			}
			if start < j {
				if p := strings.Trim(stage[start:j], `"'`); strings.HasPrefix(p, "/") {
					out = append(out, p)
				}
			}
			i = j - 1
		}
	}
	return out
}

// downloaderOutputTargets extracts paths passed to downloader output flags
// (-O, -o, --output, --output-document, --output=path) in one stage.
func downloaderOutputTargets(stage string) []string {
	var out []string
	toks := tokens(stage)
	for i, tok := range toks {
		clean := strings.Trim(tok, `"'`)
		switch {
		case clean == "-O" || clean == "-o" || clean == "--output" || clean == "--output-document":
			if i+1 < len(toks) {
				if p := strings.Trim(toks[i+1], `"'`); strings.HasPrefix(p, "/") {
					out = append(out, p)
				}
			}
		case strings.HasPrefix(clean, "--output="):
			if p := strings.TrimPrefix(clean, "--output="); strings.HasPrefix(p, "/") {
				out = append(out, p)
			}
		}
	}
	return out
}

// teeOutputTarget returns the first absolute file operand of a `tee`
// invocation, or "".
func teeOutputTarget(stage string) string {
	toks := tokens(stage)
	if len(toks) == 0 || baseName(strings.Trim(toks[0], `"'`)) != "tee" {
		return ""
	}
	for _, tok := range toks[1:] {
		a := strings.Trim(tok, `"'`)
		if strings.HasPrefix(a, "-") {
			continue
		}
		if strings.HasPrefix(a, "/") {
			return a
		}
		return ""
	}
	return ""
}

// chainStageExecutes reports whether any chain stage executes one of the
// written paths — as its own command word, or as the argument of a shell
// interpreter. Pure static path equality over `&&`/`||`/`;` stages.
func chainStageExecutes(stages []string, writes []string) bool {
	if len(writes) == 0 || len(stages) < 2 {
		return false
	}
	for _, stage := range stages {
		toks := tokens(stage)
		if len(toks) == 0 {
			continue
		}
		first := strings.Trim(toks[0], `"'`)
		for _, w := range writes {
			if first == w {
				return true
			}
			if isInterpreterWord(baseName(first)) {
				for _, arg := range toks[1:] {
					if strings.Trim(arg, `"'`) == w {
						return true
					}
				}
			}
		}
	}
	return false
}

// firstExecutablePath returns the first executable token of a command with
// its original form preserved: absolute paths and home-relative tokens are
// returned verbatim so callers can inspect them as targets. PATH-resolved
// bare names return "" because they cannot be inspected statically.
func firstExecutablePath(stage string) string {
	toks := tokens(stage)
	skipNext := false
	for _, tok := range toks {
		clean := strings.Trim(tok, `"'`)
		if skipNext {
			skipNext = false
			continue
		}
		// Wrapper commands match on their basename so absolute paths
		// (/usr/bin/env, /usr/bin/timeout) are skipped as well.
		switch baseName(clean) {
		case "sudo", "env", "nohup", "exec", "nice", "timeout", "setsid", "flock":
			if baseName(clean) == "timeout" || baseName(clean) == "nice" {
				skipNext = true
			}
			continue
		case "":
			continue
		}
		if strings.HasPrefix(clean, "/") || execTokenHome(clean) {
			return clean
		}
		return ""
	}
	return ""
}

// isHiddenPath reports whether a path contains a dot-prefixed component that
// is not a well-known tooling directory.
func isHiddenPath(p string) bool {
	for _, part := range strings.Split(p, "/") {
		if strings.HasPrefix(part, ".") && part != "." && part != ".." {
			for _, known := range knownToolDotDirs {
				if strings.Contains(p, known) {
					return false
				}
			}
			return true
		}
	}
	return false
}

// isTempPath reports whether a path lies under a temporary or shared-memory
// location.
func isTempPath(p string) bool {
	for _, pre := range tempPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// hasCommandToken reports whether word appears as a standalone command token
// (start of stage or after a shell operator), not merely as a substring.
func hasCommandToken(cmd, word string) bool {
	for _, stage := range splitCommandChain(cmd) {
		toks := tokens(stage)
		for i, tok := range toks {
			clean := strings.Trim(tok, `"'`)
			if clean != word && baseName(clean) != word {
				continue
			}
			if i == 0 {
				return true
			}
			prev := toks[i-1]
			if prev == "|" || prev == ";" || prev == "&&" || prev == "||" || prev == "(" || prev == "{" {
				return true
			}
		}
	}
	// Also match across pipe splits (`curl ... | sh`).
	for _, stage := range splitPipes(cmd) {
		toks := tokens(stage)
		if len(toks) > 0 && (strings.Trim(toks[0], `"'`) == word || baseName(toks[0]) == word) {
			return true
		}
	}
	return false
}

// splitPipes splits a command line on unquoted single pipes.
func splitPipes(cmd string) []string {
	var parts []string
	var cur strings.Builder
	var quote byte
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			cur.WriteByte(c)
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			cur.WriteByte(c)
		case '|':
			if i+1 < len(cmd) && cmd[i+1] == '|' {
				cur.WriteByte(c)
				continue
			}
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	parts = append(parts, cur.String())
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// shellTokens splits a command into whitespace-separated tokens while
// keeping quoted strings as single tokens (quote characters removed). It
// is a static approximation of shell word splitting, not a shell parser.
func shellTokens(cmd string) []string {
	var out []string
	var cur strings.Builder
	var quote byte
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case ' ', '\t':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

func isInterpreterWord(w string) bool {
	w = strings.TrimPrefix(w, "/usr/bin/")
	w = strings.TrimPrefix(w, "/bin/")
	for _, i := range execInterpreters {
		if w == i {
			return true
		}
	}
	return false
}

func trimmedLastToken(stage string) string {
	stage = strings.TrimSpace(stage)
	stage = strings.TrimSuffix(stage, ";")
	toks := tokens(stage)
	if len(toks) == 0 {
		return ""
	}
	return strings.Trim(toks[len(toks)-1], `"'`)
}

func firstExecutableToken(stage string) string {
	toks := tokens(stage)
	for _, tok := range toks {
		clean := strings.Trim(tok, `"'`)
		switch clean {
		case "sudo", "env", "nohup", "exec", "nice", "timeout", "setsid", "flock":
			continue
		}
		if clean == "" {
			continue
		}
		return baseName(clean)
	}
	return ""
}

// redactKV is the credential-assignment pattern (password=..., token: ...).
var redactKV = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|auth|authorization|credential)s?\b(\s*[:=]\s*)(\S{1,512})`)

// privateKeyLine matches PEM key boundaries.
var privateKeyLine = regexp.MustCompile(`(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----`)

// sshKeyMaterial matches the base64 body of an SSH public key.
var sshKeyMaterial = regexp.MustCompile(`(?i)\b(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-\S+)\s+([A-Za-z0-9+/=]{40,})`)

// RedactSecrets replaces credential values, private-key markers and SSH key
// material with fixed placeholders so no evidence line can leak them.
func RedactSecrets(s string) string {
	if s == "" {
		return s
	}
	s = privateKeyLine.ReplaceAllString(s, "[PRIVATE KEY REDACTED]")
	s = sshKeyMaterial.ReplaceAllString(s, "$1 [KEY MATERIAL REDACTED]")
	s = redactKV.ReplaceAllString(s, "$1$2[REDACTED]")
	return s
}
