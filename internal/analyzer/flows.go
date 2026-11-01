package analyzer

// flows.go implements the Phase 4 bounded intra-file correlation engine.
//
// Scope (stated honestly on every finding): statement-level, assignment-based
// dataflow INSIDE one PHP file. It is not a full taint analysis: no interpro-
// cedural edges, no path sensitivity, no array-key resolution and no sanitiza-
// tion modeling beyond escapeshellarg/escapeshellcmd/intval/floatval. When a
// flow cannot be proven the individual Phase 3.2 signals still stand on their
// own; nothing is silently upgraded.
//
// The engine reuses the lexical profile from lexview.go: tokens are read from
// code positions only, string bodies are recovered through their lexical
// classes (double-quoted strings and heredocs interpolate and may reference
// request variables, single quotes and nowdocs are opaque literals). Comments
// and inline HTML never produce tokens, so documentation examples cannot
// create flows.
//
// Bounded by construction: at most maxFlowStatements statements, maxFlowVars
// tracked variables, a maxFlowArgBytes window per call argument and
// maxFlowNameLen for reconstructed call names. No recursion, no decoding of
// payloads (decoder arguments are recorded, never evaluated), no allocation
// proportional to input beyond the single lexical profile the analyzer
// already builds. Output is deterministic: findings are emitted in statement
// order and deduplicated.

import (
	"fmt"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// Flow analysis bounds. All are small fixed constants: memory use does not
// grow with file size beyond the analyzer's existing 2 MiB read cap.
const (
	maxFlowStatements = 512
	maxFlowVars       = 64
	maxFlowArgTokens  = 48
	maxFlowNameLen    = 64
	maxFlowStringLit  = 256
	maxFlowFindings   = 8
)

// Flow sinks and helpers. Names are plain ASCII so the table can be written
// literally.
var (
	flowShellSinks = map[string]bool{
		"system": true, "exec": true, "shell_exec": true,
		"passthru": true, "proc_open": true, "popen": true,
	}
	flowCodeSinks = map[string]bool{
		"eval": true, "assert": true, "create_function": true,
	}
	flowIncludeKW = map[string]bool{
		"include": true, "require": true, "include_once": true, "require_once": true,
	}
	flowDecoders = map[string]bool{
		"base64_decode": true, "gzinflate": true, "gzuncompress": true,
		"str_rot13": true, "hex2bin": true, "convert_uudecode": true,
	}
	flowRemoteFetch = map[string]bool{
		"file_get_contents": true, "fopen": true, "fsockopen": true, "curl_exec": true,
	}
	flowShellSanitizers = map[string]bool{
		"escapeshellarg": true, "escapeshellcmd": true,
	}
	flowNumSanitizers = map[string]bool{
		"intval": true, "floatval": true, "abs": true,
	}
	flowDangerousNames = map[string]bool{
		"system": true, "exec": true, "shell_exec": true, "passthru": true,
		"proc_open": true, "popen": true, "eval": true, "assert": true,
		"create_function": true,
	}
	flowRequestSuperglobals = map[string]bool{
		"_GET": true, "_POST": true, "_REQUEST": true,
		"_COOKIE": true, "_FILES": true, "_SERVER": true,
	}
)

// flowServerSafeKeys lists $_SERVER subscripts set by the server itself, not
// chosen by the web client. A read of one of these is not request input.
// Everything else (HTTP_*, REQUEST_URI, QUERY_STRING, PATH_INFO, PHP_SELF and
// any non-subscripted read) stays client-controlled.
var flowServerSafeKeys = map[string]bool{
	"SCRIPT_NAME": true, "SCRIPT_FILENAME": true, "DOCUMENT_ROOT": true,
	"REQUEST_TIME": true, "REQUEST_TIME_FLOAT": true,
	"argv": true, "argc": true,
	"SERVER_ADDR": true, "SERVER_NAME": true, "SERVER_SOFTWARE": true,
	"SERVER_PROTOCOL": true, "SERVER_PORT": true, "SERVER_ADMIN": true,
	"SERVER_SIGNATURE": true, "GATEWAY_INTERFACE": true,
	"REMOTE_ADDR": true, "REMOTE_HOST": true, "REMOTE_PORT": true,
	"REQUEST_METHOD": true, "PATH_TRANSLATED": true, "AUTH_TYPE": true,
}

// flowServerSubscriptSafe reports whether the subscript starting at '['
// (index of the o'[' token) selects a server-set $_SERVER value.
func flowServerSubscriptSafe(toks []flowToken, bracketIdx int) bool {
	if bracketIdx+2 >= len(toks) {
		return false
	}
	k := toks[bracketIdx+1]
	close := toks[bracketIdx+2]
	if k.kind != 's' || k.interp || close.kind != 'o' || close.val != "]" {
		return false
	}
	return flowServerSafeKeys[strings.Trim(k.val, "'\"")]
}

// flowVar records what the analysis knows about one variable so far.
type flowVar struct {
	name string
	// reqDirect/reqIndirect record HOW the request provenance was
	// established: a bare superglobal read is direct evidence, a read
	// wrapped in an intermediate function call or used as an array
	// subscript key is only indirect (sanitization unknown).
	reqDirect     bool
	reqIndirect   bool
	isRequest     bool
	requestSrc    string
	decodeDepth   int
	isRemote      bool // holds content fetched from a remote URL
	isRemoteURL   bool // holds a remote URL literal (fetch target)
	isSanitized   bool
	dangerousName string
	isShellOut    bool
	isUpload      bool
	// written-content provenance for variables used as write targets.
	contentRequest bool
	contentRemote  bool
	contentDecoder bool
	line           int
}

// flowToken is one lexical token of the code region.
type flowToken struct {
	kind byte // 'v' variable, 'i' identifier, 's' string body, 'n' number, 'o' other byte
	// val holds the variable/identifier name, the single byte for 'o'
	// tokens, or the string body for 's'.
	val string
	// interp marks string bodies that interpolate (double-quoted, heredoc).
	interp bool
	pos    int
}

// flowFinding is one pending correlation finding awaiting emission.
type flowFinding struct {
	rule      string
	severity  finding.Severity
	line      int
	title     string
	evidence  string
	conf      string
	signals   []finding.Signal
	sortStmt  int
	dedupeKey string
}

// correlate runs the bounded correlation pass and returns new findings.
// path is used for finding metadata only; src is never modified or executed.
func correlate(path string, src []byte, prof lexProfile) []finding.Finding {
	stmts := flowStatements(src, prof)
	if len(stmts) == 0 {
		return nil
	}

	vars := make(map[string]*flowVar, 16)
	var order []string // insertion order for deterministic iteration
	pending := make([]flowFinding, 0, 4)
	ind := make(map[string]int) // webshell indicator -> first statement index
	addIndicator := func(name string, stmt int) {
		if _, ok := ind[name]; !ok {
			ind[name] = stmt
		}
	}

	for si := 0; si < len(stmts) && si < maxFlowStatements; si++ {
		toks := stmts[si]
		emit := func(f flowFinding) {
			f.sortStmt = si
			pending = append(pending, f)
		}
		flowProcessStatement(path, src, toks, si, vars, &order, emit, addIndicator)
	}

	// Indirect backtick flows: backtick bodies are skipped during token
	// scanning (backtickFindings owns the mechanism finding), but a tracked
	// request-controlled or decoder-derived variable inside a backtick
	// command is exactly the indirect execution shape the mechanism finding
	// cannot see. Bounded single pass over backtick regions.
	pending = append(pending, flowBacktickFlows(src, prof, vars)...)

	// Webshell behavior chain: at least three distinct indicators.
	if len(ind) >= 3 {
		names := make([]string, 0, len(ind))
		sig := make([]finding.Signal, 0, len(ind))
		for name, stmt := range ind {
			names = append(names, name)
			if stmt < len(stmts) && len(stmts[stmt]) > 0 {
				sig = append(sig, finding.Signal{
					Rule:   "webshell-indicator",
					Line:   lineOfSource(src, stmts[stmt][0].pos),
					Detail: name,
				})
			}
		}
		sortFlowStrings(names)
		firstStmt := indFirst(ind, names)
		firstLine := 0
		if firstStmt < len(stmts) && len(stmts[firstStmt]) > 0 {
			firstLine = lineOfSource(src, stmts[firstStmt][0].pos)
		}
		pending = append(pending, flowFinding{
			rule:     "php-webshell-chain",
			severity: finding.High,
			line:     firstLine,
			title:    "Webshell behavior chain",
			evidence: fmt.Sprintf("%d independent webshell indicators combined: %s; "+
				"individual features can be legitimate, the combination is the indicator; "+
				"intra-file behavioral correlation, not a full taint analysis",
				len(ind), strings.Join(names, "; ")),
			conf:      finding.ConfidenceEstablished,
			signals:   sig,
			sortStmt:  maxFlowStatements,
			dedupeKey: "php-webshell-chain",
		})
	}

	// Deterministic emission: statement order, then dedupe.
	seen := make(map[string]bool, len(pending))
	out := make([]finding.Finding, 0, len(pending))
	emitted := 0
	for i := 0; i < len(pending) && emitted < maxFlowFindings; i++ {
		p := pending[i]
		key := p.dedupeKey
		if key == "" {
			key = p.rule + "|" + fmt.Sprint(p.line)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, finding.Finding{
			Status:     finding.Suspicious,
			Severity:   p.severity,
			Title:      p.title,
			Path:       path,
			Rule:       p.rule,
			Line:       p.line,
			Evidence:   p.evidence,
			Confidence: p.conf,
			Category:   categoryOf(p.rule),
			Signals:    p.signals,
		})
		emitted++
	}
	return out
}

// indFirst returns the statement index of the first indicator in names.
func indFirst(ind map[string]int, names []string) int {
	best := -1
	for _, n := range names {
		if v, ok := ind[n]; ok && (best < 0 || v < best) {
			best = v
		}
	}
	if best < 0 {
		return 0
	}
	return best
}

func categoryOf(rule string) string {
	if m, ok := RuleMetadata(rule); ok {
		return m.Category
	}
	return ""
}

// flowProcessStatement analyzes one statement: assignment tracking first,
// then sink detection.
func flowProcessStatement(
	path string,
	src []byte,
	toks []flowToken,
	si int,
	vars map[string]*flowVar,
	order *[]string,
	emit func(flowFinding),
	addIndicator func(string, int),
) {
	if len(toks) == 0 {
		return
	}

	// Split at the first top-level assignment "=" (single, not ==, <=, >=, !=).
	eq := -1
	depth := 0
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.kind == 'o' {
			switch t.val {
			case "(":
				depth++
			case ")":
				depth--
			case "=":
				if depth == 0 && eq < 0 && flowIsEqOp(toks, i) {
					eq = i
				}
			}
		}
	}

	rhsStart := 0
	target := ""
	if eq >= 1 && toks[eq-1].kind == 'v' {
		target = toks[eq-1].val
		rhsStart = eq + 1
	}

	if target != "" {
		flowApplyAssignment(src, toks[rhsStart:], target, si, vars, order, emit)
	}

	// foreach over a request superglobal marks the loop value variable as
	// request-controlled: foreach ($_POST as $k => $v) injects every request
	// value into the loop body, a classic webshell primitive.
	flowTrackForeach(src, toks, si, vars, order)

	// extract($_GET) and parse_str($request) inject arbitrary request values
	// as variables.
	flowTrackInjection(src, toks, si, addIndicator)

	// Sink detection runs over the whole statement so sinks inside
	// assignments ($o = system($c)) are caught too.
	flowFindSinks(path, src, toks, si, vars, order, emit, addIndicator)
}

// flowIsEqOp reports whether the "=" token at i is a plain assignment
// (the next byte must not extend it into ==, =>, <=, >=, !=).
func flowIsEqOp(toks []flowToken, i int) bool {
	if i+1 < len(toks) {
		n := toks[i+1]
		if n.kind == 'o' && (n.val == "=" || n.val == ">") {
			return false
		}
	}
	if i-1 >= 0 {
		p := toks[i-1]
		if p.kind == 'o' && (p.val == "=" || p.val == "!" || p.val == "<" || p.val == ">" || p.val == "+" || p.val == "-" || p.val == "*" || p.val == "/" || p.val == "." || p.val == "%") {
			return false
		}
	}
	return true
}

// trackVar returns the tracked record for a variable, creating it inside the
// bounded table. Once the table is full new variables are not tracked, but
// existing records keep working: bounded memory, no unbounded growth.
func trackVar(name string, vars map[string]*flowVar, order *[]string, line int) *flowVar {
	if v, ok := vars[name]; ok {
		return v
	}
	if len(vars) >= maxFlowVars {
		return &flowVar{name: name}
	}
	v := &flowVar{name: name, line: line}
	vars[name] = v
	*order = append(*order, name)
	return v
}

// flowApplyAssignment extracts provenance from an assignment RHS into the
// target variable record.
func flowApplyAssignment(
	src []byte,
	rhs []flowToken,
	target string,
	si int,
	vars map[string]*flowVar,
	order *[]string,
	emit func(flowFinding),
) {
	if len(rhs) == 0 {
		return
	}
	tv := trackVar(target, vars, order, lineOfSource(src, rhs[0].pos))

	// Array-lookup semantics: reading $arr[<request>] selects a value from
	// an array by a client-chosen key. The selected VALUE is only indirect
	// evidence (we cannot see the array contents), unlike a bare read.
	lookupKeyTainted := false
	if len(rhs) >= 2 && rhs[0].kind == 'v' && !flowRequestSuperglobals[rhs[0].val] {
		if rhs[1].kind == 'o' && rhs[1].val == "[" {
			depth := 0
			for k := 1; k < len(rhs); k++ {
				if rhs[k].kind == 'o' && rhs[k].val == "[" {
					depth++
				} else if rhs[k].kind == 'o' && rhs[k].val == "]" {
					depth--
					if depth == 0 {
						if s, _ := flowRequestProbe(rhs[2:k], vars); s >= reqDirect {
							lookupKeyTainted = true
						}
						break
					}
				}
			}
		}
	}

	refs := flowVarRefs(rhs)
	requestSrc := ""
	decodeDepth := 0
	isRemote := false
	isRemoteURL := false
	sanitized := false
	shellOut := false

	for i := 0; i < len(rhs); i++ {
		t := rhs[i]
		if t.kind == 'v' && flowRequestSuperglobals[t.val] {
			// Server-set $_SERVER subscripts are not client input; the
			// manual scan must agree with the probe here, otherwise the
			// default fallback would re-taint values the probe cleared.
			if t.val == "_SERVER" && i+1 < len(rhs) && rhs[i+1].kind == 'o' && rhs[i+1].val == "[" && flowServerSubscriptSafe(rhs, i+1) {
				i = flowSkipSubscript(rhs, i)
				continue
			}
			requestSrc = t.val
			continue
		}
		if t.kind == 'v' {
			if rv, ok := vars[t.val]; ok {
				if rv.isRequest && requestSrc == "" {
					requestSrc = rv.name + " (assigned line " + fmt.Sprint(rv.line) + ")"
				}
				if rv.decodeDepth > decodeDepth {
					decodeDepth = rv.decodeDepth
				}
				if rv.isRemote {
					isRemote = true
				}
				if rv.isRemoteURL {
					isRemoteURL = true
				}
				if rv.isSanitized {
					sanitized = true
				}
			}
			continue
		}
		if t.kind == 's' {
			if strings.Contains(t.val, "php://input") {
				requestSrc = "php://input"
			}
			if !t.interp && strings.Contains(t.val, "://") && flowLooksRemoteURL(t.val) {
				// A URL literal is a fetch TARGET, not fetched content.
				isRemoteURL = true
			}
			continue
		}
		if t.kind == 'i' && i+1 < len(rhs) && rhs[i+1].kind == 'o' && rhs[i+1].val == "(" {
			call := t.val
			argToks := flowArgTokens(rhs, i+1)
			switch {
			case flowDecoders[call]:
				// Chain depth: the decoder adds one step on top of the
				// deepest tracked argument chain.
				argDepth := 0
				for _, at := range argToks {
					if at.kind == 'v' {
						if av, ok := vars[at.val]; ok && av.decodeDepth > argDepth {
							argDepth = av.decodeDepth
						}
					}
				}
				depth := argDepth + 1
				if decodeDepth+1 > depth {
					depth = decodeDepth + 1
				}
				if depth > 8 {
					depth = 8
				}
				decodeDepth = depth
				// Decoder inherits taint from its argument, keeping the
				// original request source visible through the chain.
				for _, at := range argToks {
					if at.kind == 'v' && flowRequestSuperglobals[at.val] {
						requestSrc = at.val
					}
					if at.kind == 'v' {
						if av, ok := vars[at.val]; ok {
							if av.isRequest && requestSrc == "" {
								if av.requestSrc != "" {
									requestSrc = av.requestSrc
								} else {
									requestSrc = av.name
								}
							}
							if av.isRemote {
								isRemote = true
							}
						}
					}
					if at.kind == 's' && strings.Contains(at.val, "php://input") {
						requestSrc = "php://input"
					}
				}
			case flowShellSanitizers[call] || flowNumSanitizers[call]:
				sanitized = true
			case flowShellSinks[call]:
				shellOut = true
			case flowRemoteFetch[call]:
				for _, at := range argToks {
					if at.kind == 's' && flowLooksRemoteURL(at.val) {
						isRemote = true
					}
					if at.kind == 'v' {
						if av, ok := vars[at.val]; ok && (av.isRemote || av.isRemoteURL) {
							isRemote = true
						}
					}
					if at.kind == 's' && strings.Contains(at.val, "php://input") {
						requestSrc = "php://input"
					}
				}
			}
		}
	}

	// Arithmetic makes a value numeric: numeric request input cannot carry
	// code or shell payloads.
	hasArith := false
	for _, t := range rhs {
		if t.kind == 'o' && (t.val == "+" || t.val == "-" || t.val == "*" || t.val == "/" || t.val == "%") {
			// "+" is also concat-free here because PHP concat uses ".".
			hasArith = true
			break
		}
	}

	tv.decodeDepth = maxInt(tv.decodeDepth, decodeDepth)
	tv.isRemote = tv.isRemote || isRemote
	tv.isRemoteURL = tv.isRemoteURL || isRemoteURL
	tv.isShellOut = tv.isShellOut || shellOut
	if requestSrc != "" || lookupKeyTainted {
		// The probe decides the provenance strength; a tainted array key
		// always caps the selected VALUE at indirect: the client chooses
		// which element is read, but not what the element contains.
		strength, psrc := flowRequestProbe(rhs, vars)
		if lookupKeyTainted {
			if strength < reqIndirect {
				psrc = requestSrc
			}
			strength = reqIndirect
		}
		switch {
		case strength >= reqDirect:
			tv.reqDirect = true
			tv.isRequest = true
			if tv.requestSrc == "" {
				if psrc != "" {
					tv.requestSrc = psrc
				} else {
					tv.requestSrc = requestSrc
				}
			}
		case strength == reqIndirect:
			tv.reqIndirect = true
			tv.isRequest = true
			if tv.requestSrc == "" {
				if psrc != "" {
					tv.requestSrc = psrc
				} else {
					tv.requestSrc = requestSrc
				}
			}
		default:
			// The manual scan found request input the probe could not
			// classify; keep it direct so nothing is silently lost.
			tv.reqDirect = true
			tv.isRequest = true
			if tv.requestSrc == "" {
				tv.requestSrc = requestSrc
			}
		}
	}
	if hasArith {
		tv.isSanitized = true
	}
	if sanitized {
		// A sanitizer result is no longer request-controlled for the domain
		// it protects: escapeshellarg output is safe as a shell argument,
		// intval/floatval output is numeric. Precision over detection count.
		tv.isSanitized = true
		tv.isRequest = false
		tv.reqDirect = false
		tv.reqIndirect = false
		tv.requestSrc = ""
	}

	// Plain variable copy: $b = $a; inherits everything.
	if len(refs) == 1 && len(rhs) == 1 && rhs[0].kind == 'v' && !flowRequestSuperglobals[rhs[0].val] {
		if sv, ok := vars[rhs[0].val]; ok {
			cp := *sv
			cp.name = target
			cp.line = tv.line
			*tv = cp
		}
	}

	// Dangerous-name literal reconstruction: "sys"."tem", chr(115)...,
	// str_rot13("flfgrz").
	if name, ok := flowReconstructName(rhs); ok {
		if flowDangerousNames[name] {
			tv.dangerousName = name
		}
	}
}

// flowFindSinks walks the statement for sink-shaped calls and emits the
// correlation findings that the tracked variable state supports.
func flowFindSinks(
	path string,
	src []byte,
	toks []flowToken,
	si int,
	vars map[string]*flowVar,
	order *[]string,
	emit func(flowFinding),
	addIndicator func(string, int),
) {
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		var callName string
		callVar := ""
		isVarCall := false
		switch {
		case t.kind == 'i' && i+1 < len(toks) && toks[i+1].kind == 'o' && toks[i+1].val == "(":
			callName = t.val
		case t.kind == 'i' && flowIncludeKW[t.val]:
			callName = t.val
		case t.kind == 'v' && i+1 < len(toks) && toks[i+1].kind == 'o' && toks[i+1].val == "(":
			isVarCall = true
			callVar = t.val
		default:
			continue
		}

		argStart := i + 1
		argToks := flowArgTokens(toks, argStart)
		line := lineOfSource(src, t.pos)

		if isVarCall {
			flowCheckVarCall(src, callVar, argToks, line, si, vars, emit, addIndicator)
			continue
		}

		switch {
		case flowShellSinks[callName]:
			flowCheckShellSink(src, callName, argToks, line, si, vars, emit, addIndicator)
		case callName == "eval" || callName == "assert" || callName == "create_function":
			flowCheckCodeSink(src, callName, argToks, line, si, vars, emit, addIndicator)
		case flowIncludeKW[callName]:
			flowCheckInclude(src, callName, argToks, line, si, vars, emit, addIndicator)
		case callName == "call_user_func" || callName == "call_user_func_array":
			flowCheckCallable(src, callName, argToks, line, si, vars, emit, addIndicator)
		case callName == "file_put_contents" || callName == "fwrite":
			flowCheckWrite(src, callName, argToks, line, si, vars, order, emit, addIndicator)
		case callName == "move_uploaded_file":
			flowCheckUpload(src, callName, argToks, line, si, vars, order, emit, addIndicator)
		case callName == "extract" || callName == "parse_str" || callName == "mb_parse_str":
			// Variable injection primitives; the indicator feeds the webshell
			// chain and the aggregate signal keeps the individual visibility.
			if req, _ := flowDirectRequest(argToks, vars); req {
				addIndicator("request-controlled variable injection", si)
			}
		}
	}

	// Output return indicator: echo/print of a shell sink result.
	for i := 0; i+1 < len(toks); i++ {
		if toks[i].kind == 'i' && (toks[i].val == "echo" || toks[i].val == "print") {
			n := toks[i+1]
			if n.kind == 'v' {
				if v, ok := vars[n.val]; ok && v.isShellOut {
					addIndicator("command output returned through HTTP", si)
				}
			}
			if n.kind == 'i' && i+2 < len(toks) && toks[i+2].kind == 'o' && toks[i+2].val == "(" {
				if flowShellSinks[toks[i+1].val] {
					addIndicator("command output returned through HTTP", si)
				}
			}
		}
	}

	// Authentication-like gate indicator: a request-derived value compared
	// against a string literal inside this statement.
	hasReq := false
	hasLit := false
	hasCmp := false
	for _, t := range toks {
		if t.kind == 'v' && flowRequestSuperglobals[t.val] {
			hasReq = true
		}
		if t.kind == 'v' && vars != nil {
			if v, ok := vars[t.val]; ok && v.isRequest {
				hasReq = true
			}
		}
		if t.kind == 's' && !t.interp {
			hasLit = true
		}
	}
	// Comparison operators == != === !== appear as adjacent o-tokens.
	for i := 0; i+1 < len(toks); i++ {
		if toks[i].kind == 'o' && (toks[i].val == "=" || toks[i].val == "!") {
			n := toks[i+1]
			if n.kind == 'o' && n.val == "=" {
				hasCmp = true
			}
		}
	}
	if hasReq && hasLit && hasCmp {
		addIndicator("authentication-like gate on request input", si)
	}

	// Variable-variables ($$name) are obfuscated dispatch.
	for i := 0; i+1 < len(toks); i++ {
		if toks[i].kind == 'o' && toks[i].val == "$" && toks[i+1].kind == 'v' {
			addIndicator("variable-variable obfuscation", si)
		}
	}
}

// flowBacktickFlows correlates tracked variables with backtick command
// regions. sortStmt is set to a mid priority so these findings sort after
// statement-level flows.
func flowBacktickFlows(src []byte, prof lexProfile, vars map[string]*flowVar) []flowFinding {
	var out []flowFinding
	n := len(src)
	inBT := false
	start := 0
	for i := 0; i < n; i++ {
		cl := prof.classes[i]
		if inBT {
			if cl == classCode && src[i] == btTick {
				// Closing tick: analyze the body just passed.
				body := src[start:i]
				for name, v := range vars {
					if !v.isRequest && v.decodeDepth == 0 {
						continue
					}
					if !strings.Contains(string(body), "$"+name) {
						continue
					}
					if v.isRequest {
						out = append(out, flowFinding{
							rule:     "php-source-to-shell",
							severity: finding.Critical,
							line:     lineOfSource(src, start-1),
							title:    "Request-controlled backtick execution",
							evidence: fmt.Sprintf("backtick command contains $%s, which was assigned request-controlled input (%s); "+
								"the executed command text is decided by the client", name, v.requestSrc),
							conf: finding.ConfidenceEstablished,
							signals: []finding.Signal{
								{Rule: "source", Line: v.line, Detail: "request input $" + name},
								{Rule: "sink", Line: lineOfSource(src, start-1), Detail: "backtick execution"},
							},
							sortStmt:  maxFlowStatements - 1,
							dedupeKey: "php-source-to-shell|backtick|" + fmt.Sprint(start),
						})
					} else {
						out = append(out, flowFinding{
							rule:     "php-decoder-exec",
							severity: finding.High,
							line:     lineOfSource(src, start-1),
							title:    "Decoder-derived backtick command",
							evidence: fmt.Sprintf("backtick command contains $%s, whose value comes from a %d-step decoder chain",
								name, v.decodeDepth),
							conf:      finding.ConfidenceEstablished,
							sortStmt:  maxFlowStatements - 1,
							dedupeKey: "php-decoder-exec|backtick|" + fmt.Sprint(start),
						})
					}
				}
				inBT = false
			}
			continue
		}
		// Opening tick: a code-position backtick whose next byte starts a
		// backtick body (empty bodies are irrelevant and stay invisible).
		if cl == classCode && src[i] == btTick && i+1 < n && prof.classes[i+1] == classBacktick {
			inBT = true
			start = i + 1
		}
	}
	return out
}

// flowTrackForeach marks the loop value variable of a foreach over a request
// superglobal as request-controlled. foreach ($_GET as $k => $v) and
// foreach ($_POST as $v) both inject request values into the loop body.
func flowTrackForeach(
	src []byte,
	toks []flowToken,
	si int,
	vars map[string]*flowVar,
	order *[]string,
) {
	hasForeach := false
	req := false
	for _, t := range toks {
		if t.kind == 'i' && t.val == "foreach" {
			hasForeach = true
		}
		if t.kind == 'v' && flowRequestSuperglobals[t.val] {
			req = true
		}
	}
	if !hasForeach || !req {
		return
	}
	for i := 1; i < len(toks); i++ {
		if toks[i].kind != 'i' || toks[i].val != "as" {
			continue
		}
		// as $k => $v  |  as $v
		if i+4 < len(toks) && toks[i+1].kind == 'v' && toks[i+2].kind == 'o' && toks[i+2].val == "=" && toks[i+3].kind == 'o' && toks[i+3].val == ">" && toks[i+4].kind == 'v' {
			tv := trackVar(toks[i+4].val, vars, order, lineOfSource(src, toks[i+4].pos))
			tv.isRequest = true
			if tv.requestSrc == "" {
				tv.requestSrc = "foreach loop value over request input"
			}
			return
		}
		if i+1 < len(toks) && toks[i+1].kind == 'v' {
			tv := trackVar(toks[i+1].val, vars, order, lineOfSource(src, toks[i+1].pos))
			tv.isRequest = true
			if tv.requestSrc == "" {
				tv.requestSrc = "foreach loop value over request input"
			}
			return
		}
	}
}

// flowTrackInjection records extract/parse_str of request input as an
// indicator; the direct call remains visible through the aggregate signal.
func flowTrackInjection(
	src []byte,
	toks []flowToken,
	si int,
	addIndicator func(string, int),
) {
	for i := 0; i+1 < len(toks); i++ {
		if toks[i].kind == 'i' && (toks[i].val == "extract" || toks[i].val == "parse_str" || toks[i].val == "mb_parse_str") &&
			toks[i+1].kind == 'o' && toks[i+1].val == "(" {
			arg := flowArgTokens(toks, i+1)
			if req, _ := flowDirectRequest(arg, nil); req {
				addIndicator("request-controlled variable injection", si)
			}
		}
	}
}

// flowCheckShellSink evaluates a shell sink call argument.
func flowCheckShellSink(
	src []byte,
	call string,
	arg []flowToken,
	line, si int,
	vars map[string]*flowVar,
	emit func(flowFinding),
	addIndicator func(string, int),
) {
	reqStrength, reqSrc := flowRequestProbe(arg, vars)
	decoderVar := ""
	decoderDepth := 0
	sanitized := false
	for _, t := range arg {
		if t.kind == 'v' {
			if v, ok := vars[t.val]; ok {
				if v.decodeDepth > decoderDepth {
					decoderDepth = v.decodeDepth
					decoderVar = v.name
				}
				if v.isSanitized {
					sanitized = true
				}
			}
		}
	}
	if sanitized && reqStrength == reqNone {
		return // sanitized shell input: no correlation finding, honest skip
	}
	if reqStrength > reqNone {
		addIndicator("request-controlled command execution", si)
		chain := ""
		if decoderDepth > 0 {
			chain = fmt.Sprintf(" through a %d-step decoder chain (variable $%s)", decoderDepth, decoderVar)
		}
		wrap := ""
		sev := finding.Critical
		conf := finding.ConfidenceEstablished
		if reqStrength == reqIndirect {
			// The request read passed through an intermediate function call
			// or array selection: the path is real, sanitization unknown.
			wrap = "; the input passes through an intermediate call or lookup, sanitization not established"
			sev = finding.Medium
			conf = finding.ConfidencePossible
		}
		emit(flowFinding{
			rule:     "php-source-to-shell",
			severity: sev,
			line:     line,
			title:    "Request-controlled shell command execution",
			evidence: fmt.Sprintf("%s() receives request-controlled input (%s)%s%s; "+
				"intra-file assignment-level flow (not a full taint analysis)",
				call, reqSrc, chain, wrap),
			conf: conf,
			signals: []finding.Signal{
				{Rule: "source", Line: flowSourceLine(arg, vars, src), Detail: "request input " + reqSrc},
				{Rule: "sink", Line: line, Detail: call + "() executes the command"},
			},
			dedupeKey: "php-source-to-shell|" + call + "|" + fmt.Sprint(line),
		})
		return
	}
	if decoderDepth > 0 {
		emit(flowFinding{
			rule:     "php-decoder-exec",
			severity: finding.High,
			line:     line,
			title:    "Decoded payload passed to shell execution",
			evidence: fmt.Sprintf("output of a %d-step decoder chain (variable $%s) reaches %s(); "+
				"the executed command text is constructed at runtime through decoding",
				decoderDepth, decoderVar, call),
			conf: finding.ConfidenceEstablished,
			signals: []finding.Signal{
				{Rule: "sink", Line: line, Detail: call + "()"},
			},
			dedupeKey: "php-decoder-exec|" + call + "|" + fmt.Sprint(line),
		})
	}
}

// flowCheckCodeSink evaluates eval/assert/create_function arguments.
func flowCheckCodeSink(
	src []byte,
	call string,
	arg []flowToken,
	line, si int,
	vars map[string]*flowVar,
	emit func(flowFinding),
	addIndicator func(string, int),
) {
	// assert() only evaluates a STRING argument as PHP code (Phase 3.2
	// argument-kind semantics). A comparison or a wrapped type-check call
	// such as assert(is_string($x)) is a boolean expression and can never
	// execute as code, no matter what the operands hold.
	if call == "assert" && len(arg) > 0 {
		// A leading namespace separator (\is_string) belongs to the
		// wrapper call, not to the argument expression.
		fi := 0
		if arg[0].kind == 'o' && arg[0].val == "\\" && len(arg) > 1 {
			fi = 1
		}
		if flowHasComparison(arg) ||
			(arg[fi].kind == 'i' && fi+1 < len(arg) && arg[fi+1].kind == 'o' && arg[fi+1].val == "(") {
			return
		}
	}
	reqStrength, reqSrc := flowRequestProbe(arg, vars)
	decoderDepth := 0
	decoderVar := ""
	for _, t := range arg {
		if t.kind == 'v' {
			if v, ok := vars[t.val]; ok && v.decodeDepth > decoderDepth {
				decoderDepth = v.decodeDepth
				decoderVar = v.name
			}
		}
	}
	if reqStrength > reqNone {
		addIndicator("request-controlled code execution", si)
		chain := ""
		if decoderDepth > 0 {
			chain = fmt.Sprintf(" through a %d-step decoder chain (variable $%s)", decoderDepth, decoderVar)
		}
		wrap := ""
		sev := finding.Critical
		conf := finding.ConfidenceEstablished
		if reqStrength == reqIndirect {
			wrap = "; the input passes through an intermediate call or lookup, sanitization not established"
			sev = finding.Medium
			conf = finding.ConfidencePossible
		}
		emit(flowFinding{
			rule:     "php-source-to-code",
			severity: sev,
			line:     line,
			title:    "Request-controlled code execution",
			evidence: fmt.Sprintf("%s() evaluates request-controlled input (%s)%s%s; the executed PHP code is decided by the client; "+
				"intra-file assignment-level flow (not a full taint analysis)",
				call, reqSrc, chain, wrap),
			conf: conf,
			signals: []finding.Signal{
				{Rule: "source", Line: flowSourceLine(arg, vars, src), Detail: "request input " + reqSrc},
				{Rule: "sink", Line: line, Detail: call + "()"},
			},
			dedupeKey: "php-source-to-code|" + call + "|" + fmt.Sprint(line),
		})
		return
	}
	if decoderDepth > 0 {
		emit(flowFinding{
			rule:     "php-decoder-exec",
			severity: finding.High,
			line:     line,
			title:    "Decoded payload evaluated as code",
			evidence: fmt.Sprintf("output of a %d-step decoder chain (variable $%s) reaches %s(); "+
				"decoded content is executed, never by RONDA itself",
				decoderDepth, decoderVar, call),
			conf: finding.ConfidenceEstablished,
			signals: []finding.Signal{
				{Rule: "sink", Line: line, Detail: call + "()"},
			},
			dedupeKey: "php-decoder-exec|" + call + "|" + fmt.Sprint(line),
		})
	}
}

// flowHasComparison reports whether the token slice contains a comparison
// operator (==, !=, <, >). Single-char o-tokens; == and != are pairs.
func flowHasComparison(arg []flowToken) bool {
	for i := 0; i < len(arg); i++ {
		t := arg[i]
		if t.kind != 'o' {
			continue
		}
		if t.val == "<" || t.val == ">" {
			return true
		}
		if i+1 < len(arg) && (t.val == "=" || t.val == "!") && arg[i+1].kind == 'o' && arg[i+1].val == "=" {
			return true
		}
	}
	return false
}

// flowCheckInclude evaluates include/require arguments (with or without
// parentheses).
func flowCheckInclude(
	src []byte,
	kw string,
	arg []flowToken,
	line, si int,
	vars map[string]*flowVar,
	emit func(flowFinding),
	addIndicator func(string, int),
) {
	if len(arg) == 0 {
		return
	}
	reqStrength, reqSrc := flowRequestProbe(arg, vars)
	var decoderVar string
	decoderDepth := 0
	writeTarget := ""
	contentRequest := false
	contentRemote := false
	contentDecoder := false
	plainVar := false
	if len(arg) == 1 && arg[0].kind == 'v' {
		plainVar = true
		if v, ok := vars[arg[0].val]; ok {
			if v.decodeDepth > 0 {
				decoderDepth = v.decodeDepth
				decoderVar = v.name
			}
			contentRequest = v.contentRequest
			contentRemote = v.contentRemote
			contentDecoder = v.contentDecoder
			if v.contentRequest || v.contentRemote || v.contentDecoder {
				writeTarget = v.name
			}
		}
	}

	switch {
	case reqStrength > reqNone:
		addIndicator("request-controlled code execution", si)
		sev := finding.Critical
		conf := finding.ConfidenceEstablished
		wrap := ""
		if reqStrength == reqIndirect {
			wrap = "; the input passes through an intermediate call or lookup, sanitization not established"
			sev = finding.Medium
			conf = finding.ConfidencePossible
		}
		emit(flowFinding{
			rule:     "php-source-to-code",
			severity: sev,
			line:     line,
			title:    "Request-controlled dynamic inclusion",
			evidence: fmt.Sprintf("%s receives request-controlled input (%s)%s; "+
				"intra-file assignment-level flow (not a full taint analysis)", kw, reqSrc, wrap),
			conf: conf,
			signals: []finding.Signal{
				{Rule: "sink", Line: line, Detail: kw},
			},
			dedupeKey: "php-source-to-code|" + kw + "|" + fmt.Sprint(line),
		})
	case contentRequest:
		emit(flowFinding{
			rule:     "php-source-to-code",
			severity: finding.Critical,
			line:     line,
			title:    "Request-controlled payload included after write",
			evidence: fmt.Sprintf("%s of $%s, a file previously written with request-controlled content; "+
				"uploaded or posted content becomes executable code", kw, writeTarget),
			conf: finding.ConfidenceEstablished,
			signals: []finding.Signal{
				{Rule: "write", Line: flowWriteLine(vars, writeTarget), Detail: "file_put_contents/fwrite of request-controlled content"},
				{Rule: "sink", Line: line, Detail: kw + " $" + writeTarget},
			},
			dedupeKey: "php-source-to-code|" + kw + "|" + fmt.Sprint(line),
		})
	case decoderDepth > 0:
		emit(flowFinding{
			rule:     "php-decoder-exec",
			severity: finding.High,
			line:     line,
			title:    "Decoder-derived path included",
			evidence: fmt.Sprintf("%s of $%s, whose value comes from a %d-step decoder chain", kw, decoderVar, decoderDepth),
			conf:     finding.ConfidenceEstablished,
			signals: []finding.Signal{
				{Rule: "sink", Line: line, Detail: kw},
			},
			dedupeKey: "php-decoder-exec|" + kw + "|" + fmt.Sprint(line),
		})
	case contentRemote || contentDecoder:
		emit(flowFinding{
			rule:     "php-write-exec",
			severity: finding.High,
			line:     line,
			title:    "Written file subsequently executed",
			evidence: fmt.Sprintf("%s of $%s, a file this script wrote from remote or decoded content; "+
				"the write-then-execute pipeline is the loader pattern", kw, writeTarget),
			conf: finding.ConfidenceEstablished,
			signals: []finding.Signal{
				{Rule: "sink", Line: line, Detail: kw + " $" + writeTarget},
			},
			dedupeKey: "php-write-exec|" + kw + "|" + fmt.Sprint(line),
		})
	case plainVar:
		emit(flowFinding{
			rule:     "php-dynamic-include",
			severity: finding.Info,
			line:     line,
			title:    "Dynamic include of variable path",
			evidence: fmt.Sprintf("%s of variable $%s; template engines and theme loaders do this legitimately; "+
				"severity stays informational because no request or decoder provenance was established", kw, arg[0].val),
			conf:      finding.ConfidencePossible,
			dedupeKey: "php-dynamic-include|" + arg[0].val,
		})
	}
}

// flowCheckCallable evaluates call_user_func/call_user_func_array first args.
func flowCheckCallable(
	src []byte,
	call string,
	arg []flowToken,
	line, si int,
	vars map[string]*flowVar,
	emit func(flowFinding),
	addIndicator func(string, int),
) {
	if len(arg) == 0 {
		return
	}
	first := arg[0]
	switch {
	case first.kind == 's' && !first.interp && flowDangerousNames[strings.Trim(first.val, "'\"")]:
		emit(flowFinding{
			rule:     "php-dynamic-call",
			severity: finding.High,
			line:     line,
			title:    "Dynamic call to dangerous function",
			evidence: fmt.Sprintf("%s() invoked with the dangerous function name %q as a literal; "+
				"dispatch hidden from call-position analysis", call, strings.Trim(first.val, "'\"")),
			conf:      finding.ConfidenceEstablished,
			dedupeKey: "php-dynamic-call|" + call + "|" + fmt.Sprint(line),
		})
	case first.kind == 'v':
		if v, ok := vars[first.val]; ok {
			switch {
			case v.isRequest:
				addIndicator("request-controlled code execution", si)
				sev := finding.Critical
				conf := finding.ConfidenceEstablished
				if v.reqIndirect && !v.reqDirect {
					sev = finding.Medium
					conf = finding.ConfidencePossible
				}
				emit(flowFinding{
					rule:     "php-source-to-code",
					severity: sev,
					line:     line,
					title:    "Request-controlled callable",
					evidence: fmt.Sprintf("%s() invoked with request-controlled callable ($%s from %s); the client chooses the executed function",
						call, v.name, v.requestSrc),
					conf:      conf,
					dedupeKey: "php-source-to-code|" + call + "|" + fmt.Sprint(line),
				})
			case v.dangerousName != "":
				emit(flowFinding{
					rule:     "php-dynamic-call",
					severity: finding.High,
					line:     line,
					title:    "Dynamic call resolving to dangerous function",
					evidence: fmt.Sprintf("%s() invoked through $%s, which was assigned the dangerous function name %q",
						call, v.name, v.dangerousName),
					conf:      finding.ConfidenceEstablished,
					dedupeKey: "php-dynamic-call|" + call + "|" + fmt.Sprint(line),
				})
			}
		}
	}
}

// flowCheckVarCall evaluates $f(...) variable function calls.
func flowCheckVarCall(
	src []byte,
	name string,
	arg []flowToken,
	line, si int,
	vars map[string]*flowVar,
	emit func(flowFinding),
	addIndicator func(string, int),
) {
	v, ok := vars[name]
	if !ok {
		return
	}
	switch {
	case v.isRequest:
		addIndicator("request-controlled code execution", si)
		sev := finding.Critical
		conf := finding.ConfidenceEstablished
		if v.reqIndirect && !v.reqDirect {
			sev = finding.Medium
			conf = finding.ConfidencePossible
		}
		emit(flowFinding{
			rule:     "php-source-to-code",
			severity: sev,
			line:     line,
			title:    "Request-controlled callable invoked",
			evidence: fmt.Sprintf("variable function $%s() invoked; the callable comes from %s; "+
				"the client decides which function runs with which arguments", name, v.requestSrc),
			conf:      conf,
			dedupeKey: "php-source-to-code|varcall|" + fmt.Sprint(line),
		})
	case v.dangerousName != "":
		addIndicator("obfuscated callable construction", si)
		emit(flowFinding{
			rule:     "php-dynamic-call",
			severity: finding.High,
			line:     line,
			title:    "Variable function resolves to dangerous function",
			evidence: fmt.Sprintf("variable function $%s() invoked; $%s was assigned the dangerous function name %q",
				name, name, v.dangerousName),
			conf:      finding.ConfidenceEstablished,
			dedupeKey: "php-dynamic-call|varcall|" + fmt.Sprint(line),
		})
	case v.decodeDepth > 0:
		emit(flowFinding{
			rule:     "php-dynamic-call",
			severity: finding.High,
			line:     line,
			title:    "Decoder-derived function name invoked",
			evidence: fmt.Sprintf("variable function $%s() invoked; the callable name comes from a %d-step decoder chain",
				name, v.decodeDepth),
			conf:      finding.ConfidenceEstablished,
			dedupeKey: "php-dynamic-call|varcall|" + fmt.Sprint(line),
		})
	}
}

// flowCheckWrite evaluates file_put_contents/fwrite calls for dropper and
// loader pipelines.
func flowCheckWrite(
	src []byte,
	call string,
	arg []flowToken,
	line, si int,
	vars map[string]*flowVar,
	order *[]string,
	emit func(flowFinding),
	addIndicator func(string, int),
) {
	// Targets: file_put_contents($target, $content); fwrite($fh, $content).
	contentIdx := 1
	if call == "fwrite" {
		contentIdx = 1 // fwrite($handle, $string): content is arg 2 (index 1)
	}
	if len(arg) <= contentIdx {
		return
	}
	content := arg[contentIdx:]
	targetToks := arg[:contentIdx]

	directRemote := false
	for i := 0; i+1 < len(content); i++ {
		if content[i].kind == 'i' && flowRemoteFetch[content[i].val] && content[i+1].kind == 'o' && content[i+1].val == "(" {
			// The fetch only counts as remote when its own argument
			// carries a URL scheme; local fixture paths and prose URLs
			// are not remote retrieval.
			for _, at := range flowArgTokens(content, i+1) {
				if at.kind == 's' && flowLooksRemoteURL(at.val) {
					directRemote = true
				}
				if at.kind == 'v' {
					if av, ok := vars[at.val]; ok && (av.isRemote || av.isRemoteURL) {
						directRemote = true
					}
				}
			}
		}
	}
	directReq, reqSrc := flowDirectRequest(content, vars)
	contentStrength, _ := flowRequestProbe(content, vars)
	_ = contentStrength
	contentDecoder := false
	for _, t := range content {
		if t.kind == 'v' {
			if v, ok := vars[t.val]; ok && v.decodeDepth > 0 {
				contentDecoder = true
			}
		}
	}
	contentRemote := directRemote
	for _, t := range content {
		if t.kind == 'v' {
			if v, ok := vars[t.val]; ok && v.isRemote {
				contentRemote = true
			}
		}
	}

	// Track the write target so a later include can be correlated. Only
	// simple variable targets are tracked (bounded, honest scope).
	targetName := ""
	if len(targetToks) == 1 && targetToks[0].kind == 'v' {
		targetName = targetToks[0].val
		tv := trackVar(targetName, vars, order, line)
		tv.contentRequest = tv.contentRequest || directReq
		tv.contentRemote = tv.contentRemote || contentRemote
		tv.contentDecoder = tv.contentDecoder || contentDecoder
	}

	if directReq || contentRemote || contentDecoder {
		if directReq {
			addIndicator("request-controlled file operations", si)
		}
		kind := "remote-fetched"
		what := "remote content"
		switch {
		case directReq:
			kind = "request-controlled"
			what = reqSrc
		case contentDecoder:
			kind = "decoder-derived"
		}
		sev := finding.Medium
		if directReq {
			sev = finding.High
		}
		emit(flowFinding{
			rule:     "php-remote-write",
			severity: sev,
			line:     line,
			title:    "Untrusted content written to file",
			evidence: fmt.Sprintf("%s() writes %s content (%s) to a file at runtime; "+
				"the write alone is not execution, a later include of the target would complete the loader chain",
				call, kind, what),
			conf: finding.ConfidenceEstablished,
			signals: []finding.Signal{
				{Rule: "sink", Line: line, Detail: call + "()"},
			},
			dedupeKey: "php-remote-write|" + fmt.Sprint(line),
		})
	}
}

// flowCheckUpload evaluates move_uploaded_file for upload-plus-execution
// chains.
func flowCheckUpload(
	src []byte,
	call string,
	arg []flowToken,
	line, si int,
	vars map[string]*flowVar,
	order *[]string,
	emit func(flowFinding),
	addIndicator func(string, int),
) {
	if len(arg) < 2 {
		return
	}
	addIndicator("request-controlled file operations", si)
	// The moved file content originates from the client upload, so the
	// target variable carries request-controlled content: a later include
	// of it completes an upload-to-execution chain. The destination is the
	// LAST variable argument (the source is an expression such as
	// $_FILES['f']['tmp_name']).
	for j := len(arg) - 1; j >= 0; j-- {
		if arg[j].kind == 'v' && !flowRequestSuperglobals[arg[j].val] {
			tv := trackVar(arg[j].val, vars, order, line)
			tv.isUpload = true
			tv.contentRequest = true
			if tv.requestSrc == "" {
				tv.requestSrc = "uploaded file content (move_uploaded_file)"
			}
			break
		}
	}
}

// Request provenance strength. Evidence strength decides severity: direct
// bare reads support CRITICAL, wrapped reads only support MEDIUM/possible.
const (
	reqNone     = 0
	reqIndirect = 1
	reqDirect   = 2
)

// flowRequestProbe scans a token slice for request input and reports the
// strongest provenance. A request superglobal read bare (or subscripted) is
// DIRECT; the same read inside an intermediate function call, or a tracked
// variable whose provenance was indirect, is INDIRECT. Sanitizer calls
// suppress their wrapped reads entirely; decoder calls do not de-taint.
// $_SERVER subscripts with server-set keys are not request input.
func flowRequestProbe(arg []flowToken, vars map[string]*flowVar) (int, string) {
	strength := reqNone
	src := ""
	wrapperDepth := 0 // >0 when inside a non-decoder, non-sanitizer call
	callDepth := 0
	for i := 0; i < len(arg); i++ {
		t := arg[i]
		switch {
		case t.kind == 'i' && i+1 < len(arg) && arg[i+1].kind == 'o' && arg[i+1].val == "(":
			callDepth++
			// Sanitizer wrapper: skip its whole argument, the value that
			// comes out is escaped or numeric.
			if flowShellSanitizers[t.val] || flowNumSanitizers[t.val] {
				skip := flowArgTokens(arg, i+1)
				consumed := len(skip) + 2
				i += consumed
				continue
			}
			// Decoder wrappers keep provenance direct: decoding does not
			// de-taint client input.
			if !flowDecoders[t.val] {
				wrapperDepth++
			}
			continue
		case t.kind == 'o' && t.val == "(":
			callDepth++
			continue
		case t.kind == 'o' && t.val == ")":
			if callDepth > 0 {
				callDepth--
			}
			if wrapperDepth > 0 && callDepth < wrapperDepth {
				wrapperDepth--
			}
			continue
		}
		strengthHere := reqNone
		srcHere := ""
		switch {
		case t.kind == 'v' && flowRequestSuperglobals[t.val]:
			// $_SERVER with a server-set subscript is not client input.
			if t.val == "_SERVER" && i+1 < len(arg) && arg[i+1].kind == 'o' && arg[i+1].val == "[" {
				if flowServerSubscriptSafe(arg, i+1) {
					continue
				}
			}
			strengthHere = reqDirect
			srcHere = "$" + t.val
			i = flowSkipSubscript(arg, i)
		case t.kind == 'v' && vars != nil:
			if v, ok := vars[t.val]; ok && v.isRequest {
				if v.reqDirect {
					strengthHere = reqDirect
				} else {
					strengthHere = reqIndirect
				}
				srcHere = "$" + v.name + " (assigned line " + fmt.Sprint(v.line) + " from " + v.requestSrc + ")"
			}
			i = flowSkipSubscript(arg, i)
		case t.kind == 's' && t.interp:
			for name := range flowRequestSuperglobals {
				if strings.Contains(t.val, "$"+name) {
					strengthHere = reqIndirect // interpolated, context opaque
					srcHere = "interpolated $" + name
				}
			}
		}
		if strengthHere > reqNone {
			here := strengthHere
			if wrapperDepth > 0 && here == reqDirect {
				here = reqIndirect
			}
			if here > strength {
				strength = here
				src = srcHere
			}
		}
	}
	return strength, src
}

// flowSkipSubscript returns the index of the last token of a (possibly
// chained) subscript following the token at i, or i when none follows.
func flowSkipSubscript(arg []flowToken, i int) int {
	j := i + 1
	for j+1 < len(arg) && arg[j].kind == 'o' && arg[j].val == "[" {
		// Skip to the matching ']'.
		depth := 0
		k := j
		for k < len(arg) {
			if arg[k].kind == 'o' && arg[k].val == "[" {
				depth++
			} else if arg[k].kind == 'o' && arg[k].val == "]" {
				depth--
				if depth == 0 {
					break
				}
			}
			k++
		}
		j = k + 1
	}
	return j - 1
}

// flowDirectRequest is the boolean wrapper for callers that only need a
// yes/no answer (variable-injection indicators, parse_str/extract).
func flowDirectRequest(arg []flowToken, vars map[string]*flowVar) (bool, string) {
	s, src := flowRequestProbe(arg, vars)
	return s >= reqIndirect, src
}

// flowSourceLine finds the line of the first request source in arg.
func flowSourceLine(arg []flowToken, vars map[string]*flowVar, src []byte) int {
	for _, t := range arg {
		if t.kind == 'v' && flowRequestSuperglobals[t.val] {
			return lineOfSource(src, t.pos)
		}
		if t.kind == 'v' {
			if v, ok := vars[t.val]; ok && v.isRequest {
				return v.line
			}
		}
	}
	return 0
}

// flowWriteLine returns the recorded line of the write to a target variable.
func flowWriteLine(vars map[string]*flowVar, name string) int {
	if v, ok := vars[name]; ok {
		return v.line
	}
	return 0
}

// flowVarRefs lists distinct variable names referenced in toks.
func flowVarRefs(toks []flowToken) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range toks {
		if t.kind == 'v' && !seen[t.val] {
			seen[t.val] = true
			out = append(out, t.val)
		}
	}
	return out
}

// flowArgTokens returns the tokens inside the parentheses that open at
// index open (toks[open].val == "("), bounded by maxFlowArgTokens. When the
// window is exceeded the collected prefix is returned: bounded work, and the
// leading tokens carry the argument head, which is what the correlation
// rules read.
func flowArgTokens(toks []flowToken, open int) []flowToken {
	if open >= len(toks) || toks[open].kind != 'o' || toks[open].val != "(" {
		// include without parentheses: expression runs to the statement end.
		if open < len(toks) {
			rest := toks[open:]
			if len(rest) > maxFlowArgTokens {
				rest = rest[:maxFlowArgTokens]
			}
			return rest
		}
		return nil
	}
	depth := 0
	out := make([]flowToken, 0, 8)
	for i := open; i < len(toks); i++ {
		t := toks[i]
		if t.kind == 'o' {
			switch t.val {
			case "(":
				depth++
				if depth == 1 {
					continue
				}
			case ")":
				depth--
				if depth == 0 {
					return out
				}
			}
		}
		if depth >= 1 {
			out = append(out, t)
			if len(out) >= maxFlowArgTokens {
				return out
			}
		}
	}
	return out
}

// flowLooksRemoteURL reports whether a string literal looks like a remote
// URL (http, https, ftp schemes only; php://input is handled as request
// input elsewhere).
func flowLooksRemoteURL(s string) bool {
	for _, scheme := range []string{"http://", "https://", "ftp://"} {
		if strings.Contains(s, scheme) {
			return true
		}
	}
	return false
}

// flowReconstructName evaluates a bounded constant-name expression built
// from string literals, chr() of literal integers and str_rot13 of literals,
// joined by ".". It returns the reconstructed string and whether the whole
// RHS was such a constant expression. No decoder is ever executed: encoded
// names that would require base64/gzinflate evaluation are not reconstructed
// and stay invisible to this rule (honest limitation).
func flowReconstructName(rhs []flowToken) (string, bool) {
	if len(rhs) == 0 || len(rhs) > 33 {
		return "", false
	}
	var b strings.Builder
	for i := 0; i < len(rhs); i++ {
		t := rhs[i]
		switch t.kind {
		case 's':
			if t.interp || len(t.val) > maxFlowStringLit {
				return "", false
			}
			b.WriteString(strings.Trim(t.val, "'\""))
		case 'i':
			// chr(123) or str_rot13("text")
			if i+2 < len(rhs) && rhs[i+1].kind == 'o' && rhs[i+1].val == "(" {
				if t.val == "chr" && rhs[i+2].kind == 'n' {
					n := 0
					for _, c := range rhs[i+2].val {
						if c < '0' || c > '9' {
							return "", false
						}
						n = n*10 + int(c-'0')
						if n > 255 {
							return "", false
						}
					}
					b.WriteString(string(rune(n)))
					// skip to closing paren
					if i+3 < len(rhs) && rhs[i+3].kind == 'o' && rhs[i+3].val == ")" {
						i += 3
						continue
					}
					return "", false
				}
				if t.val == "str_rot13" && rhs[i+2].kind == 's' && !rhs[i+2].interp {
					b.WriteString(flowRot13(strings.Trim(rhs[i+2].val, "'\"")))
					if i+3 < len(rhs) && rhs[i+3].kind == 'o' && rhs[i+3].val == ")" {
						i += 3
						continue
					}
					return "", false
				}
			}
			return "", false
		case 'o':
			if t.val == "." {
				continue
			}
			return "", false
		default:
			return "", false
		}
	}
	out := b.String()
	if out == "" || len(out) > maxFlowNameLen {
		return "", false
	}
	return out, true
}

// flowRot13 applies ROT13 to ASCII letters.
func flowRot13(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			b[i] = 'A' + (c-'A'+13)%26
		}
	}
	return string(b)
}

// flowStatements splits the code positions of src into statements. Statement
// boundaries are ";" at parenthesis depth 0 and braces. String bodies (both
// quotes) are single tokens; double-quoted bodies and heredocs keep their
// interpolation flag. Tokens carry their source position so line numbers are
// exact.
func flowStatements(src []byte, prof lexProfile) [][]flowToken {
	n := len(src)
	var out [][]flowToken
	cur := make([]flowToken, 0, 16)
	depth := 0
	flush := func() {
		if len(cur) > 0 {
			// Copy: cur is reused via cur[:0], so appending the header alone
			// would alias one backing array across all statements and
			// silently corrupt every previously collected statement.
			cp := make([]flowToken, len(cur))
			copy(cp, cur)
			out = append(out, cp)
			if len(out) >= maxFlowStatements {
				cur = nil
				return
			}
		}
		cur = cur[:0]
	}
	i := 0
	for i < n && len(out) < maxFlowStatements {
		cl := prof.classes[i]
		switch cl {
		case classCode:
			c := src[i]
			switch {
			case c == btDollar && i+1 < n && isIdentByte(src[i+1]):
				j := i + 1
				for j < n && isIdentByte(src[j]) {
					j++
				}
				cur = append(cur, flowToken{kind: 'v', val: string(src[i+1 : j]), pos: i})
				i = j
			case isIdentStart(c):
				j := i
				for j < n && isIdentByte(src[j]) {
					j++
				}
				cur = append(cur, flowToken{kind: 'i', val: string(src[i:j]), pos: i})
				i = j
			case c >= '0' && c <= '9':
				j := i
				for j < n && src[j] >= '0' && src[j] <= '9' {
					j++
				}
				cur = append(cur, flowToken{kind: 'n', val: string(src[i:j]), pos: i})
				i = j
			case c == btSQ || c == btDQ:
				body, interp, next := flowReadString(src, i, prof)
				cur = append(cur, flowToken{kind: 's', val: body, interp: interp, pos: i})
				i = next
			case c == btTick:
				// Backtick body: handled by backtickFindings; skip here.
				i = skipQuoted(src, i, btTick)
			default:
				if c == btSpace || c == btNL || c == btTab || c == byte(13) {
					// Whitespace never carries semantics at token level;
					// dropping it keeps adjacency patterns (var "=" var,
					// "==", "=>") intact regardless of source formatting.
					i++
					continue
				}
				if c == '(' {
					depth++
				}
				if c == ')' && depth > 0 {
					depth--
				}
				if c == ';' && depth == 0 {
					flush()
					i++
					continue
				}
				if c == '{' || c == '}' {
					flush()
					i++
					continue
				}
				cur = append(cur, flowToken{kind: 'o', val: string(c), pos: i})
				i++
			}
		case classSQ, classDQ, classHeredoc, classNowdoc, classBacktick, classComment, classNonPHP, classTag:
			// These are consumed together with their openers above; any
			// stray bytes (e.g. inside malformed regions) are skipped.
			i++
		}
	}
	flush()
	return out
}

// flowReadString reads the string body starting at the opening quote at i
// and returns the body, whether it interpolates, and the index past the
// closing quote.
func flowReadString(src []byte, i int, prof lexProfile) (string, bool, int) {
	quote := src[i]
	interp := quote == btDQ
	j := i + 1
	n := len(src)
	start := j
	for j < n {
		if prof.classes[j] == classCode && src[j] == quote {
			return string(src[start:j]), interp, j + 1
		}
		if src[j] == btBS && j+1 < n {
			j += 2
			continue
		}
		j++
	}
	return string(src[start:n]), interp, n
}

func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == btUnder
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// sortFlowStrings is a tiny deterministic sort for indicator names.
func sortFlowStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
