package analyzer

import (
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// vendorprecision_test.go locks in every false-positive class observed in the
// Phase 3.2 vendor audit (Laminas, phpseclib, Symfony, PHPMailer, voku,
// web-token) and every real capability signal that must survive. Each test
// mirrors one concrete vendor code pattern; nothing is executed.

func aggregateOf(fs []finding.Finding) *finding.Finding {
	for i := range fs {
		if fs[i].Title == "Suspicious PHP code" {
			return &fs[i]
		}
	}
	return nil
}

func evidenceOf(fs []finding.Finding) string {
	var b strings.Builder
	for i := range fs {
		b.WriteString(fs[i].Evidence)
		b.WriteString(" || ")
	}
	return b.String()
}

// --- false-positive classes eliminated by the lexical views ---

func TestEvalOnlyInsideStringLiteralNoFinding(t *testing.T) {
	// DebugClassLoader pattern: the only "eval(" occurrences are a PHP
	// string literal naming the eval'd-code filename suffix and a comment.
	src := "<?php" + regNL +
		"if (!isset($dirFiles[$file]) && str_ends_with($file, ') : eval()' . chr(39) . 'd code')) {" + regNL +
		"    // Get the file name from \"file_name.php(123) : eval()'d code\"" + regNL +
		"    $file = substr($file, 0, -strlen(') : eval()' . chr(39) . 'd code'));" + regNL +
		"}" + regNL
	if fs := AnalyzeBytes("debug_loader.php", []byte(src)); len(fs) != 0 {
		t.Fatalf("string/comment eval mentions are not invocations: %+v", fs)
	}
}

func TestEvalOnlyInsideCommentNoFinding(t *testing.T) {
	src := "<?php" + regNL +
		"// Legacy note: eval() was removed from this helper in 2.3." + regNL +
		"/* eval(base64_decode($x)) is forbidden by policy */" + regNL +
		"echo 'ok';" + regNL
	if fs := AnalyzeBytes("legacy.php", []byte(src)); len(fs) != 0 {
		t.Fatalf("comment-only eval mentions must stay silent: %+v", fs)
	}
}

func TestCurlExecIsNotShellExecution(t *testing.T) {
	// CurlHttpClient pattern: "exec(" as a suffix of curl_multi_exec must
	// never satisfy the operating-system execution signal.
	src := "<?php" + regNL +
		"while (CURLM_CALL_MULTI_PERFORM === curl_multi_exec($multi->handle, $active)) {" + regNL +
		"    curl_exec($h);" + regNL +
		"}" + regNL
	if fs := AnalyzeBytes("curl.php", []byte(src)); len(fs) != 0 {
		t.Fatalf("cURL transfer functions are not OS execution: %+v", fs)
	}
}

func TestDocblockExecExampleNoFinding(t *testing.T) {
	// phpseclib SSH Agent pattern: usage examples inside a docblock.
	src := "<?php" + regNL +
		"/**" + regNL +
		" *    echo $ssh->exec('pwd');" + regNL +
		" *    echo $ssh->exec('ls -la');" + regNL +
		" */" + regNL +
		"$sock = fsockopen('unix:///tmp/agent.sock');" + regNL
	if fs := AnalyzeBytes("agent.php", []byte(src)); len(fs) != 0 {
		t.Fatalf("docblock examples are not invocations: %+v", fs)
	}
}

// --- assert() precision: argument kind decides ---

func TestExpressionAssertIsBenign(t *testing.T) {
	// The Laminas / voku / web-token pattern: boolean-expression asserts.
	cases := map[string]string{
		"laminas_count":    "<?php" + regNL + "assert(count($parts) >= 2);" + regNL,
		"voku_namespaced":  "<?php" + regNL + "\\assert(\\is_string($str_encoded));" + regNL,
		"voku_comparison":  "<?php" + regNL + "\\assert($str !== '');" + regNL,
		"jwt_instanceof":   "<?php" + regNL + "assert($key instanceof RSASSAPSSPrivateKey);" + regNL,
		"jwt_with_message": "<?php" + regNL + "assert(is_string($crv), 'Unsupported key type.');" + regNL,
	}
	for name, src := range cases {
		if fs := AnalyzeBytes(name+".php", []byte(src)); len(fs) != 0 {
			t.Errorf("%s: boolean-expression assert must be benign: %+v", name, fs)
		}
	}
}

func TestStringAssertDetected(t *testing.T) {
	// The genuinely dangerous form: a quoted string argument is evaluated
	// as PHP code (deprecated since PHP 7.2 but real in older runtimes).
	// Combined with a user-input read the pair crosses the aggregate
	// threshold exactly like the historical scoring policy requires.
	src := "<?php" + regNL +
		"assert('system(" + sigil() + "x);');" + regNL +
		"$" + "c = " + sigil() + "_GET['c'];" + regNL
	fs := AnalyzeBytes("stringassert.php", []byte(src))
	agg := aggregateOf(fs)
	if agg == nil {
		t.Fatalf("assert('...') must produce a finding: %+v", fs)
	}
	if !strings.Contains(agg.Evidence, "assert() with a string argument") {
		t.Fatalf("evidence must name the string-assert rule: %q", agg.Evidence)
	}
}

func TestSuperglobalAssertIsCritical(t *testing.T) {
	src := "<?php" + regNL + "assert(" + sigil() + "_GET['cmd']);" + regNL
	fs := AnalyzeBytes("assertget.php", []byte(src))
	agg := aggregateOf(fs)
	if agg == nil {
		t.Fatalf("assert($_GET[...]) must be detected: %+v", fs)
	}
	if agg.Severity != finding.Critical {
		t.Fatalf("severity=%s, want CRITICAL", agg.Severity)
	}
	if !strings.Contains(agg.Evidence, "assert() evaluates user-controlled input") {
		t.Fatalf("evidence=%q", agg.Evidence)
	}
}

func TestBareVariableAssertContributesLowSignal(t *testing.T) {
	// assert($code) could evaluate a string at runtime: a LOW capability
	// signal that surfaces when combined with other behaviour.
	src := "<?php" + regNL +
		"eval(" + sigil() + "in);" + regNL +
		"assert(" + sigil() + "code);" + regNL
	fs := AnalyzeBytes("assertvar.php", []byte(src))
	agg := aggregateOf(fs)
	if agg == nil {
		t.Fatalf("eval + assert($var) must produce a finding: %+v", fs)
	}
	if !strings.Contains(agg.Evidence, "assert() with a bare variable argument") {
		t.Fatalf("evidence must name the bare-variable assert rule: %q", agg.Evidence)
	}
}

// --- invocation versus definition ---

func TestFunctionDefinitionIsNotAnInvocation(t *testing.T) {
	// phpseclib Strings.php pattern: a polyfill method named base64_decode.
	src := "<?php" + regNL +
		"class Strings {" + regNL +
		"    public static function base64_decode($data)" + regNL +
		"    {" + regNL +
		"        return function_exists('base64_decode') ? \\base64_decode($data) : self::safe($data);" + regNL +
		"    }" + regNL +
		"}" + regNL
	if fs := AnalyzeBytes("polyfill.php", []byte(src)); len(fs) != 0 {
		t.Fatalf("a definition alone is a capability, not an executed behaviour: %+v", fs)
	}
}

func TestDefinitionEvidenceSeparatedFromInvocation(t *testing.T) {
	// The real phpseclib Strings.php combination: a real eval() invocation
	// plus an unrelated base64_decode definition. The evidence must keep
	// the two apart instead of claiming base64_decode was called.
	src := "<?php" + regNL +
		"function splitX($xor, $part)" + regNL +
		"{" + regNL +
		"    return $xor ^ eval('return 0b' . $part . ';');" + regNL +
		"}" + regNL +
		"class Strings {" + regNL +
		"    public static function base64_decode($data) { return $data; }" + regNL +
		"}" + regNL
	fs := AnalyzeBytes("strings.php", []byte(src))
	agg := aggregateOf(fs)
	if agg == nil {
		t.Fatalf("real eval invocation must produce a finding: %+v", fs)
	}
	if !strings.Contains(agg.Evidence, "dynamic code execution via eval()") {
		t.Fatalf("eval invocation evidence missing: %q", agg.Evidence)
	}
	if !strings.Contains(agg.Evidence, "capability_definition") ||
		!strings.Contains(agg.Evidence, "base64_decode") ||
		!strings.Contains(agg.Evidence, "not invoked here") {
		t.Fatalf("definition must be recorded separately: %q", agg.Evidence)
	}
}

// --- dynamic dispatch visibility ---

func TestDynamicDispatchQuotedNameDetected(t *testing.T) {
	// A quoted dangerous function name is dispatch capability; combined
	// with a real call the evidence must name it.
	src := "<?php" + regNL +
		"$" + "f = 'base64_decode';" + regNL +
		"eval(" + sigil() + "in);" + regNL
	fs := AnalyzeBytes("dispatch.php", []byte(src))
	agg := aggregateOf(fs)
	if agg == nil {
		t.Fatalf("dispatch + eval must produce a finding: %+v", fs)
	}
	if !strings.Contains(agg.Evidence, "dynamic_ref") {
		t.Fatalf("dynamic_ref evidence missing: %q", agg.Evidence)
	}
}

func TestCapabilityProbeStringNotDispatchEvidence(t *testing.T) {
	// Joomla extract.php pattern: function_exists('base64_decode') is a
	// capability probe, not dynamic dispatch, while the real call in the
	// same file stays a genuine decode invocation.
	src := "<?php" + regNL +
		"if (\\function_exists('base64_decode')) { $s = base64_decode($s); }" + regNL +
		"$z = gzinflate($raw);" + regNL +
		"$in = " + sigil() + "_REQUEST['d'];" + regNL
	fs := AnalyzeBytes("probe.php", []byte(src))
	if agg := aggregateOf(fs); agg == nil {
		t.Fatalf("the real base64_decode call must still fire: %+v", fs)
	} else if strings.Contains(agg.Evidence, "dynamic_ref") {
		t.Fatalf("function_exists argument must not be dispatch evidence: %q", agg.Evidence)
	}
}

// --- vendor trust is never automatic ---

func TestVendorPathPositiveThreatStillDetected(t *testing.T) {
	// A real webshell inside a vendor-looking path must stay CRITICAL: no
	// directory allowlist and no vendor trust exists.
	src := "<?php" + regNL + "eval(base64_decode(" + sigil() + "_POST['c']));" + regNL
	fs := AnalyzeBytes("/srv/site/libraries/vendor/acme/src/gateway.php", []byte(src))
	agg := aggregateOf(fs)
	if agg == nil {
		t.Fatalf("vendor-path webshell must be detected: %+v", fs)
	}
	if agg.Severity != finding.Critical {
		t.Fatalf("severity=%s, want CRITICAL", agg.Severity)
	}
	if !strings.Contains(agg.Evidence, "evaluates a decoded blob") {
		t.Fatalf("encoded_eval evidence missing: %q", agg.Evidence)
	}
}

func TestCleanIntegrityStatusHasNoAnalyzerEffect(t *testing.T) {
	// The analyzer has no integrity input at all: the same bytes produce
	// the same findings regardless of any checksum status a caller holds.
	src := "<?php" + regNL + "system(" + sigil() + "_GET['cmd']);" + regNL
	withRef := AnalyzeBytes("clean-core.php", []byte(src))
	if len(withRef) == 0 || withRef[0].Severity != finding.Critical {
		t.Fatalf("suspicious code must be reported regardless of integrity status: %+v", withRef)
	}
}

// --- metadata: rule ids and line numbers ---

func TestRuleAndLineMetadataPresent(t *testing.T) {
	src := "<?php" + regNL +
		"// neutral line" + regNL +
		"// another neutral line" + regNL +
		"system(" + sigil() + "_GET['cmd']);" + regNL +
		"$" + "out = " + tick() + "id" + tick() + ";" + regNL
	fs := AnalyzeBytes("meta.php", []byte(src))
	// Phase 4: aggregate + backtick + established request-to-shell flow.
	if len(fs) != 3 {
		t.Fatalf("expected aggregate + backtick + correlation findings, got %+v", fs)
	}
	for i := range fs {
		if fs[i].Rule == "" {
			t.Errorf("finding %d (%s) has no rule id", i, fs[i].Title)
		}
		if fs[i].Line <= 0 {
			t.Errorf("finding %d (%s) has no line number", i, fs[i].Title)
		}
	}
	if fs[0].Line != 4 {
		t.Errorf("aggregate line=%d, want 4 (the system() call)", fs[0].Line)
	}
	if fs[1].Line != 5 {
		t.Errorf("backtick line=%d, want 5", fs[1].Line)
	}
	if fs[0].Rule != "php-signals" || fs[1].Rule != "php-backtick" {
		t.Errorf("rule ids: %q / %q", fs[0].Rule, fs[1].Rule)
	}
}

// --- classification is visible in the finding stream ---

func TestClassificationFindingsCarryRules(t *testing.T) {
	fs := AnalyzeBytes("from.cp0999.php", charsetTableFixture(10))
	if len(fs) != 1 || fs[0].Rule != "php-embedded-binary" {
		t.Fatalf("embedded-binary rule missing: %+v", fs)
	}
	fs = AnalyzeBytes("resource.php", append([]byte("MZ\x90\x00"), append(binaryBlob(2048), []byte("<?php")...)...))
	if len(fs) != 1 || fs[0].Rule != "php-binary-resource" {
		t.Fatalf("binary-resource rule missing: %+v", fs)
	}
}

// --- existing dangerous fixtures keep firing (positive regression) ---

func TestGenuineThreatMatrixStillDetected(t *testing.T) {
	type threatCase struct {
		src   string
		want  finding.Severity
		title string
	}
	cases := map[string]threatCase{
		"eval_post":        {"<?php" + regNL + " eval(base64_decode(" + sigil() + "_POST['c']));" + regNL, finding.Critical, "Suspicious PHP code"},
		"system_get":       {"<?php" + regNL + " system(" + sigil() + "_GET['cmd']);" + regNL, finding.Critical, "Suspicious PHP code"},
		"shell_exec_post":  {"<?php" + regNL + " shell_exec(" + sigil() + "_POST['c']);" + regNL, finding.Critical, "Suspicious PHP code"},
		"passthru_request": {"<?php" + regNL + " passthru(" + sigil() + "_REQUEST['c']);" + regNL, finding.Critical, "Suspicious PHP code"},
		// proc_open is scored by the shell capability signal, not the
		// superglobal_shell rule (historical semantics, preserved).
		"proc_open_get":   {"<?php" + regNL + " proc_open(" + sigil() + "_GET['c'], $d, $e);" + regNL, finding.Medium, "Suspicious PHP code"},
		"plain_eval":      {"<?php" + regNL + " eval(base64_decode('ZWNobyAiaGkiOw=='));" + regNL, finding.Critical, "Suspicious PHP code"},
		"gzinflate_chain": {"<?php" + regNL + "eval(gzinflate(base64_decode('H4sIA')));" + regNL, finding.Critical, "Suspicious PHP code"},
		"backtick_exec":   {"<?php" + regNL + "$" + "o = " + tick() + "id" + tick() + ";" + regNL, finding.High, "PHP backtick shell execution"},
		"preg_replace_e":  {"<?php" + regNL + "$s = preg_replace('/a/e', $c, $s);" + regNL + "$in = " + sigil() + "_GET['c'];" + regNL, finding.High, "Suspicious PHP code"},
		"long_base64_blob": {"<?php" + regNL + "$d = '" + strings.Repeat("QUJD", 120) + "';" + regNL +
			"$f = " + sigil() + "_GET['f'];" + regNL, finding.Medium, "Suspicious PHP code"},
		"create_function_call": {"<?php" + regNL + "$" + "f = create_function('$a', 'return $a;');" + regNL + "$" + "g = " + sigil() + "_GET['x'];" + regNL, finding.Medium, "Suspicious PHP code"},
	}
	for name, tc := range cases {
		fs := AnalyzeBytes(name+".php", []byte(tc.src))
		var hit *finding.Finding
		for i := range fs {
			if fs[i].Title == tc.title && fs[i].Severity == tc.want {
				hit = &fs[i]
				break
			}
		}
		if hit == nil {
			t.Errorf("%s: no %s/%s finding in %+v", name, tc.want, tc.title, fs)
		}
	}
}

// --- existing benign shapes stay clean (negative regression) ---

func TestBenignMatrixStillClean(t *testing.T) {
	cases := map[string]string{
		"plain_echo":         "<?php" + regNL + "echo 'hello world';" + regNL,
		"base64_roundtrip":   "<?php" + regNL + "$" + "e = base64_encode($" + "d);" + regNL + "$" + "r = base64_decode($" + "e);" + regNL,
		"json_decode":        "<?php" + regNL + "$" + "a = json_decode($" + "raw, true);" + regNL,
		"isset_checks":       "<?php" + regNL + "if (isset(" + sigil() + "_GET['page'])) { $p = " + sigil() + "_GET['page']; }" + regNL,
		"curl_transfer":      "<?php" + regNL + "$" + "r = curl_exec($" + "ch);" + regNL,
		"db_exec_wrapper":    "<?php" + regNL + "$" + "n = $" + "db->exec($" + "sql);" + regNL,
		"assert_count":       "<?php" + regNL + "assert(count($" + "parts) >= 2);" + regNL,
		"preg_replace_plain": "<?php" + regNL + "$" + "s = preg_replace('/x/', 'y', $" + "s);" + regNL,
		"fwrite_plain":       "<?php" + regNL + "fwrite($" + "fh, $" + "line);" + regNL,
		"str_rot13_label":    "<?php" + regNL + "$" + "l = str_rot13('Label');" + regNL,
	}
	for name, src := range cases {
		if fs := AnalyzeBytes(name+".php", []byte(src)); len(fs) != 0 {
			t.Errorf("%s: false positive: %+v", name, fs)
		}
	}
}
