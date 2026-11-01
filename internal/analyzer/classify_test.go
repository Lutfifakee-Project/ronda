package analyzer

import (
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// classify_test.go covers the five-way file classification required by the
// Phase 3.2 audit: PHP source, PHP with embedded binary data, binary
// resources with a PHP opening tag, text documentation and unknown formats.
// Every fixture is static data; nothing is executed.

// charsetTableFixture mirrors the real Symfony polyfill-iconv structure:
// "<?php static $data = array('...' => '...'); return $data;" where the
// string literals contain the raw code-page mapping bytes, including NUL.
func charsetTableFixture(rows int) []byte {
	var b strings.Builder
	b.WriteString("<?php" + regNL)
	b.WriteString("// Character set table generated from the official mapping." + regNL)
	b.WriteString("static $data = array(" + regNL)
	nul := string([]byte{0})
	for i := 0; i < rows; i++ {
		b.WriteString("    '" + strings.Repeat("A", 3) + nul + strings.Repeat("B", 4) + "' => '\\xC3\\xA9'," + regNL)
	}
	b.WriteString(");" + regNL)
	b.WriteString("return $data;" + regNL)
	return []byte(b.String())
}

func binaryBlob(size int) []byte {
	out := make([]byte, size)
	for i := range out {
		// Deterministic pseudo-random bytes including control characters.
		out[i] = byte((i*7 + 13) % 251)
	}
	return out
}

func findingByTitle(fs []finding.Finding, title string) *finding.Finding {
	for i := range fs {
		if fs[i].Title == title {
			return &fs[i]
		}
	}
	return nil
}

func TestClassifyClasses(t *testing.T) {
	cases := []struct {
		name string
		src  []byte
		want fileClass
	}{
		{"php source", []byte("<?php" + regNL + "echo 'hello';" + regNL), classPHPSource},
		{"php with embedded binary", charsetTableFixture(20), classPHPWithEmbeddedBinary},
		{"text documentation", []byte("Deployment notes:" + regNL + "run the migrator before switching traffic." + regNL), classTextDoc},
		{"text doc with shell commands", []byte("Restore recipe:" + regNL + "system( 'rm -rf /var/cache/app' );" + regNL + "exec('restart php-fpm');" + regNL), classTextDoc},
		{"binary without tag", binaryBlob(4096), classBinaryResource},
		{"binary with accidental tag", append([]byte("JFIF\x00\x01"), append(binaryBlob(2048), []byte("<?php")...)...), classBinaryResource},
		{"nul in code position", []byte("<?php" + regNL + "$a = 1;" + regNL + regNL + string([]byte{0}) + regNL + "echo $a;" + regNL), classUnknown},
		{"nul in inline html", []byte("<?php echo 'a'; ?>" + regNL + "text" + string([]byte{0}) + "more" + regNL), classUnknown},
		// Valid UTF-8 text in any language is never binary data.
		{"utf8 greek strings", []byte("<?php" + regNL + "$msg = 'Χαίετε κόσμε'; // Greek greeting" + regNL + "echo $msg;" + regNL), classPHPSource},
		{"utf8 cjk strings", []byte("<?php" + regNL + "echo '中文测试';" + regNL), classPHPSource},
		// Raw legacy-charset bytes inside string literals are the
		// non-NUL sibling of the Symfony charset tables.
		// rawBig5Fixture mirrors the real from.big5.php shape: many raw legacy
		// double-byte sequences inside single-quoted string literals.
		{"raw big5 table", func() []byte {
			var b []byte
			b = append(b, []byte("<?php"+regNL+"static $data = array("+regNL)...)
			for i := 0; i < 40; i++ {
				b = append(b, []byte("  '")...)
				b = append(b, 0xa1, byte(0x40+i)) // raw Big5 lead+follow pair
				b = append(b, []byte("' => '")...)
				b = append(b, []byte("\xc3\xa9")...) // valid UTF-8 text value
				b = append(b, []byte("',"+regNL)...)
			}
			b = append(b, []byte(");"+regNL+"return $data;"+regNL)...)
			return b
		}(), classPHPWithEmbeddedBinary},
	}
	for _, tc := range cases {
		got, st, ps := classifyBytes(tc.src)
		if got != tc.want {
			t.Errorf("%s: class=%s want %s (nul=%d/%d code=%d ratio=%.2f)", tc.name, got, tc.want, st.nulInString, st.nulInCode, ps.codeBytes, ps.printableRatio)
		}
	}
}

func TestTextDocumentationNoFindings(t *testing.T) {
	src := "Deployment notes:" + regNL +
		"The worker calls system( 'clearcache' ) during rotation and" + regNL +
		"shell_exec('drush cc all') is documented in the runbook." + regNL
	if fs := AnalyzeBytes("notes.php", []byte(src)); len(fs) != 0 {
		t.Fatalf("text documentation must not be analyzed as PHP: %+v", fs)
	}
}

// TestGenuineBinaryResourceNotPHPSource proves a binary blob carrying an
// accidental PHP opening tag is never parsed as PHP source: no signal runs
// over the bytes, so garbage cannot produce PHP malware evidence. The
// classification stays visible as an UNVERIFIED low-severity finding.
func TestGenuineBinaryResourceNotPHPSource(t *testing.T) {
	garbage := binaryBlob(8192)
	// Accidental PHP-like byte sequences inside the garbage, including a
	// dangerous-looking call and a superglobal read.
	copy(garbage[300:], "<?php")
	copy(garbage[900:], "eval(base64_decode(")
	copy(garbage[1500:], "$_POST['c']);")
	copy(garbage[2500:], "shell_exec(")

	fs := AnalyzeBytes("resource.php", garbage)
	if len(fs) != 1 {
		t.Fatalf("expected exactly 1 classification finding, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.Title != "Binary resource with PHP opening tag" {
		t.Fatalf("title=%q", f.Title)
	}
	if f.Status != finding.Unverified {
		t.Fatalf("status=%s, want UNVERIFIED (uncertainty must be preserved)", f.Status)
	}
	if f.Severity != finding.Low {
		t.Fatalf("severity=%s, want LOW", f.Severity)
	}
	if f.Rule != "php-binary-resource" {
		t.Fatalf("rule=%q", f.Rule)
	}
	if strings.Contains(f.Evidence, "eval") || strings.Contains(f.Evidence, "shell_exec") {
		t.Fatalf("binary garbage must not produce PHP signal evidence: %q", f.Evidence)
	}
	if !strings.Contains(f.Evidence, "not parsed as PHP source") {
		t.Fatalf("evidence must state the non-parse decision: %q", f.Evidence)
	}
}

func TestBinaryWithoutPHPByteSequence(t *testing.T) {
	if fs := AnalyzeBytes("blob.php", binaryBlob(5000)); len(fs) != 0 {
		t.Fatalf("binary without PHP tag and without NUL must stay silent: %+v", fs)
	}
}

// TestSymfonyCharsetTableClassification is the regression test for the 54
// real findings: a legitimate PHP character-set table must be classified as
// PHP source with embedded binary data, reported at LOW severity with an
// honest evidence line, and its PHP sections must remain analyzed.
func TestSymfonyCharsetTableClassification(t *testing.T) {
	src := charsetTableFixture(50)
	fs := AnalyzeBytes("from.cp037.php", src)
	if len(fs) != 1 {
		t.Fatalf("expected exactly the embedded-binary note, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.Title != "PHP file contains embedded binary data" {
		t.Fatalf("title=%q", f.Title)
	}
	if f.Severity != finding.Low {
		t.Fatalf("severity=%s, want LOW (embedded string data is not a HIGH malware indicator)", f.Severity)
	}
	if f.Rule != "php-embedded-binary" {
		t.Fatalf("rule=%q", f.Rule)
	}
	if !strings.Contains(f.Evidence, "string literals") || !strings.Contains(f.Evidence, "remain analyzed") {
		t.Fatalf("evidence incomplete: %q", f.Evidence)
	}
	if f.Line <= 0 {
		t.Fatalf("line must point at the first embedded byte, got %d", f.Line)
	}
}

// TestEmbeddedBinaryPHPStillAnalyzed is the critical combination: a charset
// table whose PHP section was tampered with must produce BOTH the
// embedded-data note AND the full CRITICAL signal finding. The old
// early-return behavior hid everything after the first NUL byte.
func TestEmbeddedBinaryPHPStillAnalyzed(t *testing.T) {
	src := append(charsetTableFixture(30), []byte("system("+sigil()+"_GET['cmd']);"+regNL)...)
	fs := AnalyzeBytes("tampered_table.php", src)
	// Phase 4: embedded-binary note + aggregate + established request-to-
	// shell correlation finding for the tampered PHP section.
	if len(fs) != 3 {
		t.Fatalf("expected embedded-binary note + aggregate + correlation, got %d: %+v", len(fs), fs)
	}
	if fs[0].Title != "PHP file contains embedded binary data" {
		t.Fatalf("first finding=%q", fs[0].Title)
	}
	agg := fs[1]
	if agg.Title != "Suspicious PHP code" || agg.Severity != finding.Critical {
		t.Fatalf("aggregate=%q/%s, want Suspicious PHP code/CRITICAL", agg.Title, agg.Severity)
	}
	if !strings.Contains(agg.Evidence, "runs user-controlled shell commands") {
		t.Fatalf("aggregate evidence must contain the superglobal shell signal: %q", agg.Evidence)
	}
}

// TestNullInCodePositionKeepsHighSeverity pins the dangerous end of the
// classification: NUL bytes in code position (malformed, truncated or
// obfuscated PHP) keep the original HIGH severity and explicit evidence.
func TestNullInCodePositionKeepsHighSeverity(t *testing.T) {
	src := []byte("<?php" + regNL + "$a = 1;" + regNL + string([]byte{0}) + regNL + "eval(base64_decode('x'));" + regNL)
	fs := AnalyzeBytes("corrupt.php", src)
	f := findingByTitle(fs, "PHP file contains binary data")
	if f == nil {
		t.Fatalf("HIGH binary-data finding missing: %+v", fs)
	}
	if f.Severity != finding.High {
		t.Fatalf("severity=%s, want HIGH", f.Severity)
	}
	if !strings.Contains(f.Evidence, "code position") {
		t.Fatalf("evidence must locate the NUL in code position: %q", f.Evidence)
	}
	// The analysis must also continue past the classification finding.
	if findingByTitle(fs, "Suspicious PHP code") == nil {
		t.Fatalf("code after the NUL must still be analyzed: %+v", fs)
	}
}

func TestMixedPHPAndHTMLClean(t *testing.T) {
	src := "<html>" + regNL + "<?php $t = 'page'; ?>" + regNL +
		"<h1><?= htmlspecialchars($t) ?></h1>" + regNL + "</html>" + regNL
	if fs := AnalyzeBytes("template.php", []byte(src)); len(fs) != 0 {
		t.Fatalf("mixed PHP/HTML template must stay clean: %+v", fs)
	}
}

// TestEmbeddedBinaryNoAggregateNoise pins that the real Symfony tables
// (data-only PHP) produce exactly one LOW finding and no signal aggregate.
func TestEmbeddedBinaryNoAggregateNoise(t *testing.T) {
	for rows := 1; rows <= 200; rows *= 4 {
		src := charsetTableFixture(rows)
		fs := AnalyzeBytes("table.php", src)
		if len(fs) != 1 || fs[0].Title != "PHP file contains embedded binary data" {
			t.Fatalf("rows=%d: unexpected findings %+v", rows, fs)
		}
	}
}
