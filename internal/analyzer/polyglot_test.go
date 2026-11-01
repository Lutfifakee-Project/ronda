package analyzer

// polyglot_test.go — Phase 4 §7: binary and polyglot classification. All
// fixtures are synthetic byte slices; nothing is written to disk or executed.

import (
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// appendedBlob builds raw non-text binary data (no NUL bytes, invalid UTF-8).
func appendedBlob(n int) []byte {
	b := make([]byte, 0, n)
	for i := 0; i < n; i++ {
		b = append(b, byte(0x80+(i%60)))
	}
	return b
}

// TestAppendedBinaryAfterClosingTag closes the Phase 3.2 known limitation:
// substantial non-NUL binary appended after the PHP source must be reported
// conservatively while the PHP sections stay fully analyzed.
func TestAppendedBinaryAfterClosingTag(t *testing.T) {
	src := "<?php\necho 'hello';\n?>\n" + string(appendedBlob(512))
	cls, st, ps := classifyBytes([]byte(src))
	if cls != classPHPWithAppendedBinary {
		t.Fatalf("class=%s, want php-with-appended-binary (nonTextInHTML=%d nonPHP=%d)",
			cls, st.nonTextInHTML, st.nonPHPBytes)
	}
	if !ps.structureIsPHP {
		t.Fatalf("php structure lost")
	}
	fs := AnalyzeBytes("appended.php", []byte(src))
	var note *finding.Finding
	for i := range fs {
		if fs[i].Rule == "php-appended-binary" {
			note = &fs[i]
		}
	}
	if note == nil {
		t.Fatalf("php-appended-binary finding missing: %+v", fs)
	}
	if note.Severity != finding.Low || note.Status != finding.Unverified {
		t.Fatalf("severity/status=%s/%s, want LOW/UNVERIFIED", note.Severity, note.Status)
	}
	if note.Category != "POLYGLOT_OR_BINARY_ANOMALY" {
		t.Fatalf("category=%q", note.Category)
	}
	// The PHP sections must remain fully analyzed: the echo statement alone
	// is clean, so exactly the classification finding exists.
	if len(fs) != 1 {
		t.Fatalf("clean PHP plus appended data must not gain behavior findings, got %+v", fs)
	}
}

// TestAppendedBinaryWithSuspiciousPHP proves both halves are visible: the
// polyglot note AND the behavior findings from the PHP section.
func TestAppendedBinaryWithSuspiciousPHP(t *testing.T) {
	src := "<?php\nsystem(" + string(rune(36)) + "_GET['c']);\n?>\n" + string(appendedBlob(300))
	fs := AnalyzeBytes("polyglot.php", []byte(src))
	hasNote, hasSignal := false, false
	for i := range fs {
		switch fs[i].Rule {
		case "php-appended-binary":
			hasNote = true
		case "php-signals", "php-source-to-shell":
			hasSignal = true
		}
	}
	if !hasNote || !hasSignal {
		t.Fatalf("polyglot note=%t behavior finding=%t: %+v", hasNote, hasSignal, fs)
	}
}

// TestBinaryInsidePHPRegionRaisesUnknown: substantial PHP source whose code
// region ends with a moderate non-NUL binary tail classifies as
// unknown/malformed and keeps HIGH — the Phase 3.2 non-NUL limitation.
func TestBinaryInsidePHPRegionRaisesUnknown(t *testing.T) {
	var b strings.Builder
	b.WriteString("<?php\n")
	for i := 0; i < 40; i++ {
		b.WriteString("$v" + string(rune('a'+i%26)) + " = 'line of real php code';\n")
	}
	src := b.String() + string(appendedBlob(100))
	cls, _, _ := classifyBytes([]byte(src))
	if cls != classUnknown {
		t.Fatalf("class=%s, want unknown", cls)
	}
	fs := AnalyzeBytes("code-binary.php", []byte(src))
	found := false
	for i := range fs {
		if fs[i].Rule == "php-binary-data" && fs[i].Severity == finding.High {
			found = true
		}
	}
	if !found {
		t.Fatalf("php-binary-data HIGH missing: %+v", fs)
	}
}

// TestBinaryDominantFileStaysBinaryResource: mostly-binary content with an
// accidental PHP region stays a binary resource (UNVERIFIED, not parsed as
// PHP source) — the classification keeps the honest conservative verdict.
func TestBinaryDominantFileStaysBinaryResource(t *testing.T) {
	src := "<?php\n$a = 1;\n" + string(appendedBlob(2000))
	cls, _, _ := classifyBytes([]byte(src))
	if cls != classBinaryResource {
		t.Fatalf("class=%s, want binary-resource", cls)
	}
	fs := AnalyzeBytes("dominant.php", []byte(src))
	if len(fs) != 1 || fs[0].Rule != "php-binary-resource" || fs[0].Status != finding.Unverified {
		t.Fatalf("expected single UNVERIFIED binary-resource finding, got %+v", fs)
	}
}

// TestSmallMojibakeStaysSilent: a handful of stray legacy-encoding bytes in
// the inline HTML never triggers the polyglot indicator.
func TestSmallMojibakeStaysSilent(t *testing.T) {
	src := "<?php echo 'caf" + string([]byte{0xE9}) + "'; ?>\n<p>na" + string([]byte{0xEF, 0xBD}) + "ve</p>\n"
	cls, _, _ := classifyBytes([]byte(src))
	if cls == classPHPWithAppendedBinary {
		t.Fatalf("stray mojibake must not classify as appended binary")
	}
	fs := AnalyzeBytes("mojibake.php", []byte(src))
	for i := range fs {
		if fs[i].Rule == "php-appended-binary" {
			t.Fatalf("mojibake must not produce the polyglot finding: %+v", fs[i])
		}
	}
}

// TestLegacyCharsetShareStaysBelowPolyglot: an old cp1252-style template
// whose HTML part is mostly valid text with moderate accents stays clean.
func TestLegacyCharsetShareStaysBelowPolyglot(t *testing.T) {
	var b strings.Builder
	b.WriteString("<?php echo $title; ?>\n<html><body>\n")
	for i := 0; i < 20; i++ {
		b.WriteString("<p>Legitimate paragraph with a few accented words caf")
		b.WriteString(string([]byte{0xE9})) // cp1252 é, invalid UTF-8
		b.WriteString(" and more regular text to dilute the share.</p>\n")
	}
	b.WriteString("</body></html>\n")
	fs := AnalyzeBytes("legacy.php", []byte(b.String()))
	for i := range fs {
		if fs[i].Rule == "php-appended-binary" {
			t.Fatalf("diluted legacy encoding must not trigger the polyglot rule: %+v", fs[i])
		}
	}
}

// TestPHPPolyglotHTMLKeepsAnalyzing: PHP plus ordinary HTML keeps analyzing
// both sections (positive PHP finding inside an HTML-heavy template).
func TestPHPPolyglotHTMLKeepsAnalyzing(t *testing.T) {
	src := "<html><body>\n<?php eval(" + string(rune(36)) + "_POST['x']); ?>\n</body></html>\n"
	fs := AnalyzeBytes("template.php", []byte(src))
	found := false
	for i := range fs {
		if fs[i].Severity == finding.Critical {
			found = true
		}
	}
	if !found {
		t.Fatalf("PHP inside HTML must stay analyzed: %+v", fs)
	}
}
