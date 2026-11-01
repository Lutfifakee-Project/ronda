package analyzer

import (
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// The short echo tag is a plain constant; backticks and dollar signs in this
// file come from tick() and sigil() so the test source carries no fragile
// characters.
const seOpen = "<?="

// --- positive: files whose only opening tag is the short echo tag ---

func TestShortEchoBacktickStatic(t *testing.T) {
	src := seOpen + " " + tick() + "id" + tick() + " ?>\n"
	found := AnalyzeBytes("shortecho_static.php", []byte(src))
	if len(found) != 1 {
		t.Fatalf("expected 1 finding, got %d (%+v)", len(found), found)
	}
	if found[0].Title != "PHP backtick shell execution" {
		t.Fatalf("title=%s", found[0].Title)
	}
	if found[0].Severity != finding.High {
		t.Fatalf("severity=%s, want HIGH", found[0].Severity)
	}
	if !strings.Contains(found[0].Evidence, "static command") {
		t.Fatalf("evidence=%q", found[0].Evidence)
	}
}

func TestShortEchoSystemSuperglobal(t *testing.T) {
	src := seOpen + " system(" + sigil() + "_GET['cmd']) ?>\n"
	found := AnalyzeBytes("shortecho_get.php", []byte(src))
	// Phase 4: the established request-to-shell flow adds a second,
	// correlation-level finding next to the aggregate signal finding.
	if len(found) != 2 {
		t.Fatalf("expected aggregate + correlation findings, got %d (%+v)", len(found), found)
	}
	if found[0].Title != "Suspicious PHP code" {
		t.Fatalf("title=%s", found[0].Title)
	}
	if found[0].Severity != finding.Critical {
		t.Fatalf("severity=%s, want CRITICAL", found[0].Severity)
	}
	if !strings.Contains(found[0].Evidence, "runs user-controlled shell commands") {
		t.Fatalf("evidence=%q", found[0].Evidence)
	}
}

// TestShortEchoMixedHTMLShellExec is the regression case for this task: the
// file never contains the canonical opening tag, so before short echo support
// it produced no findings at all.
func TestShortEchoMixedHTMLShellExec(t *testing.T) {
	src := "<html>\n<body>" + seOpen + " shell_exec(" + sigil() + "_POST['cmd']) ?></body>\n</html>\n"
	found := AnalyzeBytes("shortecho_html.php", []byte(src))
	if len(found) != 2 {
		t.Fatalf("expected aggregate + correlation findings, got %d (%+v)", len(found), found)
	}
	if found[0].Title != "Suspicious PHP code" {
		t.Fatalf("title=%s", found[0].Title)
	}
	// shell_exec() is part of the superglobal_shell signal, so user-controlled
	// input inside the call upgrades the severity to CRITICAL.
	if found[0].Severity != finding.Critical {
		t.Fatalf("severity=%s, want CRITICAL", found[0].Severity)
	}
	if !strings.Contains(found[0].Evidence, "runs user-controlled shell commands") {
		t.Fatalf("evidence=%q", found[0].Evidence)
	}
}

// TestShortEchoOnlyFileOrdinaryAnalysis proves ordinary heuristic analysis
// works on a file that contains only short echo tags.
func TestShortEchoOnlyFileOrdinaryAnalysis(t *testing.T) {
	src := seOpen + " eval(" + sigil() + "_POST['c']) ?>\n"
	found := AnalyzeBytes("shortecho_eval.php", []byte(src))
	if len(found) != 2 {
		t.Fatalf("expected aggregate + correlation findings, got %d (%+v)", len(found), found)
	}
	if found[0].Severity != finding.Critical {
		t.Fatalf("severity=%s, want CRITICAL", found[0].Severity)
	}
	if !strings.Contains(found[0].Evidence, "evaluates user-controlled input") {
		t.Fatalf("evidence=%q", found[0].Evidence)
	}
	// Phase 4 correlation: request input to eval() is an established flow.
	if found[1].Rule != "php-source-to-code" || found[1].Confidence != "established" {
		t.Fatalf("correlation finding missing: %+v", found[1])
	}
}

// TestShortEchoMultipleSectionsBothTags covers a file with several PHP and
// HTML sections and both supported opening tags.
func TestShortEchoMultipleSectionsBothTags(t *testing.T) {
	d := sigil()
	tickc := tick()
	src := "<html>\n" +
		"<?php " + d + "t = 'page'; ?>\n" +
		"<h1>" + seOpen + " " + tickc + "id" + tickc + " ?></h1>\n" +
		"<?php echo strtoupper(" + d + "t); ?>\n" +
		"<p>" + seOpen + " " + tickc + "whoami" + tickc + " ?></p>\n" +
		"</html>\n"
	found := AnalyzeBytes("shortecho_sections.php", []byte(src))
	bt := backtickFindingsOf(found)
	if len(bt) != 2 {
		t.Fatalf("expected 2 backtick findings across sections, got %d (%+v)", len(bt), found)
	}
	for i := 0; i < len(bt); i++ {
		if bt[i].Severity != finding.High {
			t.Fatalf("finding %d severity=%s, want HIGH", i, bt[i].Severity)
		}
	}
}

func TestShortEchoCoexistsWithAggregate(t *testing.T) {
	src := seOpen + " " + tick() + "id" + tick() + " ?>\n" +
		seOpen + " system(" + sigil() + "_GET['c']) ?>\n"
	found := AnalyzeBytes("shortecho_combo.php", []byte(src))
	// Phase 4: aggregate + backtick + established request-to-shell flow.
	if len(found) != 3 {
		t.Fatalf("expected aggregate + backtick + correlation findings, got %d (%+v)", len(found), found)
	}
	if found[0].Title != "Suspicious PHP code" {
		t.Fatalf("aggregate missing: %+v", found[0])
	}
	if found[1].Title != "PHP backtick shell execution" {
		t.Fatalf("backtick missing: %+v", found[1])
	}
	if found[2].Rule != "php-source-to-shell" {
		t.Fatalf("correlation finding missing: %+v", found[2])
	}
}

// TestShortEchoCloseTagInsideString pins transition correctness: a closing
// tag inside a PHP string does not end PHP mode, so the backtick after it is
// still code.
func TestShortEchoCloseTagInsideString(t *testing.T) {
	src := seOpen + " 'a?>' . " + tick() + "id" + tick() + " ?>\n"
	found := AnalyzeBytes("shortecho_str_close.php", []byte(src))
	if len(found) != 1 {
		t.Fatalf("expected 1 finding, got %d (%+v)", len(found), found)
	}
	if found[0].Title != "PHP backtick shell execution" {
		t.Fatalf("title=%s", found[0].Title)
	}
}

// TestShortEchoUnterminatedFinalTag covers PHP's optional closing tag.
func TestShortEchoUnterminatedFinalTag(t *testing.T) {
	src := seOpen + " " + tick() + "id" + tick() + ";\n"
	found := AnalyzeBytes("shortecho_open.php", []byte(src))
	if len(found) != 1 {
		t.Fatalf("expected 1 finding, got %d (%+v)", len(found), found)
	}
	if found[0].Title != "PHP backtick shell execution" {
		t.Fatalf("title=%s", found[0].Title)
	}
}

// TestShortEchoAnalyzeFileDiskPath proves the disk entry point works for a
// short-echo file as well (content is benign, so writing it is safe).
func TestShortEchoAnalyzeFileDiskPath(t *testing.T) {
	p := writeTemp(t, seOpen+" htmlspecialchars("+sigil()+"t) ?>\n")
	found, err := AnalyzeFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("expected no findings, got %+v", found)
	}
}

// --- negative: short echo support must not create false positives ---

func TestShortEchoNegativeContexts(t *testing.T) {
	d := sigil()
	tickc := tick()
	cases := map[string]string{
		// Backticks in plain HTML; the file never opens PHP.
		"html_only": "<html>\n<body>Run " + tickc + "id" + tickc + " now</body>\n</html>\n",
		// Backticks in HTML after a PHP section has closed.
		"html_after_close":           "<?php echo 'a'; ?>\n<p>see " + tickc + "id" + tickc + " docs</p>\n",
		"shortecho_html_after_close": seOpen + " 'a' ?>\n<p>see " + tickc + "id" + tickc + " docs</p>\n",
		// Backticks in HTML comments outside PHP.
		"html_comment": "<?php echo 'x'; ?>\n<!-- docs: " + tickc + "id" + tickc + " -->\n",
		// An XML processing instruction stays inline text; the legacy tag
		// after the question mark must not switch the lexer into PHP mode.
		"xml_processing_instruction": "<?php echo 'x'; ?>\n<?xml version=\"1.0\"?>\n<doc>markdown " + tickc + "code" + tickc + " span</doc>\n",
		// Backticks inside PHP strings.
		"single_quoted_string": seOpen + " 'use the " + tickc + "id" + tickc + " operator' ?>\n",
		"double_quoted_string": "<?php " + d + "s = \"see " + tickc + "id" + tickc + " docs\"; ?>\n",
		// Backticks inside PHP comments.
		"line_comment":  seOpen + " 'ok' // docs: " + tickc + "id" + tickc + " example\n?>\n",
		"block_comment": seOpen + " /* shell docs " + tickc + "id" + tickc + " */ 1 ?>\n",
		// Legitimate echo expressions.
		"legit_echo_expression": seOpen + " htmlspecialchars(" + d + "title) ?>\n",
		"legit_number_echo":     seOpen + " number_format(" + d + "total, 2) ?>\n",
		// Mixed HTML/PHP file without dangerous expressions.
		"mixed_html_clean": "<html>\n<?php " + d + "a = 'x'; ?>\n<body><h1>" + seOpen + " htmlspecialchars(" + d + "page['title']) ?></h1>\n</body>\n</html>\n",
		// Legacy short tag only: short_open_tag is off by default, so this
		// file is not analyzable PHP and must not be flagged.
		"legacy_short_tag_only": "<? echo " + tickc + "id" + tickc + "; ?>\n",
	}
	for name, src := range cases {
		if found := AnalyzeBytes(name+".php", []byte(src)); len(found) != 0 {
			t.Errorf("%s: false positive: %+v", name, found)
		}
	}
}
