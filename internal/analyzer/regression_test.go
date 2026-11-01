package analyzer

import (
	"testing"
)

func sigil() string { return string(rune(36)) }

func tick() string { return string(rune(96)) }

var regNL = string([]byte{10})

func negFixtures() map[string]string {
	t := tick()
	m := make(map[string]string)
	m["sql_backticks.php"] = "<?php" + regNL +
		"function q() { return 'SELECT " + t + "id" + t + ", " + t + "name" + t + " FROM " + t + "wp_options" + t + "'; }" + regNL +
		"function u() { return 'UPDATE " + t + "wp_posts" + t + " SET " + t + "x" + t + " = 1'; }" + regNL
	m["backtick_in_string.php"] = "<?php" + regNL +
		"function m() { return 'Use the " + t + "tag" + t + " column'; }" + regNL +
		"echo 'Run " + t + "make" + t + " in the shell';" + regNL
	m["doc_shell_keywords.php"] = "<?php" + regNL +
		"/**" + regNL +
		" * This helper does NOT run shell commands." + regNL +
		" * It documents system(), exec(), passthru() for education only." + regNL +
		" */" + regNL +
		"function docs() { return 'system exec shell_exec'; }" + regNL
	m["function_docs_examples.php"] = "<?php" + regNL +
		"// Example: base64_decode() is described here but never called on input." + regNL +
		"function examples() { return 'base64_decode gzinflate'; }" + regNL
	return m
}

func posFixtures() map[string]string {
	m := make(map[string]string)
	m["webshell_eval_post.php"] = "<?php" + regNL + " eval(base64_decode(" + sigil() + "_POST['c']));" + regNL
	m["cmd_shell_superglobal.php"] = "<?php" + regNL + " system(" + sigil() + "_GET['cmd']);" + regNL
	m["obfuscated_exec.php"] = "<?php" + regNL + "eval(gzinflate(base64_decode('H4sIA')));" + regNL
	m["encoded_eval.php"] = "<?php" + regNL + "eval(base64_decode('ZWNobyAiaGkiOw=='));" + regNL
	return m
}

func TestNegativeFixturesNoHigh(t *testing.T) {
	fx := negFixtures()
	for name, src := range fx {
		found := AnalyzeBytes(name, []byte(src))
		for i := 0; i < len(found); i++ {
			if found[i].Severity == "HIGH" || found[i].Severity == "CRITICAL" {
				t.Errorf("%s: false %s finding: %s", name, found[i].Severity, found[i].Evidence)
			}
		}
	}
}

func TestPositiveFixturesDetected(t *testing.T) {
	fx := posFixtures()
	for name, src := range fx {
		found := AnalyzeBytes(name, []byte(src))
		if len(found) == 0 {
			t.Errorf("%s: expected a finding, got none", name)
			continue
		}
		if found[0].Status != "SUSPICIOUS" {
			t.Errorf("%s: status=%s", name, found[0].Status)
		}
	}
}

func TestModifiedCoreStillScanned(t *testing.T) {
	src := "<?php" + regNL + sigil() + "wp_version = '6.4.2';" + regNL + "eval(" + sigil() + "_POST['x']);" + regNL
	found := AnalyzeBytes("version.php", []byte(src))
	if len(found) == 0 {
		t.Fatal("modified core with eval(POST) must be flagged")
	}
}

func TestCleanDocsNotFlagged(t *testing.T) {
	src := "<?php" + regNL + "// base64_decode is mentioned here only." + regNL + "echo 'hi';" + regNL
	found := AnalyzeBytes("clean.php", []byte(src))
	if len(found) != 0 {
		t.Fatalf("expected no findings, got %d", len(found))
	}
}
