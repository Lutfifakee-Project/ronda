package analyzer

// rules_test.go — Phase 4 §9: the structured rule registry must be complete,
// stable and consistent with what the analyzer actually emits.

import (
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// TestRuleRegistryComplete: every rule the analyzer emits resolves to
// registry metadata with a valid category.
func TestRuleRegistryComplete(t *testing.T) {
	emitted := []string{
		"php-signals", "php-backtick", "php-binary-data",
		"php-embedded-binary", "php-binary-resource", "php-appended-binary",
		"php-source-to-shell", "php-source-to-code", "php-decoder-exec",
		"php-dynamic-call", "php-dynamic-include", "php-remote-write",
		"php-write-exec", "php-webshell-chain",
	}
	for _, id := range emitted {
		m, ok := RuleMetadata(id)
		if !ok {
			t.Errorf("rule %q missing from registry", id)
			continue
		}
		if m.ID != id {
			t.Errorf("rule %q registered under ID %q", id, m.ID)
		}
		if m.Name == "" || m.Description == "" || m.FPNotes == "" {
			t.Errorf("rule %q has incomplete metadata: %+v", id, m)
		}
		if m.Category == "" {
			t.Errorf("rule %q has no category", id)
		}
		if m.DefaultSeverity.Rank() == 0 {
			t.Errorf("rule %q has no default severity", id)
		}
	}
}

// TestRuleCategoriesStable: the categories match the Phase 4 taxonomy.
func TestRuleCategoriesStable(t *testing.T) {
	want := map[string]string{
		"php-signals":         "BROAD_SIGNAL",
		"php-backtick":        "COMMAND_EXECUTION",
		"php-binary-data":     "POLYGLOT_OR_BINARY_ANOMALY",
		"php-embedded-binary": "POLYGLOT_OR_BINARY_ANOMALY",
		"php-binary-resource": "POLYGLOT_OR_BINARY_ANOMALY",
		"php-appended-binary": "POLYGLOT_OR_BINARY_ANOMALY",
		"php-source-to-shell": "COMMAND_EXECUTION",
		"php-source-to-code":  "CODE_INJECTION",
		"php-decoder-exec":    "OBFUSCATION",
		"php-dynamic-call":    "DYNAMIC_EXECUTION",
		"php-dynamic-include": "DYNAMIC_EXECUTION",
		"php-remote-write":    "FILE_DROPPER",
		"php-write-exec":      "PAYLOAD_LOADER",
		"php-webshell-chain":  "WEBSHELL",
	}
	for id, cat := range want {
		m, ok := RuleMetadata(id)
		if !ok {
			t.Fatalf("rule %q missing", id)
		}
		if m.Category != cat {
			t.Errorf("rule %q category=%q, want %q", id, m.Category, cat)
		}
	}
}

// TestRuleIDsSorted: RuleIDs returns a deterministic sorted list.
func TestRuleIDsSorted(t *testing.T) {
	ids := RuleIDs()
	if len(ids) < 14 {
		t.Fatalf("registry too small: %d", len(ids))
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] < ids[i-1] {
			t.Fatalf("RuleIDs not sorted: %v", ids)
		}
	}
}

// TestSeverityModelPrinciples pins the Phase 4 §10 severity principles.
func TestSeverityModelPrinciples(t *testing.T) {
	// A single dangerous function name must NOT be CRITICAL by itself.
	src := "<?php\n// helper\nif (function_exists('system')) { echo 'x'; }\n"
	fs := AnalyzeBytes("single.php", []byte(src))
	for i := range fs {
		if fs[i].Severity.Rank() >= finding.High.Rank() {
			t.Fatalf("capability note must stay below HIGH: %+v", fs[i])
		}
	}
	// A request-controlled execution chain IS CRITICAL.
	src2 := "<?php\n" + string(rune(36)) + "c = " + string(rune(36)) + "_GET['c'];\nsystem(" + string(rune(36)) + "c);\n"
	fs2 := AnalyzeBytes("chain.php", []byte(src2))
	critical := false
	for i := range fs2 {
		if fs2[i].Severity == finding.Critical {
			critical = true
		}
	}
	if !critical {
		t.Fatalf("request-controlled chain must be CRITICAL: %+v", fs2)
	}
}
