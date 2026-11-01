package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// binary_analysis_test.go proves the Phase 3.2 analyzer classification flows
// through the real Scan pipeline: a Symfony-style charset table and a real
// webshell inside one directory produce two independent, correctly-classified
// findings, and the classification metadata (rule ids) reaches the result.
// All fixtures are static bytes; nothing is executed.

func charsetTableBytes(rows int) []byte {
	var b strings.Builder
	b.WriteString("<?php\n// Generated character-set mapping table.\nstatic $data = array(\n")
	nul := string([]byte{0})
	for i := 0; i < rows; i++ {
		b.WriteString("    '" + strings.Repeat("A", 4) + nul + strings.Repeat("B", 5) + "' => '\\xC3\\xA9',\n")
	}
	b.WriteString(");\nreturn $data;\n")
	return []byte(b.String())
}

func TestScanClassifiesEmbeddedBinaryAndThreatIndependently(t *testing.T) {
	root := t.TempDir()
	vendorDir := filepath.Join(root, "libraries", "vendor", "acme", "charset")
	if err := os.MkdirAll(vendorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	table := filepath.Join(vendorDir, "from.cp037.php")
	if err := os.WriteFile(table, charsetTableBytes(40), 0o644); err != nil {
		t.Fatal(err)
	}
	shell := filepath.Join(root, "shell.php")
	mustWrite(t, shell, fxEvalB64Post)

	res, err := Scan(context.Background(), Options{Target: root, Workers: 1})
	if err != nil {
		t.Fatal(err)
	}

	var tableFinding, shellFinding *finding.Finding
	for i := range res.Findings {
		f := &res.Findings[i]
		switch f.Path {
		case table:
			tableFinding = f
		case shell:
			shellFinding = f
		}
	}
	if tableFinding == nil {
		t.Fatalf("charset table produced no finding: %+v", res.Findings)
	}
	if tableFinding.Title != "PHP file contains embedded binary data" || tableFinding.Severity != "LOW" {
		t.Fatalf("table classification wrong: %+v", tableFinding)
	}
	if tableFinding.Rule != "php-embedded-binary" {
		t.Fatalf("table rule=%q", tableFinding.Rule)
	}
	if tableFinding.Line <= 0 {
		t.Fatalf("table line=%d", tableFinding.Line)
	}

	if shellFinding == nil {
		t.Fatalf("webshell produced no finding: %+v", res.Findings)
	}
	if shellFinding.Severity != "CRITICAL" {
		t.Fatalf("webshell severity=%s, want CRITICAL", shellFinding.Severity)
	}
	if shellFinding.Rule != "php-signals" {
		t.Fatalf("webshell rule=%q", shellFinding.Rule)
	}
}
