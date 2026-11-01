package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, src string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f.php")
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIsPHP(t *testing.T) {
	cases := map[string]bool{
		"a.php": true, "b.PHP": true, "c.phtml": true,
		"d.php5": true, "e.php7": true, "f.txt": false, "g": false,
	}
	for p, want := range cases {
		if got := IsPHP(p); got != want {
			t.Errorf("IsPHP(%q)=%v want %v", p, got, want)
		}
	}
}

func TestCleanFileNoFindings(t *testing.T) {
	p := writeTemp(t, "<?php echo 'hello';")
	f, err := AnalyzeFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

func TestNonPHPNoFindings(t *testing.T) {
	p := writeTemp(t, "just plain text here")
	f, err := AnalyzeFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 0 {
		t.Fatalf("expected no findings for non-PHP, got %d", len(f))
	}
}

func TestSuspiciousCombination(t *testing.T) {
	p := writeTemp(t, "<?php eval(base64_decode('x'));")
	f, err := AnalyzeFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) == 0 {
		t.Fatal("expected a finding for eval(base64_decode)")
	}
	if f[0].Status != "SUSPICIOUS" {
		t.Fatalf("status=%s", f[0].Status)
	}
}
