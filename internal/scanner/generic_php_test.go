package scanner

// generic_php_test.go — Phase 4 §12: an ordinary PHP application that is not
// WordPress, Drupal, Joomla or Laravel still receives the full advanced
// threat analysis under the generic "php" platform, without any CMS
// integrity verification being forced onto it.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenericPHPAppGetsAdvancedAnalysis(t *testing.T) {
	target := t.TempDir()
	app := filepath.Join(target, "myapp")
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}

	// No WordPress/Drupal/Joomla/Laravel marker anywhere: discovery must not
	// classify this as a supported CMS.
	files := map[string]string{
		"index.php":  "<?php\nrequire __DIR__ . '/router.php';\n",
		"router.php": "<?php\n" + dollar() + "page = " + dollar() + "_GET['page'];\ninclude " + dollar() + "page . '.php';\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(app, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	res, err := Scan(context.Background(), Options{Target: app, Offline: true})
	if err != nil {
		t.Fatal(err)
	}

	if len(res.Platforms) != 1 || res.Platforms[0] != "php" {
		t.Fatalf("platforms=%v, want [php] (generic profile)", res.Platforms)
	}

	// The request-controlled include must be caught by the correlation rules.
	found := false
	for _, f := range res.Findings {
		if f.Rule == "php-source-to-code" && strings.Contains(f.Path, "router.php") {
			if f.Confidence != "established" {
				t.Fatalf("correlation confidence=%q", f.Confidence)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("generic PHP app must receive advanced correlation analysis: %+v", res.Findings)
	}
}

func TestGenericPHPAppIsNotMislabeledAsCMS(t *testing.T) {
	target := t.TempDir()
	app := filepath.Join(target, "legacyapp")
	if err := os.MkdirAll(filepath.Join(app, "inc"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A custom config.php and a db.php do not make this a supported platform.
	body := "<?php\ndefine('DB_HOST', 'localhost');\n"
	if err := os.WriteFile(filepath.Join(app, "inc", "config.php"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "inc", "db.php"), []byte("<?php\necho 'db';\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Scan(context.Background(), Options{Target: app, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range res.Platforms {
		if p == "wordpress" || p == "drupal" || p == "joomla" || p == "laravel" {
			t.Fatalf("unknown app misclassified as %s", p)
		}
	}
	// No platform integrity findings may exist for an unknown app.
	for _, f := range res.Findings {
		if strings.Contains(strings.ToLower(f.Title), "integrity") {
			t.Fatalf("unknown app must not receive CMS integrity findings: %+v", f)
		}
	}
}
