package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// Fragile characters are built from code points so this test source carries
// no literal dollar signs or backticks.
func dollar() string { return string(rune(36)) }
func tick() string   { return string(rune(96)) }

// Static fixture payloads. They are only ever written as plain files and
// analyzed statically; RONDA never executes scanned PHP.
var (
	fxBacktick      = "<?php " + dollar() + "out = " + tick() + "id" + tick() + ";" + regLine
	fxBacktickWho   = "<?php " + dollar() + "out = " + tick() + "whoami" + tick() + ";" + regLine
	fxSystemGet     = "<?php system(" + dollar() + "_GET['cmd']);" + regLine
	fxShellExecReq  = "<?php shell_exec(" + dollar() + "_REQUEST['c']);" + regLine
	fxEvalPost      = "<?php eval(" + dollar() + "_POST['c']);" + regLine
	fxEvalB64Post   = "<?php eval(base64_decode(" + dollar() + "_POST['c']));" + regLine
	fxShortEchoTick = "<?=" + " " + tick() + "id" + tick() + " ?>" + regLine
	fxShortEchoSys  = "<?=" + " system(" + dollar() + "_GET['cmd']) ?>" + regLine
	fxShortEchoMix  = "<html>" + regLine + "<body><?=" + " shell_exec(" + dollar() + "_POST['cmd']) ?></body>" + regLine + "</html>" + regLine
)

const regLine = "\n"

// buildWordPressInstall creates the minimal marker files discovery needs to
// recognise a WordPress installation root.
func buildWordPressInstall(t *testing.T, root string) {
	t.Helper()
	mustWrite(t, filepath.Join(root, "wp-load.php"), "<?php"+regLine)
	mustWrite(t, filepath.Join(root, "wp-includes", "version.php"), "<?php"+regLine)
}

func countTitle(res Result, title string) int {
	n := 0
	for i := 0; i < len(res.Findings); i++ {
		if res.Findings[i].Title == title {
			n++
		}
	}
	return n
}

func hasFindingAt(t *testing.T, res Result, title, path string) bool {
	t.Helper()
	for i := 0; i < len(res.Findings); i++ {
		f := res.Findings[i]
		if f.Title == title && f.Path == path {
			return true
		}
	}
	return false
}

func assertNoDuplicateFindings(t *testing.T, res Result) {
	t.Helper()
	seen := make(map[string]bool, len(res.Findings))
	for i := 0; i < len(res.Findings); i++ {
		f := res.Findings[i]
		key := f.Platform + "|" + f.Path + "|" + f.Title
		if seen[key] {
			t.Errorf("duplicate finding: %s at %s", f.Title, f.Path)
		}
		seen[key] = true
	}
}

// --- Core PHP: modified core areas must surface PHP security findings -------

func TestWordPressModeRetainsCorePHPFindings(t *testing.T) {
	target := t.TempDir()
	site := filepath.Join(target, "site")
	buildWordPressInstall(t, site)

	wpAdminHelper := filepath.Join(site, "wp-admin", "includes", "upgrade-helper.php")
	hiddenShell := filepath.Join(site, "wp-includes", "hidden-shell.php")
	obfuscated := filepath.Join(site, "wp-includes", "obf.php")
	wpAdminSetup := filepath.Join(site, "wp-admin", "setup.php")
	mustWrite(t, wpAdminHelper, fxShellExecReq)
	mustWrite(t, hiddenShell, fxBacktick)
	mustWrite(t, obfuscated, fxEvalB64Post)
	mustWrite(t, wpAdminSetup, fxSystemGet)

	res, err := Scan(context.Background(), Options{Target: target, Platforms: []string{"wordpress"}, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	assertNoDuplicateFindings(t, res)

	for _, want := range []struct{ title, path string }{
		{"PHP backtick shell execution", hiddenShell},
		{"Suspicious PHP code", wpAdminSetup},
		{"Suspicious PHP code", obfuscated},
		{"Suspicious PHP code", wpAdminHelper},
	} {
		if !hasFindingAt(t, res, want.title, want.path) {
			t.Errorf("missing %s at %s; findings: %+v", want.title, want.path, res.Findings)
		}
	}

	// WordPress integrity results must coexist with the PHP findings.
	if countTitle(res, "WordPress core integrity unverified") != 1 {
		t.Errorf("expected the WordPress integrity finding to coexist, got %+v", res.Findings)
	}
	// wp-admin and wp-includes findings must not be missing. Phase 4 adds
	// one established request-to-sink correlation finding per suspicious
	// fixture file (upgrade-helper.php, setup.php, obf.php): 4 signal
	// findings + 3 correlation findings = 7.
	php := 0
	corr := 0
	for i := 0; i < len(res.Findings); i++ {
		if res.Findings[i].Platform == "php" {
			php++
			if res.Findings[i].Confidence == "established" {
				corr++
			}
		}
	}
	if php != 7 {
		t.Errorf("expected 7 php findings, got %d: %+v", php, res.Findings)
	}
	if corr != 3 {
		t.Errorf("expected 3 established correlation findings, got %d: %+v", corr, res.Findings)
	}
}

// --- wp-content: plugins, themes, uploads and custom subdirectories ---------

func TestWordPressModeRetainsWPContentFindings(t *testing.T) {
	target := t.TempDir()
	site := filepath.Join(target, "site")
	buildWordPressInstall(t, site)

	plugin := filepath.Join(site, "wp-content", "plugins", "evil-plugin", "shell.php")
	theme := filepath.Join(site, "wp-content", "themes", "evil-theme", "functions.php")
	uploads := filepath.Join(site, "wp-content", "uploads", "2024", "06", "backdoor.php")
	custom := filepath.Join(site, "wp-content", "custom-tools", "maintenance.php")
	mustWrite(t, plugin, fxEvalPost)
	mustWrite(t, theme, fxBacktickWho)
	mustWrite(t, uploads, fxSystemGet)
	mustWrite(t, custom, fxBacktick)

	res, err := Scan(context.Background(), Options{Target: target, Platforms: []string{"wordpress"}, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	assertNoDuplicateFindings(t, res)

	for _, want := range []struct{ title, path string }{
		{"Suspicious PHP code", plugin},
		{"PHP backtick shell execution", theme},
		{"Suspicious PHP code", uploads},
		{"PHP backtick shell execution", custom},
	} {
		if !hasFindingAt(t, res, want.title, want.path) {
			t.Errorf("missing %s at %s; findings: %+v", want.title, want.path, res.Findings)
		}
	}
}

// --- Short echo tag integration through the full scanner pipeline -----------

func TestWordPressModeShortEchoFindings(t *testing.T) {
	target := t.TempDir()
	site := filepath.Join(target, "site")
	buildWordPressInstall(t, site)

	index := filepath.Join(site, "index.php")
	cmd := filepath.Join(site, "cmd.php")
	tpl := filepath.Join(site, "template.php")
	mustWrite(t, index, fxShortEchoTick)
	mustWrite(t, cmd, fxShortEchoSys)
	mustWrite(t, tpl, fxShortEchoMix)

	res, err := Scan(context.Background(), Options{Target: target, Platforms: []string{"wordpress"}, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	assertNoDuplicateFindings(t, res)

	if !hasFindingAt(t, res, "PHP backtick shell execution", index) {
		t.Errorf("short echo backtick missing: %+v", res.Findings)
	}
	if !hasFindingAt(t, res, "Suspicious PHP code", cmd) {
		t.Errorf("short echo system() missing: %+v", res.Findings)
	}
	if !hasFindingAt(t, res, "Suspicious PHP code", tpl) {
		t.Errorf("mixed HTML/PHP short echo missing: %+v", res.Findings)
	}
	for i := 0; i < len(res.Findings); i++ {
		f := res.Findings[i]
		if f.Path == index && f.Severity != finding.High {
			t.Errorf("backtick severity=%s want HIGH", f.Severity)
		}
		if (f.Path == cmd || f.Path == tpl) && f.Severity != finding.Critical {
			t.Errorf("superglobal severity=%s want CRITICAL", f.Severity)
		}
	}
}

// --- Scope isolation: only the selected installation is exposed -------------

func TestWordPressModeExcludesOutsidePHP(t *testing.T) {
	target := t.TempDir()
	site := filepath.Join(target, "site")
	buildWordPressInstall(t, site)

	plugin := filepath.Join(site, "wp-content", "plugins", "p", "shell.php")
	loose := filepath.Join(target, "loose.php")
	backup := filepath.Join(target, "site-backup", "evil.php")
	mustWrite(t, plugin, fxBacktick)
	mustWrite(t, loose, fxBacktick)
	mustWrite(t, backup, fxBacktick)

	wpRes, err := Scan(context.Background(), Options{Target: target, Platforms: []string{"wordpress"}, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	assertNoDuplicateFindings(t, wpRes)
	if !hasFindingAt(t, wpRes, "PHP backtick shell execution", plugin) {
		t.Errorf("in-install finding dropped: %+v", wpRes.Findings)
	}
	if hasFindingAt(t, wpRes, "PHP backtick shell execution", loose) {
		t.Errorf("unrelated root PHP must stay excluded: %+v", wpRes.Findings)
	}
	if hasFindingAt(t, wpRes, "PHP backtick shell execution", backup) {
		t.Errorf("sibling directory must stay excluded: %+v", wpRes.Findings)
	}

	// Default full scan keeps everything: behavior unchanged.
	defRes, err := Scan(context.Background(), Options{Target: target, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{plugin, loose, backup} {
		if !hasFindingAt(t, defRes, "PHP backtick shell execution", want) {
			t.Errorf("default scan must keep %s: %+v", want, defRes.Findings)
		}
	}
}

// --- Multiple installations --------------------------------------------------

func TestMultipleInstallationsRetainedAndScoped(t *testing.T) {
	target := t.TempDir()
	site1 := filepath.Join(target, "site1")
	site2 := filepath.Join(target, "site2")
	buildWordPressInstall(t, site1)
	buildWordPressInstall(t, site2)

	p1 := filepath.Join(site1, "wp-content", "plugins", "p1", "shell.php")
	p2 := filepath.Join(site2, "wp-content", "plugins", "p2", "cmd.php")
	neutral := filepath.Join(target, "neutral.php")
	mustWrite(t, p1, fxBacktick)
	mustWrite(t, p2, fxSystemGet)
	mustWrite(t, neutral, fxBacktick)

	res, err := Scan(context.Background(), Options{Target: target, Platforms: []string{"wordpress"}, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	assertNoDuplicateFindings(t, res)

	if len(res.WordPress) != 2 {
		t.Fatalf("expected 2 discovered installations, got %d", len(res.WordPress))
	}
	if countTitle(res, "WordPress core integrity unverified") != 2 {
		t.Errorf("each installation needs its own integrity finding: %+v", res.Findings)
	}
	if !hasFindingAt(t, res, "PHP backtick shell execution", p1) {
		t.Errorf("site1 finding missing: %+v", res.Findings)
	}
	if !hasFindingAt(t, res, "Suspicious PHP code", p2) {
		t.Errorf("site2 finding missing: %+v", res.Findings)
	}
	if hasFindingAt(t, res, "PHP backtick shell execution", neutral) {
		t.Errorf("PHP outside both installations must stay excluded: %+v", res.Findings)
	}
}

// --- Nested and overlapping installation roots -------------------------------

func TestNestedInstallNoDuplicateFindings(t *testing.T) {
	target := t.TempDir()
	site := filepath.Join(target, "site")
	buildWordPressInstall(t, site)

	nested := filepath.Join(site, "wp-content", "plugins", "nested-wp")
	buildWordPressInstall(t, nested)
	evil := filepath.Join(nested, "evil.php")
	mustWrite(t, evil, fxBacktick)

	res, err := Scan(context.Background(), Options{Target: target, Platforms: []string{"wordpress"}, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	assertNoDuplicateFindings(t, res)

	// Discovery stops at the outermost installation; the nested markers are
	// inside it, so exactly one installation is verified.
	if len(res.WordPress) != 1 {
		t.Fatalf("expected 1 discovered installation, got %d", len(res.WordPress))
	}
	if !hasFindingAt(t, res, "PHP backtick shell execution", evil) {
		t.Errorf("nested content finding missing: %+v", res.Findings)
	}
	if n := countTitle(res, "PHP backtick shell execution"); n != 1 {
		t.Errorf("expected exactly 1 backtick finding, got %d: %+v", n, res.Findings)
	}
}

func TestTargetIsInstallRoot(t *testing.T) {
	site := t.TempDir()
	buildWordPressInstall(t, site)
	evil := filepath.Join(site, "wp-content", "plugins", "p", "shell.php")
	mustWrite(t, evil, fxBacktick)

	res, err := Scan(context.Background(), Options{Target: site, Platforms: []string{"wordpress"}, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFindingAt(t, res, "PHP backtick shell execution", evil) {
		t.Fatalf("target == installation root must retain findings: %+v", res.Findings)
	}
}

// --- Relative versus absolute paths ------------------------------------------

func TestRelativeTargetPathIntegration(t *testing.T) {
	base := t.TempDir()
	site := filepath.Join(base, "site")
	buildWordPressInstall(t, site)
	evil := filepath.Join(site, "wp-content", "plugins", "p", "shell.php")
	mustWrite(t, evil, fxBacktick)

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatal(err)
		}
	}()
	if err := os.Chdir(base); err != nil {
		t.Fatal(err)
	}

	res, err := Scan(context.Background(), Options{Target: "site", Platforms: []string{"wordpress"}, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFindingAt(t, res, "PHP backtick shell execution", evil) {
		t.Fatalf("relative target must retain install findings: %+v", res.Findings)
	}
	for i := 0; i < len(res.Findings); i++ {
		if res.Findings[i].Path != "" && !filepath.IsAbs(res.Findings[i].Path) {
			t.Errorf("finding path not absolute: %s", res.Findings[i].Path)
		}
	}
}

// --- Safety: symlinks and path traversal -------------------------------------

func TestScanDoesNotFollowSymlinkOutsideInstall(t *testing.T) {
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "real-evil.php")
	mustWrite(t, outsideFile, fxBacktick)

	target := t.TempDir()
	site := filepath.Join(target, "site")
	buildWordPressInstall(t, site)
	link := filepath.Join(site, "wp-content", "uploads", "evil-link.php")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	res, err := Scan(context.Background(), Options{Target: target, Platforms: []string{"wordpress"}, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	assertNoDuplicateFindings(t, res)
	if hasFindingAt(t, res, "PHP backtick shell execution", link) {
		t.Errorf("symlink outside the scan scope must not be followed: %+v", res.Findings)
	}
	for i := 0; i < len(res.Findings); i++ {
		if res.Findings[i].Path == outsideFile {
			t.Errorf("content outside the scan scope was read: %s", res.Findings[i].Path)
		}
	}
}

func TestTraversalPathNeverRetained(t *testing.T) {
	site := "/srv/site"
	items := []finding.Finding{
		phpFinding(site + "/../../../etc/evil.php"),
		phpFinding(site + "/sub/../../outside.php"),
		phpFinding(site + "/./wp-content/ok.php"),
	}
	got := filterFindings(items, []string{"wordpress"}, []string{site})
	if len(got) != 1 {
		t.Fatalf("only the contained path may be retained, got %+v", got)
	}
	if got[0].Path != site+"/./wp-content/ok.php" {
		t.Fatalf("unexpected retained path: %s", got[0].Path)
	}
}
