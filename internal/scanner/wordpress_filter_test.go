package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/wordpress"
)

func phpFinding(path string) finding.Finding {
	return finding.Finding{
		Status:   finding.Suspicious,
		Severity: finding.High,
		Title:    "PHP backtick shell execution",
		Platform: "php",
		Path:     path,
		Evidence: "evidence",
	}
}

func wpIntegrityFinding(root string) finding.Finding {
	return finding.Finding{
		Status:   finding.Unverified,
		Severity: finding.Info,
		Title:    "WordPress core integrity unverified",
		Platform: "wordpress",
		Path:     root,
	}
}

func TestFilterFindingsWordPressModeRetainsInstallPHP(t *testing.T) {
	site := "/srv/site"
	items := []finding.Finding{
		wpIntegrityFinding(site),
		phpFinding(site + "/wp-content/plugins/p/shell.php"),
		phpFinding("/srv/loose.php"),
	}
	got := filterFindings(items, []string{"wordpress"}, []string{site})
	if len(got) != 2 {
		t.Fatalf("expected wp finding + in-install php finding, got %d: %+v", len(got), got)
	}
	if got[0].Platform != "wordpress" || got[1].Platform != "php" {
		t.Fatalf("wrong findings retained: %+v", got)
	}
}

func TestFilterFindingsWordPressModeNoInstallsDropsPHP(t *testing.T) {
	items := []finding.Finding{
		phpFinding("/srv/loose.php"),
		phpFinding("/srv/other.php"),
	}
	got := filterFindings(items, []string{"wordpress"}, nil)
	if len(got) != 0 {
		t.Fatalf("--wordpress with no discovered installs must keep no PHP findings, got %+v", got)
	}
}

func TestFilterFindingsPHPRequestKeepsEverythingPHP(t *testing.T) {
	site := "/srv/site"
	items := []finding.Finding{
		wpIntegrityFinding(site),
		phpFinding(site + "/wp-content/plugins/p/shell.php"),
		phpFinding("/srv/loose.php"),
	}
	got := filterFindings(items, []string{"php"}, []string{site})
	if len(got) != 2 {
		t.Fatalf("php request must keep all PHP findings and drop wordpress findings, got %d: %+v", len(got), got)
	}
	for i := 0; i < len(got); i++ {
		if got[i].Platform != "php" {
			t.Fatalf("finding %d platform=%s", i, got[i].Platform)
		}
	}
}

func TestFilterFindingsEmptyRequestUnchanged(t *testing.T) {
	site := "/srv/site"
	items := []finding.Finding{
		wpIntegrityFinding(site),
		phpFinding(site + "/x.php"),
		phpFinding("/srv/loose.php"),
	}
	got := filterFindings(items, nil, []string{site})
	if len(got) != len(items) {
		t.Fatalf("default scan must keep everything, got %d want %d", len(got), len(items))
	}
}

func TestFilterFindingsNonPHPPlatformNotRescued(t *testing.T) {
	site := "/srv/site"
	drupal := finding.Finding{
		Status:   finding.Suspicious,
		Severity: finding.High,
		Title:    "Suspicious PHP code",
		Platform: "drupal",
		Path:     site + "/modules/x.php",
	}
	got := filterFindings([]finding.Finding{drupal}, []string{"wordpress"}, []string{site})
	if len(got) != 0 {
		t.Fatalf("only platform:php findings are retained via the WordPress association, got %+v", got)
	}
}

func TestFilterFindingsCaseInsensitiveRequest(t *testing.T) {
	site := "/srv/site"
	items := []finding.Finding{
		phpFinding(site + "/wp-load-x.php"),
	}
	got := filterFindings(items, []string{"WordPress"}, []string{site})
	if len(got) != 1 {
		t.Fatalf("platform request must be case-insensitive, got %+v", got)
	}
}

func TestFilterFindingsNoDuplicates(t *testing.T) {
	site := "/srv/site"
	items := []finding.Finding{
		phpFinding(site + "/wp-content/x.php"),
		phpFinding(site + "/wp-content/x.php"),
	}
	got := filterFindings(items, []string{"wordpress"}, []string{site})
	if len(got) != 2 {
		t.Fatalf("filter must not add or deduplicate on its own, got %d", len(got))
	}
}

func TestContainsPath(t *testing.T) {
	cases := []struct {
		root string
		path string
		want bool
	}{
		{"/srv/site", "/srv/site/wp-load.php", true},
		{"/srv/site", "/srv/site", true},
		{"/srv/site", "/srv/site/wp-admin/includes/file.php", true},
		// The sibling trap: a shared prefix is not a parent.
		{"/srv/site", "/srv/site-backup/x.php", false},
		{"/srv/site", "/srv/site2/x.php", false},
		{"/srv/site", "/srv/siteevil/x.php", false},
		{"/srv/site", "/srv/x.php", false},
		{"/srv/site", "/srv", false},
		{"/srv/site", "/etc/passwd", false},
		// Traversal collapses during normalization.
		{"/srv/site", "/srv/site/../evil.php", false},
		{"/srv/site", "/srv/site/sub/../../out.php", false},
		{"/srv/site", "/srv/site/..", false},
		{"/srv/site", "/srv/site/./wp-load.php", true},
		{"/srv/site", "/srv/site/sub/../wp-load.php", true},
		// A child whose name only starts with dots is still a child.
		{"/srv/site", "/srv/site/..hidden.php", true},
		// Empty inputs never match.
		{"", "/srv/x.php", false},
		{"/srv/site", "", false},
		{"   ", "/srv/x.php", false},
	}
	for _, c := range cases {
		if got := containsPath(c.root, c.path); got != c.want {
			t.Errorf("containsPath(%q, %q)=%v want %v", c.root, c.path, got, c.want)
		}
	}
}

func TestContainsPathRelativeConsistent(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "inst", "site", "wp-content"), 0o755); err != nil {
		t.Fatal(err)
	}
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

	// Relative root and relative path resolve against the same working
	// directory, so the decision matches the absolute equivalent.
	if !containsPath("inst/site", "inst/site/wp-load.php") {
		t.Fatal("relative child rejected")
	}
	if containsPath("inst/site", "inst/other.php") {
		t.Fatal("relative sibling accepted")
	}
	// Mixed relative root with absolute path.
	if !containsPath("inst/site", filepath.Join(base, "inst", "site", "wp-load.php")) {
		t.Fatal("mixed relative root rejected")
	}
}

func TestHasContainingRootMultipleInstalls(t *testing.T) {
	roots := []string{"/srv/site1", "/srv/site2"}
	if !hasContainingRoot(roots, "/srv/site1/x.php") {
		t.Fatal("site1 child rejected")
	}
	if !hasContainingRoot(roots, "/srv/site2/x.php") {
		t.Fatal("site2 child rejected")
	}
	if hasContainingRoot(roots, "/srv/site1-backup/x.php") {
		t.Fatal("sibling of site1 accepted")
	}
	if hasContainingRoot(nil, "/srv/site1/x.php") {
		t.Fatal("empty root list accepted a path")
	}
}

func TestWordpressRootsFromResults(t *testing.T) {
	roots := wordpressRoots([]wordpress.Result{
		{Root: "/srv/site1"},
		{Root: "  "},
		{Root: "/srv/site2"},
	})
	if len(roots) != 2 || roots[0] != "/srv/site1" || roots[1] != "/srv/site2" {
		t.Fatalf("unexpected roots: %v", roots)
	}
	if n := len(wordpressRoots(nil)); n != 0 {
		t.Fatalf("expected no roots, got %d", n)
	}
}
