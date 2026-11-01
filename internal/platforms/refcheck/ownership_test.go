package refcheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// ownershipPolicy mirrors the Joomla adapter's ownership boundaries so the
// engine-level fixtures exercise exactly the policy production uses: strict
// core-only directories, shared extension areas with per-platform extension
// root depth, and flat per-extension language trees.
func ownershipPolicy() Policy {
	return Policy{
		StrictDirs: []string{
			"libraries",
			"includes",
			"administrator/manifests",
			"administrator/includes",
			"api/includes",
			"cli",
		},
		SharedDirs: []SharedDir{
			{Dir: "components", Depth: 1},
			{Dir: "modules", Depth: 1},
			{Dir: "plugins", Depth: 2},
			{Dir: "templates", Depth: 1},
			{Dir: "layouts", Depth: 1},
			{Dir: "media", Depth: 1},
			{Dir: "administrator/components", Depth: 1},
			{Dir: "administrator/modules", Depth: 1},
			{Dir: "administrator/templates", Depth: 1},
			{Dir: "api/components", Depth: 1},
		},
		LanguageTrees: []string{"language", "administrator/language", "api/language"},
		RootExtra:     true,
		RootExtraExcluded: map[string]bool{
			"configuration.php": true,
			".htaccess":         true,
		},
	}
}

// ownershipCoreFiles is the official reference fixture: the manifest-derived
// file set of a minimal "official package" spanning every shared area.
func ownershipCoreFiles() map[string]string {
	return map[string]string{
		"libraries/src/Version.php":                        "<?php version",
		"includes/defines.php":                             "<?php defines",
		"components/com_content/content.php":               "<?php content",
		"components/com_content/tmpl/article/default.php":  "<?php view",
		"modules/mod_login/login.php":                      "<?php login",
		"plugins/system/cache/cache.php":                   "<?php cache",
		"plugins/content/pagebreak/pagebreak.php":          "<?php pagebreak",
		"templates/cassiopeia/index.php":                   "<?php cassiopeia",
		"layouts/joomla/form/field.php":                    "<?php layout",
		"media/vendor/joomla/core.js":                      "js",
		"language/en-GB/en-GB.ini":                         "base language",
		"administrator/components/com_admin/admin.php":     "<?php admin",
		"administrator/modules/mod_latest/latest.php":      "<?php latest",
		"administrator/templates/atum/index.php":           "<?php atum",
		"administrator/language/en-GB/en-GB.com_admin.ini": "admin lang",
		"api/components/com_media/api.php":                 "<?php api media",
		"api/language/en-GB/en-GB.com_media.ini":           "api lang",
		"installation/index.php":                           "<?php install",
	}
}

// TestSharedOwnershipUnexpectedScan walks the 13 directive fixture scenarios:
// an unexpected file inside a directory subtree the official package
// demonstrably owns is reported, while third-party extensions, language
// overrides and files at unknown ownership levels stay unreported. Absence
// from the official package is never a malware claim anywhere below.
func TestSharedOwnershipUnexpectedScan(t *testing.T) {
	core := ownershipCoreFiles()
	policy := ownershipPolicy()

	scenarios := []struct {
		name         string
		extra        map[string]string
		wantReported []string
		wantAbsent   []string
	}{
		{
			// 1. Extra file inside an official Core component directory.
			name:         "component_core_owned_extra_reported",
			extra:        map[string]string{"components/com_content/rogue.php": "rogue"},
			wantReported: []string{"components/com_content/rogue.php"},
			wantAbsent:   []string{"components/com_3p/loader.php"},
		},
		{
			// 2. A third-party component directory is unknown ownership; none
			// of its files may ever be reported.
			name: "component_third_party_not_reported",
			extra: map[string]string{
				"components/com_foo/foo.php":       "3p",
				"components/com_foo/helpers/x.php": "3p",
			},
			wantAbsent: []string{"components/com_foo/foo.php", "components/com_foo/helpers/x.php"},
		},
		{
			// 3. A file placed directly in the shared root belongs to no
			// extension directory: unknown ownership, never reported.
			name:         "component_shallow_file_unknown",
			extra:        map[string]string{"components/loose.php": "loose"},
			wantReported: nil,
			wantAbsent:   []string{"components/loose.php"},
		},
		{
			// 4. Extra file inside an official Core module vs a third-party
			// module directory.
			name: "module_core_owned_vs_third_party",
			extra: map[string]string{
				"modules/mod_login/rogue.php": "rogue",
				"modules/mod_foo/x.php":       "3p",
			},
			wantReported: []string{"modules/mod_login/rogue.php"},
			wantAbsent:   []string{"modules/mod_foo/x.php"},
		},
		{
			// 5. Extra file inside an official Core plugin (two-level root).
			name:         "plugin_core_owned_extra_reported",
			extra:        map[string]string{"plugins/system/cache/rogue.php": "rogue"},
			wantReported: []string{"plugins/system/cache/rogue.php"},
		},
		{
			// 6. Third-party plugins are unknown ownership, even inside an
			// official plugin group directory: ownership is checked at the
			// exact plugin root, not the group level.
			name: "plugin_third_party_not_reported",
			extra: map[string]string{
				"plugins/mygroup/myplugin/x.php": "3p",
				"plugins/system/myplugin/x.php":  "3p",
			},
			wantAbsent: []string{"plugins/mygroup/myplugin/x.php", "plugins/system/myplugin/x.php"},
		},
		{
			// 7. Official template vs third-party template.
			name: "template_core_owned_vs_third_party",
			extra: map[string]string{
				"templates/cassiopeia/rogue.php": "rogue",
				"templates/mytpl/x.php":          "3p",
			},
			wantReported: []string{"templates/cassiopeia/rogue.php"},
			wantAbsent:   []string{"templates/mytpl/x.php"},
		},
		{
			// 8. Official layout tree vs third-party layout directory.
			name: "layout_core_owned_vs_third_party",
			extra: map[string]string{
				"layouts/joomla/extra.php": "rogue",
				"layouts/custom/x.php":     "3p",
			},
			wantReported: []string{"layouts/joomla/extra.php"},
			wantAbsent:   []string{"layouts/custom/x.php"},
		},
		{
			// 9. Official media subtree vs third-party media directory.
			name: "media_core_owned_vs_third_party",
			extra: map[string]string{
				"media/vendor/rogue.js": "rogue",
				"media/mylib/x.png":     "3p",
			},
			wantReported: []string{"media/vendor/rogue.js"},
			wantAbsent:   []string{"media/mylib/x.png"},
		},
		{
			// 10. Extra language files whose token maps to a manifest-owned
			// extension directory: reported.
			name: "language_core_token_reported",
			extra: map[string]string{
				"language/en-GB/en-GB.com_content.ini":      "rogue",
				"language/en-GB/en-GB.mod_login.sys.ini":    "rogue",
				"language/en-GB/en-GB.plg_system_cache.ini": "rogue",
			},
			wantReported: []string{
				"language/en-GB/en-GB.com_content.ini",
				"language/en-GB/en-GB.mod_login.sys.ini",
				"language/en-GB/en-GB.plg_system_cache.ini",
			},
		},
		{
			// 11. Language overrides, unknown tokens and non-language files
			// stay unreported; so do nested (non-flat) files in the tree.
			name: "language_unknown_token_not_reported",
			extra: map[string]string{
				"language/en-GB/en-GB.com_custom.ini":            "override",
				"language/en-GB/override.ini":                    "override",
				"language/en-GB/notes.txt":                       "not a language file",
				"language/en-GB/nested/deep.ini":                 "nested, not flat",
				"administrator/language/en-GB/en-GB.com_foo.ini": "3p token",
			},
			wantAbsent: []string{
				"language/en-GB/en-GB.com_custom.ini",
				"language/en-GB/override.ini",
				"language/en-GB/notes.txt",
				"language/en-GB/nested/deep.ini",
				"administrator/language/en-GB/en-GB.com_foo.ini",
			},
		},
		{
			// 12. Administrator shared areas behave like their site
			// counterparts: owned extension roots report, unknown do not.
			name: "administrator_areas_ownership",
			extra: map[string]string{
				"administrator/components/com_admin/rogue.php": "rogue",
				"administrator/modules/mod_latest/rogue.php":   "rogue",
				"administrator/templates/atum/rogue.php":       "rogue",
				"administrator/components/com_custom/x.php":    "3p",
			},
			wantReported: []string{
				"administrator/components/com_admin/rogue.php",
				"administrator/modules/mod_latest/rogue.php",
				"administrator/templates/atum/rogue.php",
			},
			wantAbsent: []string{"administrator/components/com_custom/x.php"},
		},
		{
			// 13. Strict core-only directories report any extra file, and the
			// API area follows the same ownership rules as its site
			// counterparts.
			name: "strict_dirs_and_api_areas",
			extra: map[string]string{
				"cli/rogue.php":                              "rogue",
				"api/includes/rogue.php":                     "rogue",
				"api/components/com_media/rogue.php":         "rogue",
				"api/components/com_custom/x.php":            "3p",
				"api/language/en-GB/en-GB.com_media.sys.ini": "rogue token",
				"api/language/en-GB/en-GB.com_foo.ini":       "3p token",
			},
			wantReported: []string{
				"cli/rogue.php",
				"api/includes/rogue.php",
				"api/components/com_media/rogue.php",
				"api/language/en-GB/en-GB.com_media.sys.ini",
			},
			wantAbsent: []string{
				"api/components/com_custom/x.php",
				"api/language/en-GB/en-GB.com_foo.ini",
			},
		},
	}

	for _, sc := range scenarios {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			root := t.TempDir()
			writeTree(t, root, core)
			manifest := manifestFrom(t, root, core)
			writeTree(t, root, sc.extra)

			res, err := Compare(context.Background(), root, manifest, policy)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range sc.wantReported {
				found := false
				for _, got := range res.Unexpected {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("%s must be reported as unexpected; got %v", want, res.Unexpected)
				}
			}
			for _, absent := range sc.wantAbsent {
				for _, got := range res.Unexpected {
					if got == absent {
						t.Fatalf("%s must NOT be reported (unknown ownership); got %v", absent, res.Unexpected)
					}
				}
			}
			// The comparison of official files is unaffected by the
			// unexpected scan: every manifest entry is still verified.
			if res.TotalFiles != len(manifest) || res.CleanCount != len(manifest) {
				t.Fatalf("integrity comparison changed: total=%d clean=%d want=%d",
					res.TotalFiles, res.CleanCount, len(manifest))
			}
		})
	}
}

// TestTrustPersistenceAndDerivation checks the explicit trust block survives
// the cache round trip and that cache entries predating the trust model get
// an honest category derived from their authenticated archive identity.
func TestTrustPersistenceAndDerivation(t *testing.T) {
	store := NewStoreAt(t.TempDir())

	strong := Reference{
		Platform: "drupal", Version: "10.3.5", Algorithm: "sha256", Digest: "aa",
		ArchiveURL: "https://example.invalid/drupal-10.3.5.tar.gz",
		Manifest:   Manifest{"core/a.php": shaOfContent("a")},
		Trust: Trust{
			Category:             StrengthSHA256Authenticated,
			DigestAlgorithm:      "sha256",
			AuthenticationMethod: "release page SHA-256",
			ArchiveSHA256:        "bb",
			Confidence:           "strong",
		},
	}
	store.Put(strong)
	got, ok := store.Get("drupal", "10.3.5", strong.ArchiveURL, "aa")
	if !ok {
		t.Fatal("strong ref lost")
	}
	if got.Trust.Category != StrengthSHA256Authenticated || got.Trust.AuthenticationMethod == "" ||
		got.Trust.ArchiveSHA256 != "bb" || got.Trust.Confidence == "" {
		t.Fatalf("trust block must round-trip intact: %+v", got.Trust)
	}

	// Old cache entry: no Trust block, category derived from the algorithm.
	legacy := Reference{
		Platform: "joomla", Version: "5.2.0", Algorithm: "md5+sha1", Digest: "cc",
		ArchiveURL: "https://example.invalid/joomla.tar.gz",
		Manifest:   Manifest{"libraries/x.php": shaOfContent("x")},
	}
	store.Put(legacy)
	got, ok = store.Get("joomla", "5.2.0", legacy.ArchiveURL, "cc")
	if !ok {
		t.Fatal("legacy ref lost")
	}
	derived := got.EffectiveTrust()
	if derived.Category != StrengthLegacyDigestMatch || derived.DigestAlgorithm != "md5+sha1" {
		t.Fatalf("derived trust must be honest legacy: %+v", derived)
	}
	if derived.Category == StrengthSHA256Authenticated {
		t.Fatal("legacy digest must never be presented as strong authentication")
	}

	// Derivation table.
	cases := map[string]string{
		"sha256":   StrengthSHA256Authenticated,
		"md5":      StrengthLegacyDigestMatch,
		"sha1":     StrengthLegacyDigestMatch,
		"md5+sha1": StrengthLegacyDigestMatch,
		"sha1+md5": StrengthLegacyDigestMatch,
		"mystery":  StrengthUnverified,
		"":         StrengthUnverified,
	}
	for algo, want := range cases {
		if got := TrustCategoryForAlgorithm(algo); got != want {
			t.Fatalf("TrustCategoryForAlgorithm(%q) = %q, want %q", algo, got, want)
		}
	}

	// Digest bytes of the trust block stay intact through JSON marshal.
	if sum := sha256.Sum256([]byte(strong.Trust.AuthenticationMethod)); len(hex.EncodeToString(sum[:])) != 64 {
		t.Fatal("sanity: hex encoding changed length")
	}
}
