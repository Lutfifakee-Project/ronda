package reporter

import (
	"fmt"
	"html"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/platforms/refcheck"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/wordpress"
)

// renderWordPressTerminal prints per-installation core integrity summaries.
func renderWordPressTerminal(b *strings.Builder, installs []wordpress.Result) {
	for i := 0; i < len(installs); i++ {
		wp := installs[i]
		line(b, "WordPress: "+wp.Root)
		line(b, "  version: "+wp.Version+"   locale: "+wp.Locale+" ("+wp.LocaleSource+", confidence "+wp.LocaleConfidence+")")
		if wp.RuntimeLanguage != "" {
			line(b, "  runtime language (WPLANG): "+wp.RuntimeLanguage)
		}
		if !wp.Verified {
			line(b, "  status: UNVERIFIED ("+wp.Reason+")")
			line(b, "  reference strength: "+refcheck.StrengthUnverified)
			continue
		}
		line(b, fmt.Sprintf("  files: %d expected, %d clean, %d modified, %d missing, %d extra, %d unverified", wp.TotalFiles, wp.CleanCount, len(wp.ModifiedFiles), len(wp.MissingFiles), len(wp.ExtraFiles), wp.UnverifiedCount))
		if len(wp.RootExtraFiles) > 0 {
			line(b, fmt.Sprintf("  unexpected root files: %d (informational)", len(wp.RootExtraFiles)))
		}
		line(b, "  manifest: "+wp.ManifestSource)
		line(b, "  reference strength: "+refcheck.StrengthLegacyDigestMatch+" (per-file MD5 checksums; legacy digests, weaker than SHA-256 or signatures)")
	}
}

// wordpressJSON converts WordPress results to a JSON-friendly shape.
func wordpressJSON(installs []wordpress.Result) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(installs))
	for i := 0; i < len(installs); i++ {
		wp := installs[i]
		m := map[string]interface{}{
			"root":              wp.Root,
			"version":           wp.Version,
			"locale":            wp.Locale,
			"locale_source":     wp.LocaleSource,
			"locale_confidence": wp.LocaleConfidence,
			"locale_inferred":   wp.LocaleInferred,
			"verified":          wp.Verified,
			"total_files":       wp.TotalFiles,
			"clean":             wp.CleanCount,
		}
		if wp.RuntimeLanguage != "" {
			m["runtime_language"] = wp.RuntimeLanguage
		}
		if wp.Reason != "" {
			m["reason"] = wp.Reason
		}
		if wp.ManifestSource != "" {
			m["manifest_source"] = wp.ManifestSource
		}
		// Explicit reference strength (additive): the WordPress checksum
		// API publishes per-file MD5 digests only, so a verified run is
		// honest legacy-digest evidence, never strong authentication.
		if wp.Verified {
			m["reference_strength"] = refcheck.StrengthLegacyDigestMatch
			m["reference_digest_algorithm"] = "md5"
			m["reference_authentication_method"] = "per-file MD5 checksums published by api.wordpress.org, compared against local core files"
			m["verification_confidence"] = "matching per-file MD5 digests are legacy evidence; collision-broken algorithms make this weaker than a SHA-256 or signature match"
		} else {
			m["reference_strength"] = refcheck.StrengthUnverified
		}
		m["modified"] = coreFileList(wp.ModifiedFiles)
		m["missing"] = coreFileList(wp.MissingFiles)
		m["extra"] = wp.ExtraFiles
		m["root_extra"] = wp.RootExtraFiles
		m["unverified"] = coreFileList(wp.UnverifiedFiles)
		out = append(out, m)
	}
	return out
}

func coreFileList(items []wordpress.CoreFile) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(items))
	for i := 0; i < len(items); i++ {
		f := items[i]
		m := map[string]interface{}{
			"path":   f.Path,
			"status": string(f.Status),
		}
		if f.MD5 != "" {
			m["expected_md5"] = f.MD5
		}
		if f.Actual != "" {
			m["actual_md5"] = f.Actual
		}
		if f.Reason != "" {
			m["reason"] = f.Reason
		}
		out = append(out, m)
	}
	return out
}

// renderWordPressHTML emits a WordPress integrity table section.
func renderWordPressHTML(b *strings.Builder, installs []wordpress.Result) {
	if len(installs) == 0 {
		return
	}
	esc := html.EscapeString
	line(b, "<h2>WordPress Core Integrity</h2>")
	for i := 0; i < len(installs); i++ {
		wp := installs[i]
		line(b, "<h3>"+esc(wp.Root)+"</h3>")
		line(b, "<ul>")
		line(b, fmt.Sprintf("<li>Version: %s, locale: %s (%s, confidence %s)</li>", esc(wp.Version), esc(wp.Locale), esc(wp.LocaleSource), esc(wp.LocaleConfidence)))
		if wp.RuntimeLanguage != "" {
			line(b, "<li>Runtime language (WPLANG): "+esc(wp.RuntimeLanguage)+"</li>")
		}
		if !wp.Verified {
			line(b, "<li>Status: UNVERIFIED - "+esc(wp.Reason)+"</li>")
			line(b, "<li>Reference strength: "+esc(refcheck.StrengthUnverified)+"</li>")
			line(b, "</ul>")
			continue
		}
		line(b, fmt.Sprintf("<li>Expected files: %d, clean: %d, modified: %d, missing: %d, extra: %d, unverified: %d</li>",
			wp.TotalFiles, wp.CleanCount, len(wp.ModifiedFiles), len(wp.MissingFiles), len(wp.ExtraFiles), wp.UnverifiedCount))
		line(b, "<li>Manifest: "+esc(wp.ManifestSource)+"</li>")
		line(b, "<li>Reference strength: "+esc(refcheck.StrengthLegacyDigestMatch)+" (per-file MD5 checksums; legacy digests, weaker than SHA-256 or signatures)</li>")
		line(b, "</ul>")

		if len(wp.ModifiedFiles)+len(wp.MissingFiles)+len(wp.ExtraFiles)+len(wp.RootExtraFiles) > 0 {
			line(b, "<table><thead><tr><th>Status</th><th>Path</th><th>Expected MD5</th><th>Actual MD5</th></tr></thead><tbody>")
			for j := 0; j < len(wp.ModifiedFiles); j++ {
				f := wp.ModifiedFiles[j]
				line(b, fmt.Sprintf("<tr><td class='sev-HIGH'>MODIFIED</td><td>%s</td><td>%s</td><td>%s</td></tr>", esc(f.Path), esc(f.MD5), esc(f.Actual)))
			}
			for j := 0; j < len(wp.MissingFiles); j++ {
				f := wp.MissingFiles[j]
				line(b, fmt.Sprintf("<tr><td class='sev-MEDIUM'>MISSING</td><td>%s</td><td>%s</td><td></td></tr>", esc(f.Path), esc(f.MD5)))
			}
			for j := 0; j < len(wp.ExtraFiles); j++ {
				line(b, fmt.Sprintf("<tr><td class='sev-LOW'>EXTRA</td><td>%s</td><td></td><td></td></tr>", esc(wp.ExtraFiles[j])))
			}
			for j := 0; j < len(wp.RootExtraFiles); j++ {
				line(b, fmt.Sprintf("<tr><td class='sev-INFO'>ROOT-EXTRA</td><td>%s</td><td></td><td></td></tr>", esc(wp.RootExtraFiles[j])))
			}
			line(b, "</tbody></table>")
		}
	}
}
