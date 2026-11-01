package reporter

import (
	"fmt"
	"html"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/platforms/drupal"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/joomla"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/laravel"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/refcheck"
)

// ---------------------------------------------------------------- Drupal --

func renderDrupalTerminal(b *strings.Builder, installs []drupal.Result) {
	for i := 0; i < len(installs); i++ {
		d := installs[i]
		line(b, "Drupal: "+d.Root)
		if d.Layout == drupal.LayoutComposer {
			line(b, "  layout: composer (project root "+d.ProjectRoot+")")
		} else {
			line(b, "  layout: tarball extraction")
		}
		if d.Version != "" {
			line(b, "  version: "+d.Version+" ("+versionSourcesText(d.VersionSources)+")")
		}
		if !d.Verified {
			line(b, "  status: UNVERIFIED ("+d.Reason+")")
			line(b, "  reference strength: "+refcheck.StrengthUnverified)
			continue
		}
		line(b, "  status: VERIFIED via "+d.VerificationMethod)
		line(b, "  reference: "+d.Reference.ArchiveURL)
		line(b, fmt.Sprintf("  files: %d expected, %d compared, %d skipped by policy, %d clean, %d modified, %d missing, %d unexpected, %d unverified",
			d.TotalFiles, d.TotalFiles-d.SkippedCount, d.SkippedCount, d.CleanCount,
			len(d.Modified), len(d.Missing), len(d.Unexpected), len(d.Unverified)))
		line(b, "  reference page: "+d.Reference.SourcePage+" (cached: "+boolText(d.Reference.Cached)+")")
		line(b, "  reference strength: "+d.Reference.Trust.Category+" ("+d.Reference.Trust.DigestAlgorithm+" digests)")
		for j := 0; j < len(d.SkippedAreas); j++ {
			line(b, "  excluded: "+d.SkippedAreas[j])
		}
	}
}

func drupalJSON(installs []drupal.Result) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(installs))
	for i := 0; i < len(installs); i++ {
		d := installs[i]
		m := map[string]interface{}{
			"platform":            "drupal",
			"root":                d.Root,
			"layout":              d.Layout,
			"verified":            d.Verified,
			"integrity_status":    integrityStatusOf(d.Verified),
			"verification_method": d.VerificationMethod,
			"total_files":         d.TotalFiles,
			"clean":               d.CleanCount,
		}
		if d.ProjectRoot != "" {
			m["project_root"] = d.ProjectRoot
		}
		if d.Version != "" {
			m["version"] = d.Version
			m["version_confidence"] = "exact (static sources agree)"
		}
		if len(d.VersionSources) > 0 {
			m["version_sources"] = versionSourcesJSON(d.VersionSources)
		}
		if d.Reason != "" {
			m["reason"] = d.Reason
		}
		if !d.Verified {
			m["reference_strength"] = refcheck.StrengthUnverified
		}
		if d.Verified {
			ref := map[string]interface{}{
				"source_page":  d.Reference.SourcePage,
				"archive_url":  d.Reference.ArchiveURL,
				"algorithm":    d.Reference.Algorithm,
				"archive_size": d.Reference.ArchiveSize,
				"cached":       d.Reference.Cached,
				"created":      d.Reference.Created,
			}
			addReferenceTrust(ref, d.Reference.Trust, "tar.gz")
			m["reference"] = ref
			m["compared_files"] = d.TotalFiles - d.SkippedCount
			m["skipped_by_policy"] = d.SkippedCount
			m["modified"] = fileStateList(d.Modified)
			m["missing"] = fileStateList(d.Missing)
			m["unverified"] = fileStateList(d.Unverified)
			m["unexpected"] = d.Unexpected
			m["excluded_areas"] = d.SkippedAreas
		}
		out = append(out, m)
	}
	return out
}

func renderDrupalHTML(b *strings.Builder, installs []drupal.Result) {
	if len(installs) == 0 {
		return
	}
	esc := html.EscapeString
	line(b, "<h2>Drupal Core Integrity</h2>")
	for i := 0; i < len(installs); i++ {
		d := installs[i]
		line(b, "<h3>"+esc(d.Root)+"</h3>")
		line(b, "<ul>")
		line(b, fmt.Sprintf("<li>Layout: %s</li>", esc(layoutText(d.Layout, d.ProjectRoot))))
		if d.Version != "" {
			line(b, fmt.Sprintf("<li>Version: %s (%s)</li>", esc(d.Version), esc(versionSourcesText(d.VersionSources))))
		}
		if !d.Verified {
			line(b, "<li>Status: UNVERIFIED - "+esc(d.Reason)+"</li>")
			line(b, "<li>Reference strength: "+esc(refcheck.StrengthUnverified)+"</li>")
			line(b, "</ul>")
			continue
		}
		line(b, fmt.Sprintf("<li>Status: VERIFIED via %s</li>", esc(d.VerificationMethod)))
		line(b, fmt.Sprintf("<li>Files: %d expected, %d compared, %d clean, %d modified, %d missing, %d unexpected, %d unverified</li>",
			d.TotalFiles, d.TotalFiles-d.SkippedCount, d.CleanCount, len(d.Modified), len(d.Missing), len(d.Unexpected), len(d.Unverified)))
		line(b, "<li>Reference: "+esc(d.Reference.SourcePage)+" (cached: "+boolText(d.Reference.Cached)+")</li>")
		line(b, "<li>Reference strength: "+esc(d.Reference.Trust.Category)+" ("+esc(d.Reference.Trust.DigestAlgorithm)+" digests)</li>")
		line(b, "</ul>")
		integrityTableHTML(b, d.Modified, d.Missing, d.Unexpected)
	}
}

// ---------------------------------------------------------------- Joomla --

func renderJoomlaTerminal(b *strings.Builder, installs []joomla.Result) {
	for i := 0; i < len(installs); i++ {
		j := installs[i]
		line(b, "Joomla: "+j.Root)
		if j.Version != "" {
			line(b, "  version: "+j.Version+" ("+versionSourcesText(j.VersionSources)+")")
		}
		if !j.Verified {
			line(b, "  status: UNVERIFIED ("+j.Reason+")")
			line(b, "  reference strength: "+refcheck.StrengthUnverified)
			continue
		}
		line(b, "  status: VERIFIED via "+j.VerificationMethod)
		line(b, "  reference: "+j.Reference.ArchiveURL)
		line(b, fmt.Sprintf("  files: %d expected, %d clean, %d modified, %d missing, %d unexpected, %d unverified",
			j.TotalFiles, j.CleanCount, len(j.Modified), len(j.Missing), len(j.Unexpected), len(j.Unverified)))
		line(b, "  reference page: "+j.Reference.SourcePage+" (cached: "+boolText(j.Reference.Cached)+")")
		line(b, "  reference strength: "+j.Reference.Trust.Category+" ("+j.Reference.Trust.DigestAlgorithm+" digests)")
		for k := 0; k < len(j.Warnings); k++ {
			line(b, "  warning: "+j.Warnings[k])
		}
		for k := 0; k < len(j.SkippedAreas); k++ {
			line(b, "  excluded: "+j.SkippedAreas[k])
		}
	}
}

func joomlaJSON(installs []joomla.Result) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(installs))
	for i := 0; i < len(installs); i++ {
		j := installs[i]
		m := map[string]interface{}{
			"platform":            "joomla",
			"root":                j.Root,
			"verified":            j.Verified,
			"integrity_status":    integrityStatusOf(j.Verified),
			"verification_method": j.VerificationMethod,
			"total_files":         j.TotalFiles,
			"clean":               j.CleanCount,
			"excluded_areas":      j.SkippedAreas,
		}
		if j.Version != "" {
			m["version"] = j.Version
			m["version_confidence"] = "exact (static sources agree)"
		}
		if len(j.VersionSources) > 0 {
			m["version_sources"] = versionSourcesJSON(j.VersionSources)
		}
		if j.Reason != "" {
			m["reason"] = j.Reason
		}
		if !j.Verified {
			m["reference_strength"] = refcheck.StrengthUnverified
		}
		if j.Verified {
			ref := map[string]interface{}{
				"source_page":  j.Reference.SourcePage,
				"archive_url":  j.Reference.ArchiveURL,
				"algorithm":    j.Reference.Algorithm,
				"digest":       j.Reference.Digest,
				"archive_size": j.Reference.ArchiveSize,
				"cached":       j.Reference.Cached,
				"created":      j.Reference.Created,
			}
			addReferenceTrust(ref, j.Reference.Trust, "tar.gz")
			m["reference"] = ref
			if len(j.Warnings) > 0 {
				m["reference_warnings"] = j.Warnings
			}
			m["modified"] = fileStateList(j.Modified)
			m["missing"] = fileStateList(j.Missing)
			m["unverified"] = fileStateList(j.Unverified)
			m["unexpected"] = j.Unexpected
		}
		out = append(out, m)
	}
	return out
}

func renderJoomlaHTML(b *strings.Builder, installs []joomla.Result) {
	if len(installs) == 0 {
		return
	}
	esc := html.EscapeString
	line(b, "<h2>Joomla Core Integrity</h2>")
	for i := 0; i < len(installs); i++ {
		j := installs[i]
		line(b, "<h3>"+esc(j.Root)+"</h3>")
		line(b, "<ul>")
		if j.Version != "" {
			line(b, fmt.Sprintf("<li>Version: %s (%s)</li>", esc(j.Version), esc(versionSourcesText(j.VersionSources))))
		}
		if !j.Verified {
			line(b, "<li>Status: UNVERIFIED - "+esc(j.Reason)+"</li>")
			line(b, "<li>Reference strength: "+esc(refcheck.StrengthUnverified)+"</li>")
			line(b, "</ul>")
			continue
		}
		line(b, fmt.Sprintf("<li>Status: VERIFIED via %s</li>", esc(j.VerificationMethod)))
		line(b, fmt.Sprintf("<li>Files: %d expected, %d clean, %d modified, %d missing, %d unexpected, %d unverified</li>",
			j.TotalFiles, j.CleanCount, len(j.Modified), len(j.Missing), len(j.Unexpected), len(j.Unverified)))
		line(b, "<li>Reference: "+esc(j.Reference.SourcePage)+" (cached: "+boolText(j.Reference.Cached)+")</li>")
		line(b, "<li>Reference strength: "+esc(j.Reference.Trust.Category)+" ("+esc(j.Reference.Trust.DigestAlgorithm)+" digests)</li>")
		for k := 0; k < len(j.Warnings); k++ {
			line(b, "<li class='sev-MEDIUM'>Warning: "+esc(j.Warnings[k])+"</li>")
		}
		line(b, "</ul>")
		integrityTableHTML(b, j.Modified, j.Missing, j.Unexpected)
	}
}

// --------------------------------------------------------------- Laravel --

func renderLaravelTerminal(b *strings.Builder, installs []laravel.Result) {
	for i := 0; i < len(installs); i++ {
		l := installs[i]
		line(b, "Laravel: "+l.Root)
		line(b, "  confidence: "+l.Confidence)
		if l.Version != "" {
			line(b, "  laravel/framework: "+l.Version+" ("+l.VersionSource+")")
		}
		line(b, fmt.Sprintf("  packages: %d locked, %d installed; conflicts: %d", l.PackagesLocked, l.PackagesInstalled, len(l.VersionConflicts)))
		line(b, "  integrity: "+l.IntegrityStatus+" ("+l.IntegrityReason+")")
		line(b, "  reference strength: "+refcheck.StrengthUnverified+" (no official per-file reference exists for framework applications)")
		for j := 0; j < len(l.Checks); j++ {
			c := l.Checks[j]
			if c.Status == "OK" {
				continue
			}
			line(b, "  ["+c.Status+"] "+c.Name+" ("+c.Detail+")")
		}
	}
}

func laravelJSON(installs []laravel.Result) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(installs))
	for i := 0; i < len(installs); i++ {
		l := installs[i]
		m := map[string]interface{}{
			"platform":                "laravel",
			"root":                    l.Root,
			"confidence":              l.Confidence,
			"integrity_status":        l.IntegrityStatus,
			"integrity_reason":        l.IntegrityReason,
			"verification_method":     laravel.VerificationMethod,
			"reference_strength":      refcheck.StrengthUnverified,
			"verification_confidence": "Laravel publishes no per-file reference for framework applications; composer.lock is used only for version identification and structural posture checks",
			"packages_locked":         l.PackagesLocked,
			"packages_installed":      l.PackagesInstalled,
			"require":                 laravelRequireJSON(l.Require),
			"checks":                  laravelChecksJSON(l.Checks),
		}
		if l.Version != "" {
			m["version"] = l.Version
			m["version_source"] = l.VersionSource
		}
		if l.SourceRef != "" {
			m["source_reference"] = l.SourceRef
		}
		if len(l.VersionConflicts) > 0 {
			m["version_conflicts"] = l.VersionConflicts
		}
		if len(l.Notes) > 0 {
			m["notes"] = l.Notes
		}
		out = append(out, m)
	}
	return out
}

func renderLaravelHTML(b *strings.Builder, installs []laravel.Result) {
	if len(installs) == 0 {
		return
	}
	esc := html.EscapeString
	line(b, "<h2>Laravel Framework Profile</h2>")
	for i := 0; i < len(installs); i++ {
		l := installs[i]
		line(b, "<h3>"+esc(l.Root)+"</h3>")
		line(b, "<ul>")
		line(b, "<li>Confidence: "+esc(l.Confidence)+"</li>")
		if l.Version != "" {
			line(b, "<li>laravel/framework: "+esc(l.Version)+" ("+esc(l.VersionSource)+")</li>")
		}
		line(b, fmt.Sprintf("<li>Packages: %d locked, %d installed</li>", l.PackagesLocked, l.PackagesInstalled))
		if len(l.VersionConflicts) > 0 {
			line(b, "<li>Conflicts: "+esc(strings.Join(l.VersionConflicts, "; "))+"</li>")
		}
		line(b, "<li>Integrity: "+esc(l.IntegrityStatus)+" - "+esc(l.IntegrityReason)+"</li>")
		line(b, "<li>Reference strength: "+esc(refcheck.StrengthUnverified)+" (no official per-file reference exists for framework applications)</li>")
		line(b, "</ul>")
		if len(l.Checks) > 0 {
			line(b, "<table><thead><tr><th>Status</th><th>Check</th><th>Path</th><th>Detail</th></tr></thead><tbody>")
			for j := 0; j < len(l.Checks); j++ {
				c := l.Checks[j]
				line(b, fmt.Sprintf("<tr><td class='sev-%s'>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
					esc(c.Status), esc(c.Status), esc(c.Name), esc(c.Path), esc(c.Detail)))
			}
			line(b, "</tbody></table>")
		}
	}
}

// ----------------------------------------------------------- shared bits --

// addReferenceTrust writes the explicit trust metadata of one archive
// reference into its JSON representation. Every field is additive: the
// pre-existing keys are untouched, so older consumers keep parsing the
// output. The four facts the trust model keeps separate are all visible
// here: what the reference is, how strongly it was authenticated, whether
// that authentication succeeded, and how much confidence the evidence
// deserves.
func addReferenceTrust(ref map[string]interface{}, trust refcheck.Trust, archiveFormat string) {
	ref["reference_source"] = ref["source_page"]
	ref["archive_format"] = archiveFormat
	ref["reference_digest_algorithm"] = trust.DigestAlgorithm
	ref["reference_authentication_method"] = trust.AuthenticationMethod
	ref["reference_strength"] = trust.Category
	ref["reference_verified"] = true
	ref["verification_confidence"] = trust.Confidence
}

// integrityTableHTML renders one table for modified/missing/unexpected rows.
// drupal.FileState and joomla.FileState are aliases of the same underlying
// refcheck.FileState type, so one signature serves both platforms.
func integrityTableHTML(b *strings.Builder, modified, missing []drupal.FileState, unexpected []string) {
	if len(modified)+len(missing)+len(unexpected) == 0 {
		return
	}
	esc := html.EscapeString
	line(b, "<table><thead><tr><th>Status</th><th>Path</th><th>Expected</th><th>Actual</th></tr></thead><tbody>")
	for i := 0; i < len(modified); i++ {
		line(b, fmt.Sprintf("<tr><td class='sev-HIGH'>MODIFIED</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			esc(modified[i].Path), esc(shortHash(modified[i].ExpectedSHA256)), esc(shortHash(modified[i].ActualSHA256))))
	}
	for i := 0; i < len(missing); i++ {
		line(b, fmt.Sprintf("<tr><td class='sev-MEDIUM'>MISSING</td><td>%s</td><td>%s</td><td></td></tr>",
			esc(missing[i].Path), esc(shortHash(missing[i].ExpectedSHA256))))
	}
	for i := 0; i < len(unexpected); i++ {
		line(b, fmt.Sprintf("<tr><td class='sev-LOW'>EXTRA</td><td>%s</td><td></td><td></td></tr>", esc(unexpected[i])))
	}
	line(b, "</tbody></table>")
}

func fileStateList(items []drupal.FileState) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(items))
	for i := 0; i < len(items); i++ {
		f := items[i]
		m := map[string]interface{}{
			"path":   f.Path,
			"status": f.Status,
		}
		if f.ExpectedSHA256 != "" {
			m["expected_sha256"] = f.ExpectedSHA256
		}
		if f.ActualSHA256 != "" {
			m["actual_sha256"] = f.ActualSHA256
		}
		if f.Reason != "" {
			m["reason"] = f.Reason
		}
		out = append(out, m)
	}
	return out
}

func versionSourcesJSON(sources []refcheck.VersionSource) []map[string]string {
	out := make([]map[string]string, 0, len(sources))
	for _, s := range sources {
		out = append(out, map[string]string{"value": s.Value, "source": s.Source})
	}
	return out
}

func versionSourcesText(sources []refcheck.VersionSource) string {
	parts := make([]string, 0, len(sources))
	for i := 0; i < len(sources); i++ {
		parts = append(parts, sources[i].Source+"="+sources[i].Value)
	}
	return strings.Join(parts, ", ")
}

func laravelRequireJSON(pkgs []laravel.PackageInfo) []map[string]string {
	out := make([]map[string]string, 0, len(pkgs))
	for i := 0; i < len(pkgs); i++ {
		out = append(out, map[string]string{"name": pkgs[i].Name, "version": pkgs[i].Version})
	}
	return out
}

func laravelChecksJSON(checks []laravel.Check) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(checks))
	for i := 0; i < len(checks); i++ {
		c := checks[i]
		m := map[string]interface{}{
			"name":   c.Name,
			"status": c.Status,
			"detail": c.Detail,
		}
		if c.Path != "" {
			m["path"] = c.Path
		}
		if c.Line != 0 {
			m["line"] = c.Line
		}
		if c.Evidence != "" {
			m["evidence"] = c.Evidence
		}
		out = append(out, m)
	}
	return out
}

func integrityStatusOf(verified bool) string {
	if verified {
		return "VERIFIED"
	}
	return "UNVERIFIED"
}

func layoutText(layout, projectRoot string) string {
	if layout == "composer" {
		return "composer (project root " + projectRoot + ")"
	}
	return "tarball extraction"
}

func boolText(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12] + "..."
	}
	return h
}
