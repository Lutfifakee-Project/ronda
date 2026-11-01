package reporter

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/ronda/internal/analyzer"
	"github.com/Lutfifakee-Project/ronda/internal/finding"
	"github.com/Lutfifakee-Project/ronda/internal/persistence"
	"github.com/Lutfifakee-Project/ronda/internal/scanner"
	"github.com/Lutfifakee-Project/ronda/internal/version"
)

var nl = string([]byte{10})

// Options selects the output format and destination.
type Options struct {
	Format string
	Output string
}

// Write renders the result in the requested format.
func Write(w io.Writer, res scanner.Result, opts Options) error {
	format := strings.ToLower(strings.TrimSpace(opts.Format))
	if format == "" {
		format = "terminal"
	}

	var (
		body []byte
		err  error
	)

	switch format {
	case "terminal":
		body = []byte(renderTerminal(res))
	case "json":
		body, err = renderJSON(res)
	case "html":
		body = []byte(renderHTML(res))
	default:
		return fmt.Errorf("unsupported format %q (use terminal, html or json)", format)
	}
	if err != nil {
		return err
	}

	if opts.Output == "" {
		_, err = w.Write(body)
		return err
	}

	if err := os.WriteFile(opts.Output, body, 0o644); err != nil {
		return err
	}

	fmt.Fprintln(w, "Report written to "+opts.Output)
	return nil
}

func line(b *strings.Builder, s string) {
	b.WriteString(s)
	b.WriteString(nl)
}

func renderTerminal(res scanner.Result) string {
	var b strings.Builder

	line(&b, "RONDA Security Scanner")
	line(&b, "Version: "+version.Version+"  (rules "+version.RulesVersion+")")
	line(&b, "")
	line(&b, "Target: "+res.Target)
	line(&b, "")

	if len(res.Platforms) == 0 {
		line(&b, "No supported platform detected.")
	} else {
		for _, p := range res.Platforms {
			line(&b, "[+] "+titleCase(p)+" detected")
		}
	}
	line(&b, "")

	if len(res.WordPress) > 0 {
		renderWordPressTerminal(&b, res.WordPress)
		line(&b, "")
	}

	if len(res.Drupal) > 0 {
		renderDrupalTerminal(&b, res.Drupal)
		line(&b, "")
	}
	if len(res.Joomla) > 0 {
		renderJoomlaTerminal(&b, res.Joomla)
		line(&b, "")
	}
	if len(res.Laravel) > 0 {
		renderLaravelTerminal(&b, res.Laravel)
		line(&b, "")
	}

	line(&b, fmt.Sprintf("Files scanned: %d   PHP files: %d   skipped: %d", res.FilesScanned, res.PHPFiles, res.FilesSkipped))
	line(&b, fmt.Sprintf("Workers: %d   duration: %s", res.Workers, res.FinishedAt.Sub(res.StartedAt).Round(time.Millisecond)))
	line(&b, "")

	counts := finding.CountBySeverity(res.Findings)
	summary := fmt.Sprintf("Findings: %d total", len(res.Findings))
	for _, sev := range finding.Severities {
		if counts[sev] == 0 {
			continue
		}
		summary += fmt.Sprintf("   %s: %d", string(sev), counts[sev])
	}
	line(&b, summary)
	line(&b, categoryBreakdown(res.Findings))
	line(&b, "")

	if res.Persistence != nil {
		renderPersistenceScope(&b, *res.Persistence)
		line(&b, "")
	}

	if len(res.Findings) == 0 {
		line(&b, "[OK] No findings.")
	} else {
		for _, f := range res.Findings {
			line(&b, fmt.Sprintf("[%s] %s", string(f.Severity), f.Title))
			if f.Path != "" {
				line(&b, "    path: "+f.Path)
			}
			if f.Rule != "" {
				meta := ""
				if m, ok := analyzer.RuleMetadata(f.Rule); ok {
					meta = " (" + m.Category + ")"
				} else if m, ok := persistence.RuleMetadata(f.Rule); ok {
					meta = " (" + m.Category
					if len(m.MITRE) > 0 {
						meta += ", " + strings.Join(m.MITRE, " ")
					}
					meta += ")"
				}
				line(&b, "    rule: "+f.Rule+meta)
			}
			if f.Line > 0 {
				line(&b, fmt.Sprintf("    line: %d", f.Line))
			}
			if f.Confidence != "" {
				line(&b, "    confidence: "+f.Confidence)
			}
			if f.Target != "" {
				line(&b, "    target: "+f.Target)
			}
			if f.User != "" {
				line(&b, "    user: "+f.User)
			}
			if f.Owner != "" {
				line(&b, "    owner: "+f.Owner)
			}
			if f.Permissions != "" {
				line(&b, "    permissions: "+f.Permissions)
			}
			if f.Package != "" {
				line(&b, "    package: "+f.Package)
			}
			if f.Trust != "" {
				line(&b, "    trust: "+f.Trust)
			}
			if f.Evidence != "" {
				line(&b, "    evidence: "+f.Evidence)
			}
			for _, s := range f.Signals {
				loc := ""
				if s.Line > 0 {
					loc = fmt.Sprintf(" line %d:", s.Line)
				}
				line(&b, "      - "+s.Rule+loc+" "+s.Detail)
			}
		}
	}
	line(&b, "")
	line(&b, "Absence of findings is not proof of absence of compromise: static")
	line(&b, "analysis sees only what the rules model. Review the evidence.")

	if len(res.Notes) > 0 {
		line(&b, "")
		for _, n := range res.Notes {
			line(&b, "[i] "+n)
		}
	}

	if len(res.Errors) > 0 {
		line(&b, "")
		line(&b, fmt.Sprintf("%d files could not be fully inspected.", len(res.Errors)))
	}

	line(&b, "")
	line(&b, "Scan completed.")
	return b.String()
}

func renderJSON(res scanner.Result) ([]byte, error) {
	counts := make(map[string]int)
	for sev, n := range finding.CountBySeverity(res.Findings) {
		counts[string(sev)] = n
	}

	findings := make([]map[string]interface{}, 0, len(res.Findings))
	for _, f := range res.Findings {
		m := map[string]interface{}{
			"status":   string(f.Status),
			"severity": string(f.Severity),
			"title":    f.Title,
		}
		if f.Platform != "" {
			m["platform"] = f.Platform
		}
		if f.Path != "" {
			m["path"] = f.Path
		}
		if f.Line != 0 {
			m["line"] = f.Line
		}
		if f.Rule != "" {
			m["rule"] = f.Rule
		}
		if f.Evidence != "" {
			m["evidence"] = f.Evidence
		}
		if f.Recommendation != "" {
			m["recommendation"] = f.Recommendation
		}
		if f.Category != "" {
			m["category"] = f.Category
		}
		if f.Confidence != "" {
			m["confidence"] = f.Confidence
		}
		if len(f.MITRE) > 0 {
			m["mitre"] = f.MITRE
		}
		if f.Target != "" {
			m["target"] = f.Target
		}
		if f.User != "" {
			m["user"] = f.User
		}
		if f.Owner != "" {
			m["owner"] = f.Owner
		}
		if f.Permissions != "" {
			m["permissions"] = f.Permissions
		}
		if f.Modified != "" {
			m["modified"] = f.Modified
		}
		if f.Package != "" {
			m["package"] = f.Package
		}
		if f.Trust != "" {
			m["trust"] = f.Trust
		}
		if f.Kind != "" {
			m["kind"] = f.Kind
		}
		if len(f.Signals) > 0 {
			sig := make([]map[string]interface{}, 0, len(f.Signals))
			for _, s := range f.Signals {
				sm := map[string]interface{}{"signal": s.Rule}
				if s.Line != 0 {
					sm["line"] = s.Line
				}
				if s.Detail != "" {
					sm["detail"] = s.Detail
				}
				sig = append(sig, sm)
			}
			m["signals"] = sig
		}
		findings = append(findings, m)
	}

	report := map[string]interface{}{
		"tool":            "ronda",
		"version":         version.Version,
		"rules_version":   res.RulesVersion,
		"target":          res.Target,
		"started_at":      res.StartedAt.UTC().Format(time.RFC3339),
		"finished_at":     res.FinishedAt.UTC().Format(time.RFC3339),
		"platforms":       res.Platforms,
		"files_scanned":   res.FilesScanned,
		"php_files":       res.PHPFiles,
		"files_skipped":   res.FilesSkipped,
		"truncated":       res.Truncated,
		"severity_counts": counts,
		"findings":        findings,
		"wordpress":       wordpressJSON(res.WordPress),
		"drupal":          drupalJSON(res.Drupal),
		"joomla":          joomlaJSON(res.Joomla),
		"laravel":         laravelJSON(res.Laravel),
		"notes":           res.Notes,
		"errors":          res.Errors,
	}
	if res.Persistence != nil {
		report["persistence"] = persistenceJSON(*res.Persistence)
	}

	return json.MarshalIndent(report, "", "  ")
}

// persistenceJSON renders the Phase 5 scope object. Findings themselves are
// already in the shared findings array with their artifact metadata.
func persistenceJSON(rep persistence.Report) map[string]interface{} {
	counts := make(map[string]int)
	for sev, n := range finding.CountBySeverity(rep.Findings) {
		counts[string(sev)] = n
	}
	return map[string]interface{}{
		"root":                rep.Root,
		"live_host":           rep.LiveHost,
		"distribution":        rep.Distribution,
		"package_database":    rep.PackageDB,
		"init_systems":        rep.InitSystems,
		"artifacts_inspected": rep.ArtifactsInspected,
		"targets_inspected":   rep.TargetsInspected,
		"denied":              rep.Denied,
		"unverified":          rep.Unverified,
		"notes":               rep.Notes,
		"severity_counts":     counts,
	}
}

func renderHTML(res scanner.Result) string {
	esc := html.EscapeString

	var b strings.Builder
	line(&b, "<!doctype html>")
	line(&b, "<html lang='en'>")
	line(&b, "<head>")
	line(&b, "<meta charset='utf-8'>")
	line(&b, "<meta name='viewport' content='width=device-width, initial-scale=1'>")
	line(&b, "<title>RONDA report</title>")
	line(&b, "<style>")
	line(&b, "body{font-family:system-ui,sans-serif;margin:2rem;color:#111}")
	line(&b, "table{border-collapse:collapse;width:100%;margin-top:1rem}")
	line(&b, "th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;font-size:.9rem}")
	line(&b, "th{background:#f3f3f3}")
	line(&b, ".sev-CRITICAL{color:#b00020;font-weight:700}")
	line(&b, ".sev-HIGH{color:#c2410c;font-weight:700}")
	line(&b, ".sev-MEDIUM{color:#a16207}")
	line(&b, ".sev-LOW{color:#555}")
	line(&b, ".sev-INFO{color:#666}")
	line(&b, ".meta{color:#555;font-size:.9rem}")
	line(&b, "</style>")
	line(&b, "</head>")
	line(&b, "<body>")

	line(&b, "<h1>RONDA Security Scanner</h1>")
	line(&b, fmt.Sprintf("<p class='meta'>Version %s, rules %s, generated %s</p>", esc(version.Version), esc(res.RulesVersion), esc(time.Now().UTC().Format(time.RFC3339))))
	line(&b, fmt.Sprintf("<p class='meta'>Target: %s</p>", esc(res.Target)))

	line(&b, "<h2>Summary</h2>")
	line(&b, "<ul>")
	line(&b, fmt.Sprintf("<li>Platforms: %s</li>", esc(joinOr(res.Platforms, "none detected"))))
	line(&b, fmt.Sprintf("<li>Files scanned: %d, PHP files: %d, skipped: %d</li>", res.FilesScanned, res.PHPFiles, res.FilesSkipped))
	line(&b, fmt.Sprintf("<li>Duration: %s</li>", esc(res.FinishedAt.Sub(res.StartedAt).Round(time.Millisecond).String())))
	line(&b, fmt.Sprintf("<li>Coverage complete: %t</li>", !res.Truncated && len(res.DeniedDirs) == 0))
	line(&b, "</ul>")

	renderWordPressHTML(&b, res.WordPress)
	renderDrupalHTML(&b, res.Drupal)
	renderJoomlaHTML(&b, res.Joomla)
	renderLaravelHTML(&b, res.Laravel)

	if len(res.Notes) > 0 {
		line(&b, "<h2>Notes</h2><ul>")
		for _, n := range res.Notes {
			line(&b, "<li>"+esc(n)+"</li>")
		}
		line(&b, "</ul>")
	}

	line(&b, "<h2>Findings</h2>")
	if len(res.Findings) == 0 {
		line(&b, "<p>No findings.</p>")
	} else {
		// Persistence findings carry target/owner/permission/MITRE
		// metadata. The extra columns appear only when some finding
		// has them, so legacy reports keep their exact shape.
		hasMeta := false
		for _, f := range res.Findings {
			if f.Target != "" || f.Owner != "" || len(f.MITRE) > 0 || f.Permissions != "" {
				hasMeta = true
				break
			}
		}
		if hasMeta {
			line(&b, "<table><thead><tr><th>Severity</th><th>Status</th><th>Title</th><th>Rule</th><th>Line</th><th>Confidence</th><th>Path</th><th>Target</th><th>Owner</th><th>Perms</th><th>MITRE</th><th>Evidence</th></tr></thead><tbody>")
			for _, f := range res.Findings {
				conf := f.Confidence
				if conf == "" {
					conf = "-"
				}
				mitre := strings.Join(f.MITRE, " ")
				if mitre == "" {
					mitre = "-"
				}
				target := f.Target
				if target == "" {
					target = "-"
				}
				owner := f.Owner
				if owner == "" {
					owner = "-"
				}
				perms := f.Permissions
				if perms == "" {
					perms = "-"
				}
				line(&b, fmt.Sprintf("<tr><td class='sev-%s'>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
					esc(string(f.Severity)), esc(string(f.Severity)), esc(string(f.Status)),
					esc(f.Title), esc(f.Rule), f.Line, esc(conf),
					esc(f.Path), esc(target), esc(owner), esc(perms), esc(mitre), esc(f.Evidence)))
			}
			line(&b, "</tbody></table>")
		} else {
			line(&b, "<table><thead><tr><th>Severity</th><th>Status</th><th>Title</th><th>Rule</th><th>Line</th><th>Confidence</th><th>Path</th><th>Evidence</th></tr></thead><tbody>")
			for _, f := range res.Findings {
				conf := f.Confidence
				if conf == "" {
					conf = "-"
				}
				line(&b, fmt.Sprintf("<tr><td class='sev-%s'>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>",
					esc(string(f.Severity)), esc(string(f.Severity)), esc(string(f.Status)),
					esc(f.Title), esc(f.Rule), f.Line, esc(conf),
					esc(f.Path), esc(f.Evidence)))
			}
			line(&b, "</tbody></table>")
		}
	}

	if len(res.Errors) > 0 {
		line(&b, "<h2>Inspection errors</h2><ul>")
		for _, e := range res.Errors {
			line(&b, "<li>"+esc(e)+"</li>")
		}
		line(&b, "</ul>")
	}

	line(&b, "<p class='meta'>Absence of findings is not proof of absence of compromise: static analysis sees only what the rules model.</p>")
	line(&b, "</body></html>")
	return b.String()
}

// WritePersistence renders a standalone persistence report in the requested
// format. It shares the same evidence and metadata as the combined scan so
// all report formats represent the same underlying findings.
func WritePersistence(w io.Writer, rep persistence.Report, opts Options) error {
	format := strings.ToLower(strings.TrimSpace(opts.Format))
	if format == "" {
		format = "terminal"
	}

	var (
		body []byte
		err  error
	)
	switch format {
	case "terminal":
		body = []byte(renderPersistenceTerminal(rep))
	case "json":
		doc := persistenceJSON(rep)
		// The standalone report must carry the findings themselves; the
		// combined scan report embeds them in the main findings array.
		doc["findings"] = rep.Findings
		body, err = json.MarshalIndent(doc, "", "  ")
	case "html":
		body = []byte(renderPersistenceHTML(rep))
	default:
		return fmt.Errorf("unsupported format %q (use terminal, html or json)", format)
	}
	if err != nil {
		return err
	}

	if opts.Output == "" {
		_, err = w.Write(body)
		return err
	}
	if err := os.WriteFile(opts.Output, body, 0o644); err != nil {
		return err
	}
	fmt.Fprintln(w, "Report written to "+opts.Output)
	return nil
}

// renderPersistenceTerminal prints the standalone persistence report.
func renderPersistenceTerminal(rep persistence.Report) string {
	var b strings.Builder
	line(&b, "RONDA Persistence & Backdoor Scan")
	line(&b, "Version: "+version.Version+"  (rules "+version.RulesVersion+")")
	line(&b, "")
	renderPersistenceScope(&b, rep)
	line(&b, "")

	counts := finding.CountBySeverity(rep.Findings)
	summary := fmt.Sprintf("Findings: %d total", len(rep.Findings))
	for _, sev := range finding.Severities {
		if counts[sev] == 0 {
			continue
		}
		summary += fmt.Sprintf("   %s: %d", string(sev), counts[sev])
	}
	line(&b, summary)
	line(&b, categoryBreakdown(rep.Findings))
	line(&b, "")

	if len(rep.Findings) == 0 {
		line(&b, "[OK] No persistence findings.")
	} else {
		for _, f := range rep.Findings {
			line(&b, fmt.Sprintf("[%s] %s", string(f.Severity), f.Title))
			if f.Path != "" {
				line(&b, "    artifact: "+f.Path)
			}
			if f.Line > 0 {
				line(&b, fmt.Sprintf("    line: %d", f.Line))
			}
			if f.Rule != "" {
				meta := ""
				if m, ok := persistence.RuleMetadata(f.Rule); ok {
					meta = " (" + m.Category
					if len(m.MITRE) > 0 {
						meta += ", " + strings.Join(m.MITRE, " ")
					}
					meta += ")"
				}
				line(&b, "    rule: "+f.Rule+meta)
			}
			if f.Confidence != "" {
				line(&b, "    confidence: "+f.Confidence)
			}
			if f.Target != "" {
				line(&b, "    target: "+f.Target)
			}
			if f.User != "" {
				line(&b, "    user: "+f.User)
			}
			if f.Owner != "" {
				line(&b, "    owner: "+f.Owner)
			}
			if f.Permissions != "" {
				line(&b, "    permissions: "+f.Permissions)
			}
			if f.Package != "" {
				line(&b, "    package: "+f.Package)
			}
			if f.Trust != "" {
				line(&b, "    trust: "+f.Trust)
			}
			if f.Evidence != "" {
				line(&b, "    evidence: "+f.Evidence)
			}
			for _, s := range f.Signals {
				line(&b, "      - "+s.Rule+" "+s.Detail)
			}
		}
	}

	if len(rep.Denied) > 0 {
		line(&b, "")
		line(&b, fmt.Sprintf("%d artifact location(s) could not be read:", len(rep.Denied)))
		for _, d := range rep.Denied {
			line(&b, "  [DENIED] "+d)
		}
	}
	if len(rep.Unverified) > 0 {
		line(&b, "")
		line(&b, fmt.Sprintf("%d scope(s) reported as UNVERIFIED (not CLEAN):", len(rep.Unverified)))
		for _, u := range rep.Unverified {
			line(&b, "  [UNVERIFIED] "+u)
		}
	}
	if len(rep.Notes) > 0 {
		line(&b, "")
		for _, n := range rep.Notes {
			line(&b, "[i] "+n)
		}
	}
	line(&b, "")
	line(&b, "Static configuration analysis is not proof that a program executed.")
	line(&b, "Absence of findings is not proof of absence of compromise.")
	line(&b, "")
	line(&b, "Scan completed.")
	return b.String()
}

// renderPersistenceScope prints the scope block shared by both terminal
// renderers.
func renderPersistenceScope(b *strings.Builder, rep persistence.Report) {
	rootLabel := rep.Root
	if rootLabel == "" {
		rootLabel = "/ (live host)"
	}
	line(b, "Root: "+rootLabel)
	if rep.Distribution != "" {
		line(b, "Distribution: "+rep.Distribution)
	}
	if len(rep.InitSystems) > 0 {
		line(b, "Init/scheduling systems: "+strings.Join(rep.InitSystems, ", "))
	}
	db := rep.PackageDB
	if db == "" {
		db = "none available (provenance unverified)"
	}
	line(b, "Package provenance: "+db)
	line(b, fmt.Sprintf("Persistence artifacts inspected: %d   referenced targets: %d", rep.ArtifactsInspected, rep.TargetsInspected))
	if rep.DeniedCount > 0 {
		line(b, fmt.Sprintf("Unreadable locations: %d (coverage incomplete, never reported as clean)", rep.DeniedCount))
	}
	if rep.UnverifiedCount > 0 {
		line(b, fmt.Sprintf("Unverified scopes: %d (reported as UNVERIFIED)", rep.UnverifiedCount))
	}
}

// renderPersistenceHTML renders the standalone persistence HTML report.
func renderPersistenceHTML(rep persistence.Report) string {
	esc := html.EscapeString
	var b strings.Builder
	line(&b, "<!doctype html>")
	line(&b, "<html lang='en'>")
	line(&b, "<head>")
	line(&b, "<meta charset='utf-8'>")
	line(&b, "<meta name='viewport' content='width=device-width, initial-scale=1'>")
	line(&b, "<title>RONDA persistence report</title>")
	line(&b, "<style>")
	line(&b, "body{font-family:system-ui,sans-serif;margin:2rem;color:#111}")
	line(&b, "table{border-collapse:collapse;width:100%;margin-top:1rem}")
	line(&b, "th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;font-size:.9rem}")
	line(&b, "th{background:#f3f3f3}")
	line(&b, ".sev-CRITICAL{color:#b00020;font-weight:700}")
	line(&b, ".sev-HIGH{color:#c2410c;font-weight:700}")
	line(&b, ".sev-MEDIUM{color:#a16207}")
	line(&b, ".sev-LOW{color:#555}")
	line(&b, ".sev-INFO{color:#666}")
	line(&b, ".meta{color:#555;font-size:.9rem}")
	line(&b, "</style>")
	line(&b, "</head>")
	line(&b, "<body>")
	line(&b, "<h1>RONDA Persistence &amp; Backdoor Scan</h1>")
	rootLabel := rep.Root
	if rootLabel == "" {
		rootLabel = "/ (live host)"
	}
	line(&b, fmt.Sprintf("<p class='meta'>Root: %s, distribution: %s, provenance: %s</p>",
		esc(rootLabel), esc(rep.Distribution), esc(rep.PackageDB)))
	line(&b, fmt.Sprintf("<p class='meta'>Artifacts inspected: %d, referenced targets: %d, denied: %d, unverified: %d</p>",
		rep.ArtifactsInspected, rep.TargetsInspected, rep.DeniedCount, rep.UnverifiedCount))

	if len(rep.Denied) > 0 {
		line(&b, "<h2>Unreadable locations</h2><ul>")
		for _, d := range rep.Denied {
			line(&b, "<li>"+esc(d)+"</li>")
		}
		line(&b, "</ul>")
	}
	if len(rep.Unverified) > 0 {
		line(&b, "<h2>Unverified scopes</h2><ul>")
		for _, u := range rep.Unverified {
			line(&b, "<li>"+esc(u)+"</li>")
		}
		line(&b, "</ul>")
	}

	line(&b, "<h2>Findings</h2>")
	if len(rep.Findings) == 0 {
		line(&b, "<p>No persistence findings.</p>")
	} else {
		line(&b, "<table><thead><tr><th>Severity</th><th>Category</th><th>Rule</th><th>Line</th><th>Confidence</th><th>Artifact</th><th>Target</th><th>User</th><th>Owner</th><th>Perms</th><th>MITRE</th><th>Evidence</th></tr></thead><tbody>")
		for _, f := range rep.Findings {
			conf := f.Confidence
			if conf == "" {
				conf = "-"
			}
			cat := f.Category
			if cat == "" {
				cat = "-"
			}
			owner := f.Owner
			if owner == "" {
				owner = "-"
			}
			perms := f.Permissions
			if perms == "" {
				perms = "-"
			}
			mitre := strings.Join(f.MITRE, " ")
			if mitre == "" {
				mitre = "-"
			}
			line(&b, fmt.Sprintf("<tr><td class='sev-%s'>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
				esc(string(f.Severity)), esc(string(f.Severity)), esc(cat), esc(f.Rule), f.Line, esc(conf),
				esc(f.Path), esc(f.Target), esc(f.User), esc(owner), esc(perms), esc(mitre), esc(f.Evidence)))
		}
		line(&b, "</tbody></table>")
	}
	line(&b, "<p class='meta'>Static configuration analysis is not proof that a program executed. Absence of findings is not proof of absence of compromise.</p>")
	line(&b, "</body></html>")
	return b.String()
}

// categoryBreakdown renders the detection-category summary so the terminal
// output distinguishes integrity results, malware and webshell findings,
// suspicious capabilities, informational observations, unverified
// classifications and persistence mechanisms at a glance.
func categoryBreakdown(items []finding.Finding) string {
	order := []string{
		"WEBSHELL", "COMMAND_EXECUTION", "CODE_INJECTION", "OBFUSCATION",
		"PAYLOAD_LOADER", "FILE_DROPPER", "DYNAMIC_EXECUTION",
		"POLYGLOT_OR_BINARY_ANOMALY", "BROAD_SIGNAL", "INTEGRITY",
	}
	order = append(order, persistence.Categories()...)
	counts := make(map[string]int)
	for _, f := range items {
		c := f.Category
		if c == "" {
			if m, ok := analyzer.RuleMetadata(f.Rule); ok {
				c = m.Category
			} else if f.Rule == "" {
				c = "INTEGRITY"
			} else {
				c = "OTHER"
			}
		}
		counts[c]++
	}
	parts := make([]string, 0, len(order)+1)
	for _, c := range order {
		if counts[c] > 0 {
			parts = append(parts, fmt.Sprintf("%s: %d", c, counts[c]))
			delete(counts, c)
		}
	}
	var rest []string
	for c := range counts {
		rest = append(rest, c)
	}
	sort.Strings(rest)
	for _, c := range rest {
		parts = append(parts, fmt.Sprintf("%s: %d", c, counts[c]))
	}
	if len(parts) == 0 {
		return "Categories: none"
	}
	return "Categories: " + strings.Join(parts, "  ")
}

func joinOr(items []string, fallback string) string {
	if len(items) == 0 {
		return fallback
	}
	return strings.Join(items, ", ")
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
