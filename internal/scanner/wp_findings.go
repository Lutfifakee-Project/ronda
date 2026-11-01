package scanner

import (
	"fmt"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/wordpress"
)

// wpFindings converts one WordPress verification result into a small, bounded
// set of findings. Per-file detail lives in the structured WordPress result
// (JSON/HTML) so a real server with thousands of core files does not produce
// thousands of terminal findings.
func wpFindings(wp wordpress.Result) []finding.Finding {
	if !wp.Verified {
		return []finding.Finding{{
			Status:   finding.Unverified,
			Severity: finding.Info,
			Title:    "WordPress core integrity unverified",
			Platform: "wordpress",
			Path:     wp.Root,
			Evidence: wp.Reason,
		}}
	}

	var out []finding.Finding

	if len(wp.ModifiedFiles) > 0 {
		out = append(out, finding.Finding{
			Status:   finding.Modified,
			Severity: finding.High,
			Title:    fmt.Sprintf("WordPress core files modified: %d", len(wp.ModifiedFiles)),
			Platform: "wordpress",
			Path:     wp.Root,
			Evidence: summarizeCoreFiles(wp.ModifiedFiles),
		})
	}

	if len(wp.MissingFiles) > 0 {
		out = append(out, finding.Finding{
			Status:   finding.Missing,
			Severity: finding.Medium,
			Title:    fmt.Sprintf("WordPress core files missing: %d", len(wp.MissingFiles)),
			Platform: "wordpress",
			Path:     wp.Root,
			Evidence: summarizeCorePaths(wp.MissingFiles),
		})
	}

	if len(wp.ExtraFiles) > 0 {
		out = append(out, finding.Finding{
			Status:   finding.Extra,
			Severity: finding.Low,
			Title:    fmt.Sprintf("Unexpected files in WordPress core directories: %d", len(wp.ExtraFiles)),
			Platform: "wordpress",
			Path:     wp.Root,
			Evidence: summarizeStrings(wp.ExtraFiles),
		})
	}

	if len(wp.RootExtraFiles) > 0 {
		out = append(out, finding.Finding{
			Status:   finding.Extra,
			Severity: finding.Info,
			Title:    fmt.Sprintf("Unexpected files in WordPress root (informational): %d", len(wp.RootExtraFiles)),
			Platform: "wordpress",
			Path:     wp.Root,
			Evidence: summarizeStrings(wp.RootExtraFiles),
		})
	}

	return out
}

const maxEvidenceItems = 5

func summarizeCoreFiles(items []wordpress.CoreFile) string {
	paths := make([]string, 0, len(items))
	for i := 0; i < len(items); i++ {
		paths = append(paths, items[i].Path)
	}
	return summarizeStrings(paths)
}

func summarizeCorePaths(items []wordpress.CoreFile) string {
	paths := make([]string, 0, len(items))
	for i := 0; i < len(items); i++ {
		paths = append(paths, items[i].Path)
	}
	return summarizeStrings(paths)
}

func summarizeStrings(items []string) string {
	if len(items) <= maxEvidenceItems {
		return joinComma(items)
	}
	head := joinComma(items[:maxEvidenceItems])
	return fmt.Sprintf("%s (+%d more)", head, len(items)-maxEvidenceItems)
}

func joinComma(items []string) string {
	out := ""
	for i := 0; i < len(items); i++ {
		if i > 0 {
			out += ", "
		}
		out += items[i]
	}
	return out
}
