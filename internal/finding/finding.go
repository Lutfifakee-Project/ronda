// Package finding defines the status, severity and structure of scan findings.
package finding

import "sort"

// Status describes what RONDA can prove about an item.
type Status string

const (
	// Clean means the item matches a trusted baseline or shows no indicator.
	Clean Status = "CLEAN"
	// Modified means the item differs from a trusted baseline.
	Modified Status = "MODIFIED"
	// Missing means an expected file is absent.
	Missing Status = "MISSING"
	// Extra means an unknown file exists outside the trusted inventory.
	Extra Status = "EXTRA"
	// Suspicious means suspicious code or behaviour indicators were found.
	Suspicious Status = "SUSPICIOUS"
	// Vulnerable means a vulnerability is supported by sufficient evidence.
	Vulnerable Status = "VULNERABLE"
	// Unverified means no suitable trusted baseline was available.
	Unverified Status = "UNVERIFIED"
)

// Severity expresses how urgent a finding is.
type Severity string

const (
	// Critical findings usually mean active compromise.
	Critical Severity = "CRITICAL"
	// High findings indicate a strong indicator of compromise or exposure.
	High Severity = "HIGH"
	// Medium findings need review but may be legitimate.
	Medium Severity = "MEDIUM"
	// Low findings are weak indicators or hygiene problems.
	Low Severity = "LOW"
	// Info findings are informational notes.
	Info Severity = "INFO"
)

// Severities lists every severity from most to least urgent.
var Severities = []Severity{Critical, High, Medium, Low, Info}

// Rank returns a sort weight; a higher rank means a more severe finding.
func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 5
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	case Info:
		return 1
	}
	return 0
}

// Finding is a single observation produced by a scanner module.
//
// The fields Confidence, Category and Signals were added in Phase 4. All
// three carry the omitempty JSON tag and every pre-existing field kept its
// exact JSON key, so reports produced by older consumers stay parseable:
// the new keys simply do not appear when a finding carries no such data.
type Finding struct {
	Status         Status   `json:"status"`
	Severity       Severity `json:"severity"`
	Title          string   `json:"title"`
	Platform       string   `json:"platform,omitempty"`
	Path           string   `json:"path,omitempty"`
	Line           int      `json:"line,omitempty"`
	Rule           string   `json:"rule,omitempty"`
	Evidence       string   `json:"evidence,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
	// Confidence states how strongly the evidence supports the verdict:
	// "established" for assignment-level flows proven inside one file,
	// "possible" when signals coexist but no flow was proven. Empty when
	// the finding does not carry a confidence assessment.
	Confidence string `json:"confidence,omitempty"`
	// Category groups the finding into the detection taxonomy
	// (WEBSHELL, COMMAND_EXECUTION, CODE_INJECTION, OBFUSCATION,
	// PAYLOAD_LOADER, FILE_DROPPER, DYNAMIC_EXECUTION,
	// POLYGLOT_OR_BINARY_ANOMALY, BROAD_SIGNAL, INTEGRITY).
	Category string `json:"category,omitempty"`
	// Signals lists the supporting evidence locations that contributed to
	// the finding. The primary Line stays the strongest evidence; Signals
	// preserve the remaining locations so no supporting evidence is lost.
	Signals []Signal `json:"signals,omitempty"`
	// MITRE lists ATT&CK technique identifiers mapped to this finding
	// (Phase 5, persistence rules). Empty when no mapping applies.
	MITRE []string `json:"mitre,omitempty"`
	// Target is the referenced executable, script or library the finding
	// points at, expressed as a path inside the scanned root.
	Target string `json:"target,omitempty"`
	// User is the affected account or service name, where known.
	User string `json:"user,omitempty"`
	// Owner is the artifact file owner (name when resolvable, uid
	// otherwise), recorded for persistence artifacts.
	Owner string `json:"owner,omitempty"`
	// Permissions is the artifact file mode in ls-style notation.
	Permissions string `json:"permissions,omitempty"`
	// Modified is the artifact modification time (RFC3339, UTC).
	Modified string `json:"modified,omitempty"`
	// Package names the OS package owning the artifact, when package
	// provenance was statically resolvable.
	Package string `json:"package,omitempty"`
	// Trust states the reference/integrity standing of the referenced
	// target: package-owned, package-owned-modified, unowned,
	// inaccessible, unverified. Empty when not assessed.
	Trust string `json:"trust,omitempty"`
	// Kind is the artifact class (unit, crontab, authorized-keys, shell-rc,
	// config, script, elf, library, rule, account-db).
	Kind string `json:"kind,omitempty"`
}

// Signal is one supporting evidence location inside a finding.
type Signal struct {
	// Rule names the signal or rule that produced this evidence.
	Rule string `json:"signal"`
	// Line is the 1-based source line of the evidence, 0 when unknown.
	Line int `json:"line,omitempty"`
	// Detail describes what the evidence shows.
	Detail string `json:"detail,omitempty"`
}

// Confidence values used by analyzers that support graded verdicts.
const (
	// ConfidenceEstablished means an intra-file data relationship was proven
	// at assignment level (source and sink connected through a variable).
	ConfidenceEstablished = "established"
	// ConfidencePossible means indicators coexist but no flow was proven.
	ConfidencePossible = "possible"
)

// Sort orders findings by severity (descending) and then by path.
func Sort(items []Finding) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Severity.Rank() != items[j].Severity.Rank() {
			return items[i].Severity.Rank() > items[j].Severity.Rank()
		}
		if items[i].Path != items[j].Path {
			return items[i].Path < items[j].Path
		}
		return items[i].Title < items[j].Title
	})
}

// CountBySeverity returns the number of findings per severity.
func CountBySeverity(items []Finding) map[Severity]int {
	out := make(map[Severity]int, len(Severities))
	for _, s := range Severities {
		out[s] = 0
	}
	for _, f := range items {
		out[f.Severity]++
	}
	return out
}
