package analyzer

import "github.com/Lutfifakee-Project/ronda/internal/finding"

// rules.go is the structured detection-rule registry introduced in Phase 4.
// Every rule ID RONDA emits (aggregated signals, backticks, binary
// classification and the correlation rules) resolves to a RuleMeta carrying
// a stable ID, a human name, a category, a description, the default severity
// and the false-positive considerations an operator needs when reviewing.
//
// Rules are individually testable: TestRuleRegistry in rules_test.go asserts
// completeness and stability of this table, and every emitter in the analyzer
// must use these exact IDs.

// Detection categories. Existing emitters map onto them without changing any
// historical rule ID.
const (
	CatWebshell         = "WEBSHELL"
	CatCommandExecution = "COMMAND_EXECUTION"
	CatCodeInjection    = "CODE_INJECTION"
	CatObfuscation      = "OBFUSCATION"
	CatPayloadLoader    = "PAYLOAD_LOADER"
	CatFileDropper      = "FILE_DROPPER"
	CatDynamicExecution = "DYNAMIC_EXECUTION"
	CatPolyglotOrBinary = "POLYGLOT_OR_BINARY_ANOMALY"
	CatBroadSignal      = "BROAD_SIGNAL"
	CatInformational    = "INFORMATIONAL"
	CatIntegrity        = "INTEGRITY"
)

// RuleMeta describes one detection rule.
type RuleMeta struct {
	ID string
	// Name is a short human-readable rule name.
	Name string
	// Category is one of the Cat* constants.
	Category string
	// Description explains what the rule detects.
	Description string
	// DefaultSeverity is the severity the rule alone can carry.
	DefaultSeverity finding.Severity
	// FPNotes lists the known legitimate patterns reviewers should weigh;
	// it documents precision decisions instead of hiding them.
	FPNotes string
}

// ruleRegistry holds the metadata of every rule RONDA emits. It must stay
// deterministic: entries are looked up by exact ID, never by pattern.
var ruleRegistry = map[string]RuleMeta{
	// Phase 3.x rules (IDs unchanged).
	"php-signals": {
		ID:              "php-signals",
		Name:            "Suspicious PHP signal aggregate",
		Category:        CatBroadSignal,
		Description:     "Aggregated suspicious PHP signals reaching the reporting threshold inside one file. Severity is evidence-derived (highest contributing signal); Medium is only the nominal default.",
		DefaultSeverity: finding.Medium,
		FPNotes:         "Single generic calls cannot reach the threshold alone; vendor libraries with real invocation evidence legitimately appear.",
	},
	"php-backtick": {
		ID:              "php-backtick",
		Name:            "PHP backtick shell execution",
		Category:        CatCommandExecution,
		Description:     "Backtick operator executed in PHP code position, classified by command content (static, interpolated, request-controlled).",
		DefaultSeverity: finding.High,
		FPNotes:         "Build or deploy scripts inside web roots are legitimate but still execute shell commands.",
	},
	"php-binary-data": {
		ID:              "php-binary-data",
		Name:            "PHP file contains binary data",
		Category:        CatPolyglotOrBinary,
		Description:     "NUL bytes in code position or inline HTML of a PHP file: malformed, truncated or deliberately obfuscated source.",
		DefaultSeverity: finding.High,
		FPNotes:         "Binary data alone is not malware; the readable PHP sections are still analyzed for behaviour.",
	},
	"php-embedded-binary": {
		ID:              "php-embedded-binary",
		Name:            "PHP file contains embedded binary data",
		Category:        CatPolyglotOrBinary,
		Description:     "NUL or non-text bytes inside string literals or comments (e.g. character-set tables). PHP sections remain analyzed.",
		DefaultSeverity: finding.Low,
		FPNotes:         "Legitimate Symfony/Laminas charset tables produce this; embedded data alone is not a malware indicator.",
	},
	"php-binary-resource": {
		ID:              "php-binary-resource",
		Name:            "Binary resource with PHP opening tag",
		Category:        CatPolyglotOrBinary,
		Description:     "File carries PHP opening tag bytes but no analyzable PHP structure; not parsed as PHP source.",
		DefaultSeverity: finding.Low,
		FPNotes:         "Classification is uncertain, not proven clean; reported as UNVERIFIED.",
	},
	"php-appended-binary": {
		ID:              "php-appended-binary",
		Name:            "PHP source with appended non-text data",
		Category:        CatPolyglotOrBinary,
		Description:     "Substantial non-text data outside the PHP regions (e.g. after the closing tag); polyglot indicator, file stays fully analyzed.",
		DefaultSeverity: finding.Low,
		FPNotes:         "Scattered legacy-encoding bytes stay below the 5%/16-byte threshold and never trigger this rule.",
	},

	// Phase 4 correlation rules.
	"php-source-to-shell": {
		ID:              "php-source-to-shell",
		Name:            "Request-controlled shell execution",
		Category:        CatCommandExecution,
		Description:     "Request input reaches a shell command sink (system, exec, shell_exec, passthru, proc_open, popen, backtick) through a proven intra-file assignment.",
		DefaultSeverity: finding.Critical,
		FPNotes:         "Requires an established variable flow, not a mere co-occurrence; CLI-only entry points still appear if the file reads request input.",
	},
	"php-source-to-code": {
		ID:              "php-source-to-code",
		Name:            "Request-controlled code execution",
		Category:        CatCodeInjection,
		Description:     "Request input reaches eval/assert(string)/create_function or controls a dynamic callable/include through a proven intra-file assignment.",
		DefaultSeverity: finding.Critical,
		FPNotes:         "Routing frameworks dispatch on request paths; only direct callable construction or include of request input qualifies.",
	},
	"php-decoder-exec": {
		ID:              "php-decoder-exec",
		Name:            "Decoded payload execution",
		Category:        CatObfuscation,
		Description:     "Output of base64_decode/gzinflate/gzuncompress/str_rot13/hex2bin/convert_uudecode reaches an execution sink through a proven intra-file assignment.",
		DefaultSeverity: finding.High,
		FPNotes:         "Decoding into a value that is only echoed, stored or compared is not execution; ordinary base64 usage never triggers this.",
	},
	"php-dynamic-call": {
		ID:              "php-dynamic-call",
		Name:            "Dynamic call resolving to dangerous function",
		Category:        CatDynamicExecution,
		Description:     "A variable function or call_user_func argument was assigned a dangerous function name literal (directly or reconstructed).",
		DefaultSeverity: finding.High,
		FPNotes:         "Benign dispatch tables use safe names; only dangerous-name resolution is reported.",
	},
	"php-dynamic-include": {
		ID:              "php-dynamic-include",
		Name:            "Dynamic include/require of variable path",
		Category:        CatDynamicExecution,
		Description:     "include/require of a variable path; severity follows context (request-controlled or decoder-derived: HIGH; plain variable: INFO).",
		DefaultSeverity: finding.Info,
		FPNotes:         "Template engines and theme loaders legitimately include variables; only request-controlled or decoder-derived paths reach HIGH.",
	},
	"php-remote-write": {
		ID:              "php-remote-write",
		Name:            "Remote content written to file",
		Category:        CatFileDropper,
		Description:     "Remote-fetched content flows into a file write through a proven intra-file assignment.",
		DefaultSeverity: finding.Medium,
		FPNotes:         "Update routines fetch packages, but they write archives and extract them; only fetched-content-to-write flows qualify.",
	},
	"php-write-exec": {
		ID:              "php-write-exec",
		Name:            "Written file subsequently executed",
		Category:        CatPayloadLoader,
		Description:     "Content written to a file is later included/executed through a proven intra-file assignment.",
		DefaultSeverity: finding.High,
		FPNotes:         "Cache/temp systems write and include files legitimately; cache paths and request-controlled payloads are distinguished in evidence.",
	},
	"php-webshell-chain": {
		ID:              "php-webshell-chain",
		Name:            "Webshell behavior chain",
		Category:        CatWebshell,
		Description:     "Three or more independent webshell indicators form a behavioral chain (request-controlled execution, output return, auth gating, obfuscation, file ops).",
		DefaultSeverity: finding.High,
		FPNotes:         "Individual indicators are normal; only the combination is reported, with every contributing indicator listed as evidence.",
	},
}

// RuleMetadata returns the registry entry for a rule ID. The second result is
// false for unknown IDs; callers must not invent metadata for unknown rules.
func RuleMetadata(id string) (RuleMeta, bool) {
	m, ok := ruleRegistry[id]
	return m, ok
}

// RuleIDs returns every registered rule ID in sorted order.
func RuleIDs() []string {
	ids := make([]string, 0, len(ruleRegistry))
	for id := range ruleRegistry {
		ids = append(ids, id)
	}
	sortStrings(ids)
	return ids
}

// sortStrings is a tiny insertion sort so this file needs no dependency on
// sort semantics beyond determinism.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
