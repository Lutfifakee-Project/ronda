package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
	"github.com/Lutfifakee-Project/ronda/internal/scanner"
)

// Phase 3.2 classification metadata must be consistent across all three
// report formats: the JSON carries rule ids and line numbers, and the new
// classification titles reach terminal and HTML unchanged.

func classificationFixture() scanner.Result {
	var res scanner.Result
	res.Findings = []finding.Finding{
		{
			Status:   finding.Suspicious,
			Severity: finding.Low,
			Title:    "PHP file contains embedded binary data",
			Platform: "php",
			Path:     "/srv/joomla/libraries/vendor/symfony/polyfill-iconv/Resources/charset/from.cp037.php",
			Line:     4,
			Rule:     "php-embedded-binary",
			Evidence: "2 nul bytes inside string literals or comments, 0 in code position",
		},
		{
			Status:   finding.Suspicious,
			Severity: finding.Medium,
			Title:    "Suspicious PHP code",
			Platform: "php",
			Path:     "/srv/joomla/libraries/vendor/symfony/console/Application.php",
			Line:     1022,
			Rule:     "php-signals",
			Evidence: "shell_exec: operating-system command execution",
		},
	}
	return res
}

func TestClassificationMetadataInJSON(t *testing.T) {
	data, err := renderJSON(classificationFixture())
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Findings []map[string]interface{} `json:"findings"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Findings) != 2 {
		t.Fatalf("findings=%d", len(parsed.Findings))
	}
	first := parsed.Findings[0]
	if first["rule"] != "php-embedded-binary" {
		t.Fatalf("rule=%v", first["rule"])
	}
	if ln, ok := first["line"].(float64); !ok || int(ln) != 4 {
		t.Fatalf("line=%v", first["line"])
	}
	second := parsed.Findings[1]
	if second["rule"] != "php-signals" || second["line"].(float64) != 1022 {
		t.Fatalf("second metadata wrong: %v / %v", second["rule"], second["line"])
	}
}

func TestClassificationTitlesInTerminalAndHTML(t *testing.T) {
	res := classificationFixture()

	term := renderTerminal(res)
	if !strings.Contains(term, "PHP file contains embedded binary data") {
		t.Fatalf("terminal missing embedded-binary title:\n%s", term)
	}
	if !strings.Contains(term, "Suspicious PHP code") {
		t.Fatalf("terminal missing aggregate title")
	}

	page := renderHTML(res)
	if !strings.Contains(page, "PHP file contains embedded binary data") {
		t.Fatalf("HTML missing embedded-binary title")
	}
	if !strings.Contains(page, "from.cp037.php") {
		t.Fatalf("HTML missing table path")
	}
}

// TestPhase4FieldsSurfaceInReports proves the JSON report carries the
// Phase 4 per-finding fields and the terminal output shows the category
// breakdown and the absence-of-evidence disclaimer.
func TestPhase4FieldsSurfaceInReports(t *testing.T) {
	res := scanner.Result{
		Target:       "/tmp/target",
		RulesVersion: "builtin-3",
		Findings: []finding.Finding{
			{
				Status:     finding.Suspicious,
				Severity:   finding.Critical,
				Title:      "Request-controlled shell command execution",
				Path:       "/tmp/target/shell.php",
				Line:       3,
				Rule:       "php-source-to-shell",
				Evidence:   "system() receives request-controlled input",
				Confidence: "established",
				Category:   "COMMAND_EXECUTION",
				Signals: []finding.Signal{
					{Rule: "source", Line: 2, Detail: "request input $_GET"},
					{Rule: "sink", Line: 3, Detail: "system() executes the command"},
				},
			},
		},
	}

	var jsonBuf bytes.Buffer
	if err := Write(&jsonBuf, res, Options{Format: "json"}); err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		RulesVersion string `json:"rules_version"`
		Findings     []struct {
			Rule       string `json:"rule"`
			Line       int    `json:"line"`
			Category   string `json:"category"`
			Confidence string `json:"confidence"`
			Signals    []struct {
				Signal string `json:"signal"`
				Line   int    `json:"line"`
				Detail string `json:"detail"`
			} `json:"signals"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(jsonBuf.Bytes(), &parsed); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if parsed.RulesVersion != "builtin-3" {
		t.Fatalf("rules_version=%q", parsed.RulesVersion)
	}
	if len(parsed.Findings) != 1 {
		t.Fatalf("findings=%d", len(parsed.Findings))
	}
	f := parsed.Findings[0]
	if f.Rule != "php-source-to-shell" || f.Line != 3 || f.Category != "COMMAND_EXECUTION" || f.Confidence != "established" {
		t.Fatalf("phase4 fields incomplete: %+v", f)
	}
	if len(f.Signals) != 2 || f.Signals[0].Signal != "source" || f.Signals[0].Line != 2 {
		t.Fatalf("signals incomplete: %+v", f.Signals)
	}

	var termBuf bytes.Buffer
	if err := Write(&termBuf, res, Options{Format: "terminal"}); err != nil {
		t.Fatal(err)
	}
	term := termBuf.String()
	for _, want := range []string{
		"rule: php-source-to-shell (COMMAND_EXECUTION)",
		"line: 3",
		"confidence: established",
		"Categories:",
		"COMMAND_EXECUTION: 1",
		"Absence of findings is not proof of absence of compromise",
		"- source line 2: request input $_GET",
	} {
		if !strings.Contains(term, want) {
			t.Errorf("terminal output missing %q", want)
		}
	}

	var htmlBuf bytes.Buffer
	if err := Write(&htmlBuf, res, Options{Format: "html"}); err != nil {
		t.Fatal(err)
	}
	h := htmlBuf.String()
	for _, want := range []string{"php-source-to-shell", "Confidence", "Absence of findings is not proof of absence of compromise"} {
		if !strings.Contains(h, want) {
			t.Errorf("html output missing %q", want)
		}
	}
}

// TestBackwardCompatibleJSONOmitsEmptyPhase4Fields: findings without the
// Phase 4 fields keep the old JSON shape (no empty category/confidence
// keys, no signals array).
func TestBackwardCompatibleJSONOmitsEmptyPhase4Fields(t *testing.T) {
	res := scanner.Result{
		Target: "/tmp/target",
		Findings: []finding.Finding{
			{Status: finding.Clean, Severity: finding.Info, Title: "Core integrity verified"},
		},
	}
	var buf bytes.Buffer
	if err := Write(&buf, res, Options{Format: "json"}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, banned := range []string{`"category": ""`, `"confidence": ""`, `"signals": []`} {
		if strings.Contains(out, banned) {
			t.Errorf("backward compatibility broken, found %s", banned)
		}
	}
	if !strings.Contains(out, `"status": "CLEAN"`) {
		t.Errorf("old fields must survive: %s", out)
	}
}
