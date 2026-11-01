package persistence

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// traitRules maps the shared command traits onto the rule IDs of the
// mechanism that found the command. Every mechanism passes its own rule set
// so rule IDs and categories stay stable and registry-verified.
type traitRules struct {
	Writable     string // rule for payload in writable/temp path
	Hidden       string // rule for hidden payload path
	DownloadExec string // rule for fetch-then-execute chains
	EncodedExec  string // rule for decode-then-execute chains
	Reverse      string // rule for reverse-shell one-liners
	Missing      string // rule for a missing primary target
}

// expandHome maps "~/" and "$HOME/" prefixed tokens onto a concrete logical
// path using the given account home, or "" when the user is unknown.
func expandHome(tok string, home string) string {
	if home == "" {
		return ""
	}
	switch {
	case strings.HasPrefix(tok, "~/"):
		return filepath.Clean("/" + home + "/" + strings.TrimPrefix(tok, "~/"))
	case strings.HasPrefix(tok, "$HOME/"):
		return filepath.Clean("/" + home + "/" + strings.TrimPrefix(tok, "$HOME/"))
	}
	return ""
}

// classifyLocation categorizes a referenced path for trait decisions:
// "temp" (writable-by-design location), "hidden", "home", "writabledir"
// (world-writable parent directory found on disk) or "".
func (e *Engine) classifyLocation(logical string) string {
	if isTempPath(logical) {
		return "temp"
	}
	if isHiddenPath(logical) {
		return "hidden"
	}
	if strings.HasPrefix(logical, "/home/") || strings.HasPrefix(logical, "/root/") {
		return "home"
	}
	ti := e.InspectTarget(logical)
	if ti.DirWorldWrit {
		return "writabledir"
	}
	return ""
}

// traitsMatched reports whether any actionable trait was present.
func traitsMatched(t CommandTraits) bool {
	if t.ReverseShell {
		return true
	}
	if len(t.WritablePaths) > 0 || len(t.HiddenPaths) > 0 {
		return true
	}
	if t.Downloads && (t.PipeIntoExec || t.ChainedExec) {
		return true
	}
	if t.Encoded && t.PipeIntoExec {
		return true
	}
	return false
}

// reportCommandTraits inspects the target paths a command references,
// records cross-artifact references and emits the trait findings the
// mechanism's rules define. It returns the traits and whether any
// actionable trait matched.
//
// Severity policy (Phase 5 §17): location alone never proves malware; the
// rules report strongly suspicious execution PATHS, chains and encodings,
// and the evidence carries the redacted command so a reviewer can decide.
func (e *Engine) reportCommandTraits(traits CommandTraits, rules traitRules, artifact string, line int, affectedUser string, home string, execTarget string, kind string) (CommandTraits, bool) {
	evidence := traits.Raw
	if evidence == "" {
		evidence = "(command not printable)"
	}

	mk := func(rule string, sev finding.Severity, conf string) finding.Finding {
		f := finding.Finding{
			Status:     finding.Suspicious,
			Severity:   sev,
			Title:      ruleTitle(rule),
			Path:       artifact,
			Line:       line,
			Rule:       rule,
			Evidence:   evidence,
			Confidence: conf,
			User:       affectedUser,
			Kind:       kind,
		}
		if m, ok := RuleMetadata(rule); ok {
			f.Category = m.Category
			f.MITRE = m.MITRE
		}
		return f
	}

	// Inspect and reference every absolute or home-relative path.
	var primary *TargetInfo
	execPrimary := false // primary came from the execution target, not a bare path mention
	if execTarget != "" {
		execPrimary = true
		logical := execTarget
		if !strings.HasPrefix(logical, "/") {
			logical = expandHome(logical, home)
		}
		if logical != "" {
			primary = e.InspectTarget(logical)
			execPrimary = true
			e.reference(logical, rules.mechanism(), artifact, line, rules.Writable, false)
		}
	}
	for _, p := range traits.Paths {
		logical := p
		if !strings.HasPrefix(logical, "/") {
			logical = expandHome(logical, home)
		}
		if logical == "" {
			continue
		}
		ti := e.InspectTarget(logical)
		suspicious := isTempPath(logical) || isHiddenPath(logical)
		e.reference(logical, rules.mechanism(), artifact, line, rules.Writable, suspicious)
		if primary == nil {
			primary = ti
		}
	}

	matched := false

	// Primary target missing: weak indicator, still recorded.
	if primary != nil && !primary.Exists && primary.Accessible && rules.Missing != "" && execTarget != "" {
		f := mk(rules.Missing, finding.Low, finding.ConfidencePossible)
		f.Evidence = fmt.Sprintf("referenced target %s does not exist or cannot be inspected", primary.LogicalPath)
		e.add(f)
		matched = true
	}

	// Reverse shell: no legitimate startup or service needs it.
	if traits.ReverseShell && rules.Reverse != "" {
		e.add(mk(rules.Reverse, finding.Critical, finding.ConfidenceEstablished))
		matched = true
		return traits, matched
	}

	// Writable or hidden payload paths. The two primitives are reported
	// independently: a payload can be both concealed (dot-prefixed) and
	// placed in a writable-by-design location, and each fact is its own
	// evidence for reviewers. Mechanisms whose rule IDs merge both traits
	// into one rule skip the duplicate emission below.
	writableFired := false
	writableTarget := ""
	if len(traits.WritablePaths) > 0 && rules.Writable != "" {
		// Precision policy: HIGH requires the writable path to be the
		// execution target or a payload write target. A bare mention
		// (conditional tests, cat, echo) stays LOW context: location alone
		// never proves execution.
		first := expandHome(traits.WritablePaths[0], home)
		if first == "" {
			first = traits.WritablePaths[0]
		}
		execOrWrite := execPrimary && primary != nil && primary.LogicalPath == first
		if !execOrWrite {
			for _, w := range traits.Writes {
				we := expandHome(w, home)
				if we == "" {
					we = w
				}
				if we == first {
					execOrWrite = true
					break
				}
			}
		}
		sev := finding.Low
		if execOrWrite {
			sev = finding.High
		}
		f := mk(rules.Writable, sev, finding.ConfidencePossible)
		f.Target = first
		if ti := e.targets[f.Target]; ti != nil {
			f.Trust = ti.Trust
		}
		e.add(f)
		writableFired = true
		writableTarget = f.Target
		matched = true
	}
	if len(traits.HiddenPaths) > 0 && rules.Hidden != "" {
		hiddenTarget := expandHome(traits.HiddenPaths[0], home)
		if hiddenTarget == "" {
			hiddenTarget = traits.HiddenPaths[0]
		}
		if !(writableFired && rules.Writable == rules.Hidden && hiddenTarget == writableTarget) {
			f := mk(rules.Hidden, finding.Medium, finding.ConfidencePossible)
			f.Target = hiddenTarget
			e.add(f)
			matched = true
		}
	}

	// Execution from a world-writable directory: an unprivileged user can
	// replace the payload. Reported for the primary inspectable target
	// only, and never for package-owned files, to stay conservative.
	if !writableFired && execPrimary && primary != nil && primary.Exists && primary.DirWorldWrit &&
		primary.Trust != TrustPackageOwned && rules.Writable != "" {
		f := mk(rules.Writable, finding.High, finding.ConfidencePossible)
		f.Target = primary.LogicalPath
		f.Trust = primary.Trust
		f.Evidence += " (directory writable by unprivileged users)"
		e.add(f)
		matched = true
	}

	// Download-then-execute chains.
	if traits.Downloads && (traits.PipeIntoExec || traits.ChainedExec) && rules.DownloadExec != "" {
		e.add(mk(rules.DownloadExec, finding.High, finding.ConfidenceEstablished))
		matched = true
	}

	// Record write targets for cross-artifact write-then-exec correlation
	// (Phase 5 §4). A write alone is never a finding; the reference only
	// lets correlate() link a writing artifact to an executing one.
	for _, w := range traits.Writes {
		logical := w
		if !strings.HasPrefix(logical, "/") {
			logical = expandHome(logical, home)
		}
		if logical == "" {
			continue
		}
		e.reference(logical, rules.mechanism(), artifact, line, rules.Writable,
			isTempPath(logical) || isHiddenPath(logical))
	}

	// Decode-then-execute chains: a decode feeding an interpreter.
	if traits.Encoded && traits.PipeIntoExec && rules.EncodedExec != "" {
		e.add(mk(rules.EncodedExec, finding.High, finding.ConfidenceEstablished))
		matched = true
	}

	return traits, matched
}

// ruleTitle resolves the human name for a rule ID with a registry fallback.
func ruleTitle(rule string) string {
	if m, ok := RuleMetadata(rule); ok {
		return m.Name
	}
	return rule
}

// mechanism derives the artifact family from the writable-path rule ID so
// cross-artifact references record the right mechanism without each
// analyzer passing another string.
func (r traitRules) mechanism() string {
	switch {
	case strings.HasPrefix(r.Writable, "systemd-"):
		return "systemd"
	case strings.HasPrefix(r.Writable, "cron-"), strings.HasPrefix(r.Writable, "at-"):
		return "cron"
	case strings.HasPrefix(r.Writable, "ssh-"):
		return "ssh"
	case strings.HasPrefix(r.Writable, "shell-"):
		return "shell"
	case strings.HasPrefix(r.Writable, "ldso-"):
		return "ldso"
	case strings.HasPrefix(r.Writable, "pam-"):
		return "pam"
	case strings.HasPrefix(r.Writable, "kmod-"):
		return "kmod"
	case strings.HasPrefix(r.Writable, "udev-"):
		return "udev"
	}
	return "other"
}
