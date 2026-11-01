package persistence

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// correlation limits keep the pass bounded no matter how many references a
// hostile root produces.
const (
	maxCorrelationGroups = 256
	maxRefsPerGroup      = 64
	minMechanisms        = 2
)

// analyzeTargets emits target-level findings (writable directory, hidden
// name, unowned executable) once provenance is known. These are context
// findings: location and ownership alone never become a malware verdict.
func (e *Engine) analyzeTargets() {
	// Only targets referenced by at least one artifact participate.
	referenced := make(map[string]bool, len(e.refs))
	for _, r := range e.refs {
		referenced[r.Target] = true
	}
	for logical, ti := range e.targets {
		if e.canceled() {
			return
		}
		if !referenced[logical] || !ti.Exists {
			continue
		}
		isExec := ti.Kind == "elf" || ti.Kind == "script" || strings.HasSuffix(logical, ".sh")
		if !isExec {
			continue
		}

		if ti.DirWorldWrit && ti.Trust != TrustPackageOwned {
			f := e.baseFinding("target-in-writable-dir", finding.Medium, ti.LogicalPath)
			f.Evidence = fmt.Sprintf("executable %s referenced by persistence artifacts sits in a world-writable directory (%s)", logical, ti.Mode)
			f.Target = logical
			f.Trust = ti.Trust
			f.Kind = "target"
			e.add(f)
		}
		if ti.Hidden && !strings.HasPrefix(logical, "/tmp/") && ti.Trust != TrustPackageOwned {
			f := e.baseFinding("target-hidden", finding.Info, ti.LogicalPath)
			f.Evidence = "referenced executable " + logical + " has a dot-prefixed name (context, not a verdict)"
			f.Target = logical
			f.Trust = ti.Trust
			f.Kind = "target"
			e.add(f)
		}
		if ti.Trust == TrustUnowned && e.packageDB == "dpkg" || ti.Trust == TrustUnowned && e.packageDB == "apk" {
			f := e.baseFinding("target-unowned-executable", finding.Info, ti.LogicalPath)
			f.Evidence = "no package claims referenced executable " + logical + " (locally deployed tools are unowned by nature)"
			f.Target = logical
			f.Trust = ti.Trust
			f.Kind = "target"
			e.add(f)
		}
	}
}

// correlate groups references by target path and by target hash and emits
// one finding per group when at least two INDEPENDENT mechanisms point at
// the same payload. Static correlation is recorded as evidence of
// configuration relationships, never as proof of execution.
func (e *Engine) correlate() {
	if len(e.refs) == 0 {
		return
	}

	// Group by target path.
	byPath := make(map[string][]targetRef, len(e.refs)/2+1)
	for _, r := range e.refs {
		byPath[r.Target] = append(byPath[r.Target], r)
	}

	targets := make([]string, 0, len(byPath))
	for t := range byPath {
		targets = append(targets, t)
	}
	sort.Strings(targets)

	emitted := 0
	for _, target := range targets {
		if emitted >= maxCorrelationGroups {
			e.note(fmt.Sprintf("correlation capped at %d groups; remaining references are recorded individually", maxCorrelationGroups))
			break
		}
		refs := byPath[target]
		if len(refs) < minMechanisms {
			continue
		}
		// Devices, pseudo-filesystem locations and directories are not
		// payloads; references to them (>/dev/null, /run checks) never
		// correlate.
		if !corrTargetEligible(target, e.targets[target]) {
			continue
		}
		mechs := independentMechanisms(refs)
		if len(mechs) < minMechanisms {
			continue
		}
		// Package-owned targets referenced by several mechanisms are
		// distribution tooling: quiet unless a reference is suspicious.
		ti := e.targets[target]
		owned := ti != nil && ti.Trust == TrustPackageOwned
		anySuspicious := false
		for _, r := range refs {
			if r.Suspicious {
				anySuspicious = true
				break
			}
		}
		if owned && !anySuspicious {
			continue
		}
		// Escalate to HIGH only when the shared relationship is itself
		// suspicious (a reference flagged a hidden or writable
		// location, or the target is hidden, temporary or sits in a
		// world-writable directory). An ordinary locally deployed tool
		// referenced by two schedulers stays MEDIUM: the relationship
		// is always reported, only the verdict strength varies.
		sev := e.correlationSeverity(target, refs)

		e.emitCorrelation(target, refs, mechs, "correlation-shared-payload", sev)
		emitted++
	}

	// Group by SHA-256 across distinct targets (copies of one payload).
	e.correlateByHash()
}

// correlateByHash links distinct target paths that share one SHA-256.
func (e *Engine) correlateByHash() {
	type hashRef struct {
		hash  string
		paths map[string]bool
		refs  []targetRef
	}
	byHash := make(map[string]*hashRef)
	for _, r := range e.refs {
		ti := e.targets[r.Target]
		if ti == nil || ti.SHA256 == "" || !ti.Exists {
			continue
		}
		hr, ok := byHash[ti.SHA256]
		if !ok {
			hr = &hashRef{hash: ti.SHA256, paths: make(map[string]bool)}
			byHash[ti.SHA256] = hr
		}
		hr.paths[r.Target] = true
		hr.refs = append(hr.refs, r)
	}
	hashes := make([]string, 0, len(byHash))
	for h := range byHash {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)

	emitted := 0
	for _, h := range hashes {
		if emitted >= maxCorrelationGroups {
			return
		}
		hr := byHash[h]
		if len(hr.paths) < minMechanisms {
			continue
		}
		eligible := false
		for p := range hr.paths {
			if corrTargetEligible(p, e.targets[p]) {
				eligible = true
				break
			}
		}
		if !eligible {
			continue
		}
		mechs := independentMechanisms(hr.refs)
		if len(mechs) < minMechanisms {
			continue
		}
		owned := true
		anySuspicious := false
		for _, r := range hr.refs {
			if r.Suspicious {
				anySuspicious = true
				break
			}
		}
		for p := range hr.paths {
			if ti := e.targets[p]; ti != nil && ti.Trust != TrustPackageOwned {
				owned = false
				break
			}
		}
		if owned && !anySuspicious {
			continue
		}
		// Severity: the strongest grade among the shared targets.
		sev := finding.Medium
		for p := range hr.paths {
			if e.correlationSeverity(p, hr.refs) == finding.High {
				sev = finding.High
				break
			}
		}
		// Emit on the lexicographically first target path so the finding is
		// deterministic.
		paths := make([]string, 0, len(hr.paths))
		for p := range hr.paths {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		e.emitCorrelation(paths[0], hr.refs, mechs, "correlation-shared-hash", sev)
		emitted++
	}
}

// corrTargetEligible reports whether a referenced target can meaningfully
// be a shared payload: devices, /proc, /sys and directories are not.
func corrTargetEligible(target string, ti *TargetInfo) bool {
	if isPseudoDevice(target) {
		return false
	}
	if ti != nil && ti.IsDir {
		return false
	}
	return true
}

// independentMechanisms counts distinct artifact families among refs.
func independentMechanisms(refs []targetRef) []string {
	seen := make(map[string]bool, len(refs))
	out := make([]string, 0, 8)
	for _, r := range refs {
		if !seen[r.Mechanism] {
			seen[r.Mechanism] = true
			out = append(out, r.Mechanism)
		}
	}
	sort.Strings(out)
	return out
}

// correlationSeverity grades one correlation group: HIGH when a referring
// line was flagged suspicious, or the shared target is hidden, temporary
// or sits in a world-writable directory; MEDIUM otherwise. The finding is
// always emitted — severity expresses how strongly the relationship reads
// as staging, never whether it exists.
func (e *Engine) correlationSeverity(target string, refs []targetRef) finding.Severity {
	for _, r := range refs {
		if r.Suspicious {
			return finding.High
		}
	}
	if ti := e.targets[target]; ti != nil {
		if ti.Hidden || isTempPath(target) || ti.DirWorldWrit {
			return finding.High
		}
	}
	return finding.Medium
}

// emitCorrelation adds one cross-artifact finding with the full evidence
// list of referring artifacts.
func (e *Engine) emitCorrelation(target string, refs []targetRef, mechs []string, rule string, sev finding.Severity) {
	if len(refs) > maxRefsPerGroup {
		refs = refs[:maxRefsPerGroup]
	}
	f := e.baseFinding(rule, sev, refs[0].Artifact)
	f.Target = target
	f.Kind = "correlation"
	ti := e.targets[target]
	if ti != nil {
		f.Trust = ti.Trust
		if ti.SHA256 != "" {
			f.Evidence = fmt.Sprintf("target %s (sha256 %s) is referenced by %d independent persistence mechanism(s): %s",
				target, shortHash(ti.SHA256), len(mechs), strings.Join(mechs, ", "))
		}
	}
	if f.Evidence == "" {
		f.Evidence = fmt.Sprintf("target %s is referenced by %d independent persistence mechanism(s): %s",
			target, len(mechs), strings.Join(mechs, ", "))
	}
	seenSig := make(map[string]bool, len(refs))
	for _, r := range refs {
		// One signal per referring location, however many rules fired on
		// that line: correlation evidence lists relationships, not noise.
		sigKey := r.Mechanism + "|" + r.Artifact + "|" + fmt.Sprint(r.Line)
		if seenSig[sigKey] {
			continue
		}
		seenSig[sigKey] = true
		loc := fmt.Sprintf("%s", r.Artifact)
		if r.Line > 0 {
			loc += fmt.Sprintf(":%d", r.Line)
		}
		f.Signals = append(f.Signals, finding.Signal{
			Rule:   r.Mechanism,
			Line:   r.Line,
			Detail: loc + " references " + target,
		})
	}
	e.add(f)
}
