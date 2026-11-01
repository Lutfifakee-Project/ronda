package update

import (
	"strconv"
	"strings"
)

// CompareVersions compares two MAJOR.MINOR.PATCH version strings and returns
// -1 when a < b, 0 when a == b and 1 when a > b. Missing components count as
// zero and a leading "v" is ignored. Non-numeric components make the result
// conservative: they are treated as zero, so a pre-release string like
// "0.2.0-rc1" compares equal to "0.2.0" and never above it.
func CompareVersions(a, b string) int {
	x := splitVersion(a)
	y := splitVersion(b)
	for i := 0; i < 3; i++ {
		if x[i] < y[i] {
			return -1
		}
		if x[i] > y[i] {
			return 1
		}
	}
	return 0
}

// splitVersion parses the first three numeric components of v.
func splitVersion(v string) [3]int {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	for i := 0; i < 3 && i < len(parts); i++ {
		n, err := strconv.Atoi(strings.TrimSpace(parts[i]))
		if err != nil {
			// Keep the leading numeric prefix when present ("91-rc1" -> 91).
			n = leadingInt(parts[i])
		}
		out[i] = n
	}
	return out
}

// leadingInt parses digits from the start of s, returning 0 when there are
// none.
func leadingInt(s string) int {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil {
		return 0
	}
	return n
}

// ErrAlreadyUpToDate and friends are sentinel errors reported by Perform.
type sentinel string

func (e sentinel) Error() string { return string(e) }

const (
	// ErrAlreadyUpToDate reports that the installed version already matches
	// the requested target version.
	ErrAlreadyUpToDate sentinel = "already at the requested version"

	// ErrDowngrade reports that the requested target version is older than
	// the installed version. RONDA never self-downgrades.
	ErrDowngrade sentinel = "refused downgrade"
)
