package kernel

import "strings"

// FlavorFromRelease derives the kernel flavor from a uname-style release
// string ("6.8.0-40-generic" -> "generic", "5.14.0-427.13.1.el9_4.x86_64"
// -> "", "6.6.2-arch1-1" -> ""). Only well-known flavor tokens are
// reported; everything else stays empty rather than guessing.
func FlavorFromRelease(release string) string {
	switch {
	case release == "":
		return ""
	case strings.Contains(release, "-rt"):
		return "rt"
	}
	// Check the tokens of the release suffix.
	for _, token := range strings.Split(release, "-") {
		switch token {
		case "generic", "lowlatency", "cloud", "aws", "azure", "gcp", "gke",
			"oracle", "kvm", "raspi", "lts", "virt", "edge", "hardened",
			"zen", "default", "rt":
			return token
		case "rt-amd64", "rt-arm64", "rt-i386":
			return "rt"
		}
	}
	// Ubuntu HWE kernels: ...-generic-hwe-24.04 or ...-lowlatency-hwe-22.04.
	if strings.Contains(release, "generic-hwe") {
		return "generic-hwe"
	}
	if strings.Contains(release, "lowlatency-hwe") {
		return "lowlatency-hwe"
	}
	// Debian rt flavor appears as "...-rt-<arch>" handled above; Arch flavor
	// suffixes (arch1, zen1, hardened1) are the package flavor already.
	if strings.Contains(release, "arch") {
		return "default"
	}
	if strings.Contains(release, "zen") {
		return "zen"
	}
	if strings.Contains(release, "hardened") {
		return "hardened"
	}
	return ""
}

// FlavorFromDpkgName classifies Debian/Ubuntu kernel package names into the
// flavor vocabulary used by vendor advisories.
func FlavorFromDpkgName(name string) string {
	switch {
	case strings.Contains(name, "generic-hwe"):
		return "generic-hwe"
	case strings.Contains(name, "lowlatency-hwe"):
		return "lowlatency-hwe"
	case strings.Contains(name, "-lowlatency"):
		return "lowlatency"
	case strings.Contains(name, "-rt"):
		return "rt"
	case strings.Contains(name, "-cloud"):
		return "cloud"
	case strings.Contains(name, "-aws"):
		return "aws"
	case strings.Contains(name, "-azure"):
		return "azure"
	case strings.Contains(name, "-gcp"):
		return "gcp"
	case strings.Contains(name, "-gke"):
		return "gke"
	case strings.Contains(name, "-oracle"):
		return "oracle"
	case strings.Contains(name, "-kvm"):
		return "kvm"
	case strings.Contains(name, "-raspi"):
		return "raspi"
	case strings.Contains(name, "generic"):
		return "generic"
	}
	return ""
}
