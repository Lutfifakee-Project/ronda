package laravel

import (
	"os"
	"path/filepath"
	"strings"
)

// envMaxBytes bounds .env reads. The file is inspected for key names only;
// values are never copied anywhere.
const envMaxBytes = 1 << 20

// sensitivePublicNames are project files that must never be reachable from
// the public document root. Laravel's deployment guidance warns that the
// public directory is the only area a web server should serve.
var sensitivePublicNames = []string{
	".env",
	"composer.json",
	"composer.lock",
	"artisan",
	"package.json",
	"phpunit.xml",
	".gitattributes",
}

// runStructuralChecks performs the static deployment checks. It never reads
// secret values: .env is scanned for key names only and any evidence is
// redacted to key name and line number.
func runStructuralChecks(root string) []Check {
	checks := make([]Check, 0, 8)

	publicDir := filepath.Join(root, "public")
	if st, err := os.Stat(publicDir); err == nil && st.IsDir() {
		checks = append(checks, publicExposureChecks(root, publicDir)...)
	} else {
		checks = append(checks, Check{
			Name:   "public directory",
			Status: "INFO",
			Detail: "no public directory found; serving layout is custom and was not judged",
			Path:   publicDir,
		})
	}

	checks = append(checks, envFileChecks(root)...)
	checks = append(checks, writableDirChecks(root)...)
	return checks
}

// publicExposureChecks reports sensitive project files placed inside public/.
func publicExposureChecks(root, publicDir string) []Check {
	var checks []Check
	for _, name := range sensitivePublicNames {
		p := filepath.Join(publicDir, name)
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		checks = append(checks, Check{
			Name:     "sensitive file in public directory",
			Status:   "HIGH",
			Detail:   name + " is inside the public directory; Laravel's deployment guidance serves only public/ from the web server, so this file may be directly downloadable",
			Path:     p,
			Evidence: "file present: " + name,
		})
	}
	// A .git directory under public/ exposes the full source history.
	gitDir := filepath.Join(publicDir, ".git")
	if st, err := os.Stat(gitDir); err == nil && st.IsDir() {
		checks = append(checks, Check{
			Name:     "repository history in public directory",
			Status:   "HIGH",
			Detail:   "a .git directory is reachable from the public document root and may expose the complete source code and history",
			Path:     gitDir,
			Evidence: "directory present: .git",
		})
	}
	return checks
}

// envFileChecks inspects the .env file's permissions and, in strictly
// redacted form, whether debug mode is enabled.
func envFileChecks(root string) []Check {
	var checks []Check
	envPath := filepath.Join(root, ".env")
	st, err := os.Stat(envPath)
	if err != nil {
		return checks
	}

	// World-readable environment files leak every secret they contain.
	if st.Mode().Perm()&0o004 != 0 {
		checks = append(checks, Check{
			Name:     "environment file world-readable",
			Status:   "MEDIUM",
			Detail:   ".env is readable by other users on this system; it typically contains database credentials and the application key (values are never read by RONDA)",
			Path:     envPath,
			Evidence: "mode " + st.Mode().Perm().String(),
		})
	}

	// Debug mode indicator: only the key name is reported.
	if line, enabled := debugEnabled(envPath); enabled {
		c := Check{
			Name:     "debug mode enabled",
			Status:   "LOW",
			Detail:   "the environment file enables application debug mode; detailed error pages can disclose configuration and source paths (key name reported, value not shown)",
			Path:     envPath,
			Line:     line,
			Evidence: "APP_DEBUG=<redacted>",
		}
		checks = append(checks, c)
	}
	return checks
}

// debugEnabled scans .env for an enabling APP_DEBUG value and returns the
// line number. The value itself is never stored or reported.
func debugEnabled(path string) (int, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	if len(data) > envMaxBytes {
		data = data[:envMaxBytes]
	}
	line := 0
	for _, raw := range strings.Split(string(data), "\n") {
		line++
		l := strings.TrimSpace(raw)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		eq := strings.IndexByte(l, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(l[:eq])
		if key != "APP_DEBUG" {
			continue
		}
		val := strings.ToLower(strings.Trim(strings.TrimSpace(l[eq+1:]), `"'`))
		switch val {
		case "true", "1", "yes", "on":
			return line, true
		default:
			return line, false
		}
	}
	return 0, false
}

// writableDirChecks reports world-writable runtime directories, a common
// hygiene problem on shared hosts.
func writableDirChecks(root string) []Check {
	var checks []Check
	for _, rel := range []string{"storage", "bootstrap/cache"} {
		p := filepath.Join(root, rel)
		st, err := os.Stat(p)
		if err != nil || !st.IsDir() {
			continue
		}
		if st.Mode().Perm()&0o002 != 0 {
			checks = append(checks, Check{
				Name:     "world-writable directory",
				Status:   "LOW",
				Detail:   rel + " is writable by every user on this system; on shared hosts this allows other accounts to plant files the application may serve or include",
				Path:     p,
				Evidence: "mode " + st.Mode().Perm().String(),
			})
		}
	}
	return checks
}
