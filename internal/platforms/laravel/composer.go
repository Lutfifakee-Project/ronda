package laravel

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// composerLockMaxBytes bounds metadata file reads.
const composerLockMaxBytes = 8 << 20

// lockedPackage is the subset of a composer.lock package entry RONDA reads.
type lockedPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  struct {
		Reference string `json:"reference"`
		URL       string `json:"url"`
	} `json:"source"`
	Dist struct {
		URL    string `json:"url"`
		Shasum string `json:"shasum"`
	} `json:"dist"`
}

// Verify returns the static Composer inventory for one Laravel project.
// It never executes Composer, never runs PHP and never contacts a package
// registry, even for URLs found in the lock file.
func inventory(root string) (Result, error) {
	res := Result{
		Root:            root,
		IntegrityStatus: IntegrityStatus,
		IntegrityReason: "composer.lock pins exact versions but does not authenticate installed files; RONDA has no independently authenticated package archive to compare against, and dist URLs inside the lock file are target-controlled metadata that is never fetched",
	}

	req, err := readComposerJSON(filepath.Join(root, "composer.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Notes = append(res.Notes, "composer.json unreadable: "+err.Error())
	}
	res.FrameworkRequired = req["laravel/framework"] != ""
	for name, constraint := range req {
		res.Require = append(res.Require, PackageInfo{Name: name, Version: constraint})
	}
	sortPackages(res.Require)

	lock, err := readComposerLock(filepath.Join(root, "composer.lock"))
	switch {
	case err == nil:
		res.PackagesLocked = len(lock.Packages) + len(lock.PackagesDev)
		for _, p := range append(append([]lockedPackage{}, lock.Packages...), lock.PackagesDev...) {
			if p.Name == "laravel/framework" {
				res.Version = p.Version
				res.VersionSource = "composer.lock"
				res.SourceRef = p.Source.Reference
				if p.Dist.URL != "" || p.Dist.Shasum != "" {
					res.Notes = append(res.Notes,
						"composer.lock dist metadata is recorded for inventory only and is never fetched or trusted as a hash reference")
				}
			}
		}
	case errors.Is(err, os.ErrNotExist):
		res.Notes = append(res.Notes, "composer.lock is missing; installed package versions cannot be pinned")
	default:
		res.Notes = append(res.Notes, "composer.lock unreadable: "+err.Error())
	}

	installed, err := readInstalledJSON(filepath.Join(root, "vendor", "composer", "installed.json"))
	switch {
	case err == nil:
		res.PackagesInstalled = len(installed)
		for _, p := range installed {
			if p.Name == "laravel/framework" {
				if res.Version == "" {
					res.Version = p.Version
					res.VersionSource = "vendor/composer/installed.json"
				} else if p.Version != res.Version {
					res.VersionConflicts = append(res.VersionConflicts,
						"composer.lock pins laravel/framework "+res.Version+" but vendor/composer/installed.json reports "+p.Version)
				}
			}
		}
	case errors.Is(err, os.ErrNotExist):
		res.Notes = append(res.Notes, "vendor/composer/installed.json is missing; dependencies may not be installed")
	default:
		res.Notes = append(res.Notes, "vendor/composer/installed.json unreadable: "+err.Error())
	}

	res.InventoryComplete = res.PackagesLocked > 0 && res.PackagesInstalled > 0
	if res.InventoryComplete {
		// Dev packages from packages-dev are legitimately absent from a
		// production vendor tree, so only non-dev entries are compared.
		lockedNonDev := len(lock.Packages)
		if lockedNonDev != res.PackagesInstalled {
			res.VersionConflicts = append(res.VersionConflicts,
				"composer.lock lists "+itoa(lockedNonDev)+" non-dev packages but installed.json reports "+itoa(res.PackagesInstalled))
		}
	}
	return res, nil
}

// readComposerJSON parses the require map of a composer.json file.
func readComposerJSON(path string) (map[string]string, error) {
	data, err := readFileBounded(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Require map[string]string `json:"require"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Require == nil {
		doc.Require = map[string]string{}
	}
	return doc.Require, nil
}

// composerLock models the two package lists of a lock file.
type composerLock struct {
	Packages    []lockedPackage `json:"packages"`
	PackagesDev []lockedPackage `json:"packages-dev"`
}

func readComposerLock(path string) (composerLock, error) {
	var lock composerLock
	data, err := readFileBounded(path)
	if err != nil {
		return lock, err
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return lock, err
	}
	return lock, nil
}

// readInstalledJSON handles both installed.json v1 (array) and v2 ({packages: []}).
func readInstalledJSON(path string) ([]lockedPackage, error) {
	data, err := readFileBounded(path)
	if err != nil {
		return nil, err
	}
	var v2 struct {
		Packages    []lockedPackage `json:"packages"`
		PackagesDev []lockedPackage `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &v2); err == nil && v2.Packages != nil {
		return append(v2.Packages, v2.PackagesDev...), nil
	}
	var v1 []lockedPackage
	if err := json.Unmarshal(data, &v1); err != nil {
		return nil, errors.New("installed.json is neither v1 array nor v2 object")
	}
	return v1, nil
}

func readFileBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > composerLockMaxBytes {
		return nil, errors.New("metadata file exceeds the read limit")
	}
	buf := make([]byte, st.Size())
	_, err = f.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func sortPackages(p []PackageInfo) {
	for i := 0; i < len(p); i++ {
		for j := i + 1; j < len(p); j++ {
			if p[j].Name < p[i].Name {
				p[i], p[j] = p[j], p[i]
			}
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return strings.TrimSpace(string(b[i:]))
}
