package drupal

import (
	"fmt"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/official"
)

// Official drupal.org reference endpoints. Package variables so tests can
// point them at a local reference server; production always uses the
// official hosts listed in the allowlist below.
var (
	releasePageBase = "https://www.drupal.org/project/drupal/releases/"
	archiveBase     = "https://ftp.drupal.org/files/projects/"
)

// officialHosts is the static allowlist for the Drupal reference flow.
// The archive host is separate from the page host: the SHA-256 reference and
// the archive download travel over different official origins.
func officialHosts(pageBase, archiveBase string) []official.Host {
	return []official.Host{
		{Host: hostOf(pageBase)},
		{Host: hostOf(archiveBase)},
	}
}

func hostOf(rawURL string) string {
	u := rawURL
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexByte(u, '/'); i >= 0 {
		u = u[:i]
	}
	return u
}

// releasePageURL returns the official release page for a stable version.
func releasePageURL(version string) string {
	return releasePageBase + version
}

// archiveURL returns the official tar.gz archive for a stable version.
func archiveURL(version string) string {
	return archiveBase + "drupal-" + version + ".tar.gz"
}

// parseReleasePage extracts the SHA-256 digest of the version's tar.gz
// archive from the official release page HTML.
//
// The page layout (one download link per release file, each followed by a
// SHA-256 field) has been stable for years; any deviation fails parsing and
// the caller reports UNVERIFIED rather than trusting a guessed value.
func parseReleasePage(page []byte, version string) (digest string, err error) {
	const linkClass = `class="download"`
	const hashClass = `field-content hash">`

	want := "drupal-" + version + ".tar.gz"

	type pair struct{ url, hash string }
	var pairs []pair

	linkIdx := indexOfAll(page, []byte(linkClass))
	hashIdx := indexOfAll(page, []byte(hashClass))

	for _, li := range linkIdx {
		urlBytes, ok := extractQuotedHrefBefore(page, li)
		if !ok || !strings.HasSuffix(string(urlBytes), want) {
			continue
		}
		// The first SHA-256 field after this link belongs to this file row.
		var hash string
		for _, hi := range hashIdx {
			if hi <= li {
				continue
			}
			start := hi + len(hashClass)
			end := indexOfByte(page[start:], '<')
			if end < 0 {
				continue
			}
			hexValue := strings.TrimSpace(string(page[start : start+end]))
			if isHex64(hexValue) {
				hash = strings.ToLower(hexValue)
				break
			}
		}
		if hash == "" {
			return "", fmt.Errorf("release page has no SHA-256 for %s", want)
		}
		pairs = append(pairs, pair{url: string(urlBytes), hash: hash})
	}

	if len(pairs) == 0 {
		return "", fmt.Errorf("release page lists no download link for %s", want)
	}
	if len(pairs) > 1 {
		return "", fmt.Errorf("release page lists %d candidate links for %s", len(pairs), want)
	}
	return pairs[0].hash, nil
}

// extractQuotedHrefBefore finds the href="..." whose closing quote ends just
// before the anchor class at index li.
func extractQuotedHrefBefore(page []byte, li int) ([]byte, bool) {
	const href = `href="`
	hi := lastIndexOf(page, []byte(href), li)
	if hi < 0 {
		return nil, false
	}
	start := hi + len(href)
	end := indexOfByte(page[start:], '"')
	if end < 0 {
		return nil, false
	}
	return page[start : start+end], true
}

func indexOfAll(data []byte, needle []byte) []int {
	var out []int
	for i := 0; ; {
		j := indexOfFrom(data, needle, i)
		if j < 0 {
			return out
		}
		out = append(out, j)
		i = j + 1
	}
}

func indexOfFrom(data, needle []byte, from int) int {
	limit := len(data) - len(needle)
	for i := from; i <= limit; i++ {
		if matchAt(data, needle, i) {
			return i
		}
	}
	return -1
}

func lastIndexOf(data, needle []byte, before int) int {
	limit := before - len(needle)
	for i := limit; i >= 0; i-- {
		if matchAt(data, needle, i) {
			return i
		}
	}
	return -1
}

func matchAt(data, needle []byte, at int) bool {
	if at < 0 || at+len(needle) > len(data) {
		return false
	}
	for i := range needle {
		if data[at+i] != needle[i] {
			return false
		}
	}
	return true
}

func indexOfByte(data []byte, b byte) int {
	for i := range data {
		if data[i] == b {
			return i
		}
	}
	return -1
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
