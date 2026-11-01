package joomla

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/official"
)

// Official Joomla reference endpoints. Package variables so tests can point
// them at a local reference server.
var (
	downloadsBase = "https://downloads.joomla.org"
	// githubAPIBase hosts the official joomla/joomla-cms release metadata. The
	// GitHub release for a stable tag publishes SHA-256 checksums for the same
	// prebuilt full packages that downloads.joomla.org distributes; it is used
	// as an independent second source for the exact archive, never as a
	// substitute for the official downloads page.
	githubAPIBase = "https://api.github.com"
)

// officialHosts is the static allowlist for the Joomla reference flow.
// downloads.joomla.org 303-redirects full-package downloads to its signed
// official S3 mirror; that exact bucket prefix is allowlisted explicitly.
// api.github.com is allowlisted only for the joomla-cms repository metadata.
func officialHosts() []official.Host {
	return []official.Host{
		{Host: hostOf(downloadsBase)},
		{Host: "s3-us-west-2.amazonaws.com", PathPrefix: "/joomla-official-downloads/"},
		{Host: hostOf(githubAPIBase), PathPrefix: "/repos/joomla/joomla-cms/"},
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

// releasePageURL returns the official version download page for a stable
// M.M.P release, e.g. 5.2.0 -> .../cms/joomla5/5-2-0.
func releasePageURL(version string) string {
	major := version[:strings.IndexByte(version, '.')]
	dir := strings.ReplaceAll(version, ".", "-")
	return downloadsBase + "/cms/joomla" + major + "/" + dir
}

// expectedArchiveFile is the full package file name for a version as linked
// on the downloads page (dash-separated, e.g. Joomla_5-2-0-Stable-Full_Package.tar.gz).
func expectedArchiveFile(version string) string {
	dashed := strings.ReplaceAll(version, ".", "-")
	return fmt.Sprintf("Joomla_%s-Stable-Full_Package.tar.gz", dashed)
}

// publishedDigests is the authenticated reference for one release.
type publishedDigests struct {
	PageURL    string
	ArchiveURL string
	MD5        string
	SHA1       string
}

// githubReleaseURL is the release metadata endpoint for one exact tag.
func githubReleaseURL(version string) string {
	return githubAPIBase + "/repos/joomla/joomla-cms/releases/tags/" + version
}

// fetchGitHubSHA256 returns the SHA-256 that the official joomla/joomla-cms
// GitHub release publishes for the full-package tar.gz of this exact version.
// Any failure (network, rate limit, unexpected shape) is reported to the
// caller, which falls back to the honest LEGACY_DIGEST_MATCH category; the
// fallback never invents a digest.
func fetchGitHubSHA256(ctx context.Context, client *official.Client, version string) (string, error) {
	body, err := client.Get(ctx, githubReleaseURL(version))
	if err != nil {
		return "", err
	}
	var release struct {
		TagName string `json:"tag_name"`
		Body    string `json:"body"`
	}
	if err := json.Unmarshal(body, &release); err != nil {
		return "", fmt.Errorf("GitHub release response could not be parsed: %w", err)
	}
	if release.TagName != version {
		return "", fmt.Errorf("GitHub release tag %q does not match version %q", release.TagName, version)
	}
	return parseGitHubReleaseSHA256([]byte(release.Body), version)
}

// parseGitHubReleaseSHA256 extracts the SHA-256 for the full-package tar.gz
// from the release body. The parse is deliberately strict: only the "New
// Joomla! Installations" checksum table is considered (never the update
// package section), only the row whose asset link names the exact
// Joomla_<version>-Stable-Full_Package.tar.gz asset, and only when that row
// carries exactly one backtick-quoted 64-hex digest.
func parseGitHubReleaseSHA256(body []byte, version string) (string, error) {
	section := body
	i := indexOf(body, []byte("New Joomla! Installations"))
	if i < 0 {
		return "", fmt.Errorf("GitHub release body has no New Installations checksum section")
	}
	section = section[i:]
	if i := indexOf(section, []byte("Update from a previous version")); i >= 0 {
		section = section[:i] // update-package checksums must never leak in here
	}
	wantAsset := "Joomla_" + version + "-Stable-Full_Package.tar.gz"
	wantLink := "](https://github.com/joomla/joomla-cms/releases/download/" + version + "/" + wantAsset + ")"
	for _, line := range bytes.Split(section, []byte("\n")) {
		row := strings.TrimSpace(string(line))
		if !strings.HasPrefix(row, "|") || !strings.Contains(row, wantLink) {
			continue
		}
		digests := backtickedHex(row)
		if len(digests) != 1 {
			return "", fmt.Errorf("GitHub checksum row for %s carries %d digest cells, want exactly 1", wantAsset, len(digests))
		}
		return digests[0], nil
	}
	return "", fmt.Errorf("GitHub release body lists no SHA-256 row for %s", wantAsset)
}

// backtickedHex returns every backtick-quoted 64-character hex token in a
// markdown table row, lowercased.
func backtickedHex(row string) []string {
	var out []string
	for i := 0; i+1 < len(row); i++ {
		if row[i] != '`' {
			continue
		}
		end := strings.IndexByte(row[i+1:], '`')
		if end < 0 {
			break
		}
		token := row[i+1 : i+1+end]
		if len(token) == 64 && isHex(token) {
			out = append(out, strings.ToLower(token))
		}
		i += end + 1
	}
	return out
}

// digests converts the parsed pair into refcheck.Digest values.
func (p publishedDigests) digests() []refDigest {
	var out []refDigest
	if p.MD5 != "" {
		out = append(out, refDigest{Algorithm: "md5", Hex: p.MD5})
	}
	if p.SHA1 != "" {
		out = append(out, refDigest{Algorithm: "sha1", Hex: p.SHA1})
	}
	return out
}

// key combines the published digests for the cache key.
func (p publishedDigests) key() string {
	return p.MD5 + p.SHA1
}

// describe renders the digest pair for reports.
func (p publishedDigests) describe() (algo, shown string) {
	names := make([]string, 0, 2)
	values := make([]string, 0, 2)
	for _, d := range p.digests() {
		names = append(names, d.Algorithm)
		values = append(values, d.Algorithm+":"+d.Hex)
	}
	return strings.Join(names, "+"), strings.Join(values, " ")
}

// parseDownloadsPage extracts the MD5 and SHA-1 signatures and the archive
// URL of the version's Full Package (.tar.gz) from the official downloads
// page. Each package is presented in an ars-item block with a title, the
// signature list and a download link; any deviation fails parsing and the
// caller reports UNVERIFIED rather than trusting a guess.
func parseDownloadsPage(page []byte, version string) (publishedDigests, error) {
	var out publishedDigests
	wantTitle := fmt.Sprintf("Joomla! %s Full Package", version)
	wantFile := expectedArchiveFile(version)

	blocks := splitBlocks(page, []byte("ars-item-"))
	for i, block := range blocks {
		titleIdx := indexOf(block, []byte("Full Package"))
		if titleIdx < 0 {
			continue
		}
		title := h3ContentBefore(block, titleIdx)
		if !strings.Contains(title, ".tar.gz") {
			continue // zip/zst and update packages are not our reference
		}
		if !strings.Contains(cleanTitle(title), wantTitle) {
			continue // a different version's block
		}
		// The marker also occurs inside "ars-item-description", so a
		// package can be split into a title block and a body block; the
		// signatures and the download link may live in either.
		search := block
		if i+1 < len(blocks) {
			combined := make([]byte, 0, len(block)+len(blocks[i+1]))
			combined = append(combined, block...)
			combined = append(combined, blocks[i+1]...)
			search = combined
		}
		href, ok := extractHrefContaining(search, wantFile)
		if !ok {
			continue
		}
		if !strings.HasPrefix(href, "/cms/") {
			return out, fmt.Errorf("unexpected archive link %q on the downloads page", href)
		}
		md5, okMD5 := signatureAfter(search, "MD5 Signature", 32)
		sha1, okSHA1 := signatureAfter(search, "SHA1 Signature", 40)
		if !okMD5 && !okSHA1 {
			return out, fmt.Errorf("downloads page block for %s has no published digest", version)
		}
		out.PageURL = releasePageURL(version)
		out.ArchiveURL = downloadsBase + href
		out.MD5 = md5
		out.SHA1 = sha1
		return out, nil
	}
	return out, fmt.Errorf("downloads page lists no Full Package (.tar.gz) block for %s", version)
}

// h3ContentBefore returns the inner text of the <h3> element that precedes
// position at, with markup stripped.
func h3ContentBefore(block []byte, at int) string {
	hStart := lastIndexOfBefore(block, []byte("<h3"), at)
	if hStart < 0 {
		return ""
	}
	gt := indexOfByte(block[hStart:], '>')
	if gt < 0 {
		return ""
	}
	contentStart := hStart + gt + 1
	end := indexOf(block[contentStart:], []byte("</h3>"))
	if end < 0 {
		return ""
	}
	return stripTags(string(block[contentStart : contentStart+end]))
}

// stripTags removes any residual inner markup from a heading.
func stripTags(s string) string {
	var b strings.Builder
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteByte(s[i])
			}
		}
	}
	return b.String()
}

func lastIndexOfBefore(data, needle []byte, before int) int {
	limit := before - len(needle)
	for i := limit; i >= 0; i-- {
		if matchAt(data, needle, i) {
			return i
		}
	}
	return -1
}

// cleanTitle removes HTML entities and markup remnants from a block title.
func cleanTitle(title string) string {
	title = strings.NewReplacer("&nbsp;", " ", "&#160;", " ").Replace(title)
	return strings.Join(strings.Fields(title), " ")
}

// splitBlocks cuts the page into package blocks starting at each marker.
func splitBlocks(page []byte, marker []byte) [][]byte {
	var out [][]byte
	idx := indexOfAll(page, marker)
	for i, start := range idx {
		end := len(page)
		if i+1 < len(idx) {
			end = idx[i+1]
		}
		out = append(out, page[start:end])
	}
	return out
}

// extractHrefContaining finds an href whose value contains needle.
func extractHrefContaining(block []byte, needle string) (string, bool) {
	const href = `href="`
	for _, hi := range indexOfAll(block, []byte(href)) {
		start := hi + len(href)
		end := indexOfByte(block[start:], '"')
		if end < 0 {
			continue
		}
		value := string(block[start : start+end])
		if strings.Contains(value, needle) {
			// Strip the format= query suffix; the plain path serves the file.
			if q := strings.IndexByte(value, '?'); q >= 0 {
				value = value[:q]
			}
			return value, true
		}
	}
	return "", false
}

// signatureAfter extracts the hex value in the <dd> following a signature
// label, validating its length.
func signatureAfter(block []byte, label string, wantLen int) (string, bool) {
	li := indexOf(block, []byte(label))
	if li < 0 {
		return "", false
	}
	const dd = "<dd>"
	di := indexOf(block[li:], []byte(dd))
	if di < 0 {
		return "", false
	}
	start := li + di + len(dd)
	end := indexOfByte(block[start:], '<')
	if end < 0 {
		return "", false
	}
	value := strings.TrimSpace(string(block[start : start+end]))
	if len(value) != wantLen || !isHex(value) {
		return "", false
	}
	return strings.ToLower(value), true
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

func indexOf(data, needle []byte) int {
	return indexOfFrom(data, needle, 0)
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

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
