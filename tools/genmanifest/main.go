// Command genmanifest writes the release manifest for a RONDA release
// candidate directory. It is deterministic: given the same inputs it emits
// byte-identical JSON (no wall-clock timestamps; the build date comes from
// SOURCE_DATE_EPOCH via the -date flag).
//
// Usage (invoked by scripts/package-release.sh):
//
//	go run ./tools/genmanifest \
//	  -dist dist -version 0.1.0 -rules builtin-5 -commit dev \
//	  -date 2026-11-01T00:00:00Z -go-version go1.27.3 \
//	  -signing-status NOT_CONFIGURED -ldflags "-s -w ..." \
//	  -source-date-epoch 1798000000
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type artifact struct {
	Filename     string `json:"filename"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	SHA256       string `json:"sha256"`
	SizeBytes    int64  `json:"sizeBytes"`
	Kind         string `json:"kind"` // binary or archive
}

type manifest struct {
	Product         string     `json:"product"`
	Version         string     `json:"version"`
	RulesVersion    string     `json:"rulesVersion"`
	Commit          string     `json:"commit"`
	BuildDate       string     `json:"buildDate"`
	BuildDateSource string     `json:"buildDateSource"`
	GoVersion       string     `json:"goVersion"`
	TargetOS        string     `json:"targetOs"`
	BuildFlags      string     `json:"buildFlags"`
	SigningStatus   string     `json:"signingStatus"`
	Reproducible    bool       `json:"reproducible"`
	SourceDateEpoch int64      `json:"sourceDateEpoch"`
	Artifacts       []artifact `json:"artifacts"`
	GeneratedBy     string     `json:"generatedBy"`
	Notes           []string   `json:"notes"`
}

func main() {
	dist := flag.String("dist", "dist", "release directory to scan")
	version := flag.String("version", "", "application version")
	rules := flag.String("rules", "", "detection rules version")
	commit := flag.String("commit", "dev", "build commit identifier")
	date := flag.String("date", "unknown", "build date (derived from SOURCE_DATE_EPOCH)")
	goVersion := flag.String("go-version", "", "Go toolchain version")
	signing := flag.String("signing-status", "NOT_CONFIGURED", "release signature trust status")
	ldflags := flag.String("ldflags", "", "linker flags used for the build")
	epoch := flag.Int64("source-date-epoch", -1, "SOURCE_DATE_EPOCH used for the build")
	out := flag.String("out", "", "output path (default <dist>/release-manifest.json)")
	flag.Parse()

	if *version == "" || *rules == "" || *goVersion == "" {
		fmt.Fprintln(os.Stderr, "genmanifest: -version, -rules and -go-version are required")
		os.Exit(2)
	}

	names := []string{
		"ronda-linux-amd64",
		"ronda-linux-arm64",
		"ronda-linux-amd64.tar.gz",
		"ronda-linux-arm64.tar.gz",
	}
	arts := make([]artifact, 0, len(names))
	for _, name := range names {
		p := filepath.Join(*dist, name)
		fi, err := os.Stat(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue // archives may not be packaged yet
			}
			fmt.Fprintf(os.Stderr, "genmanifest: %v\n", err)
			os.Exit(1)
		}
		h, err := fileSHA256(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "genmanifest: %v\n", err)
			os.Exit(1)
		}
		kind := "binary"
		if strings.HasSuffix(name, ".tar.gz") {
			kind = "archive"
		}
		arts = append(arts, artifact{
			Filename:     name,
			OS:           "linux",
			Architecture: archOf(name),
			SHA256:       h,
			SizeBytes:    fi.Size(),
			Kind:         kind,
		})
	}

	reproducible := *epoch >= 0
	dateSource := "not provided (unknown)"
	if reproducible {
		dateSource = "SOURCE_DATE_EPOCH"
	}

	m := manifest{
		Product:         "ronda",
		Version:         *version,
		RulesVersion:    *rules,
		Commit:          *commit,
		BuildDate:       *date,
		BuildDateSource: dateSource,
		GoVersion:       *goVersion,
		TargetOS:        "linux",
		BuildFlags:      *ldflags,
		SigningStatus:   *signing,
		Reproducible:    reproducible,
		SourceDateEpoch: *epoch,
		Artifacts:       arts,
		GeneratedBy:     "tools/genmanifest",
	}
	m.Notes = append(m.Notes,
		"Binaries are built with CGO_ENABLED=0, -trimpath and -ldflags \"-s -w\".",
		"SHA256SUMS covers the binaries and archives; the manifest and SBOM are metadata.",
		"Signing status NOT_CONFIGURED means no trusted public key is embedded; artifacts are checksum-verified but not publisher-authenticated.",
	)

	data, err := json.MarshalIndent(&m, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "genmanifest: %v\n", err)
		os.Exit(1)
	}
	data = append(data, '\n')
	outPath := *out
	if outPath == "" {
		outPath = filepath.Join(*dist, "release-manifest.json")
	}
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "genmanifest: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("genmanifest: wrote %s (%d artifacts)\n", outPath, len(m.Artifacts))
}

func archOf(name string) string {
	switch {
	case strings.Contains(name, "amd64"):
		return "amd64"
	case strings.Contains(name, "arm64"):
		return "arm64"
	default:
		return "unknown"
	}
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
