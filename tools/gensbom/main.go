// Command gensbom writes a CycloneDX 1.5 software bill of materials for the
// RONDA release candidate.
//
// RONDA is standard-library-only: go.mod declares no external modules, so
// the SBOM records the application component, the Go toolchain as the build
// tool, and explicitly states that there are no third-party components.
// Licenses are recorded only where reliably known: the project's own MIT
// license comes from the LICENSE file; the toolchain entry states the Go
// version without inventing a license identifier.
//
// The output is deterministic: the serial number is derived from a SHA-256
// of the identity fields (RFC 4122 name-based UUID v5 layout) and the
// timestamp comes from SOURCE_DATE_EPOCH via the -timestamp flag.
//
// Usage (invoked by scripts/package-release.sh):
//
//	go run ./tools/gensbom -out dist/SBOM.cdx.json \
//	  -version 0.1.0 -rules builtin-5 -commit dev \
//	  -go-version go1.27.3 -timestamp 2026-11-01T00:00:00Z
package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

type licenseChoice struct {
	License struct {
		ID string `json:"id"`
	} `json:"license"`
}

type component struct {
	BOMRef     string          `json:"bom-ref,omitempty"`
	Type       string          `json:"type"`
	Name       string          `json:"name"`
	Version    string          `json:"version"`
	PURL       string          `json:"purl,omitempty"`
	Licenses   []licenseChoice `json:"licenses,omitempty"`
	Properties []property      `json:"properties,omitempty"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type metadata struct {
	Timestamp string `json:"timestamp"`
	Tools     struct {
		Components []component `json:"components,omitempty"`
	} `json:"tools"`
	Component  *component `json:"component,omitempty"`
	Properties []property `json:"properties,omitempty"`
}

type sbom struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  int         `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     metadata    `json:"metadata"`
	Components   []component `json:"components"`
	Dependencies []struct {
		Ref          string   `json:"ref"`
		Dependencies []string `json:"dependsOn"`
	} `json:"dependencies"`
}

func main() {
	out := flag.String("out", "dist/SBOM.cdx.json", "output path")
	version := flag.String("version", "", "application version")
	rules := flag.String("rules", "", "detection rules version")
	commit := flag.String("commit", "dev", "build commit identifier")
	goVersion := flag.String("go-version", "", "Go toolchain version")
	ts := flag.String("timestamp", "", "SBOM timestamp (from SOURCE_DATE_EPOCH)")
	flag.Parse()

	if *version == "" || *goVersion == "" || *ts == "" {
		fmt.Fprintln(os.Stderr, "gensbom: -version, -go-version and -timestamp are required")
		os.Exit(2)
	}

	// Name-based UUID v5 (URL namespace style) over the identity string.
	sum := sha256.Sum256([]byte("ronda|" + *version + "|" + *commit))
	var uuid [16]byte
	copy(uuid[:], sum[:16])
	uuid[6] = (uuid[6] & 0x0f) | 0x50 // version 5
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // RFC 4122 variant
	serial := fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])

	comp := &component{
		BOMRef:  "pkg:generic/Lutfifakee-Project/ronda@" + *version,
		Type:    "application",
		Name:    "ronda",
		Version: *version,
		PURL:    "pkg:generic/Lutfifakee-Project/ronda@" + *version,
	}
	var mit licenseChoice
	mit.License.ID = "MIT" // declared in the project LICENSE file
	comp.Licenses = []licenseChoice{mit}
	comp.Properties = []property{
		{Name: "ronda:rulesVersion", Value: *rules},
		{Name: "ronda:commit", Value: *commit},
		{Name: "ronda:dependencies", Value: "none (Go standard library only, per go.mod)"},
	}

	var b sbom
	b.BOMFormat = "CycloneDX"
	b.SpecVersion = 15
	b.SerialNumber = serial
	b.Version = 1
	b.Metadata.Timestamp = *ts
	b.Metadata.Tools.Components = []component{{
		Type: "toolchain", Name: "Go toolchain", Version: *goVersion,
	}}
	b.Metadata.Component = comp
	b.Metadata.Properties = []property{
		{Name: "ronda:licenseBasis", Value: "LICENSE file (MIT), declared by the project owner"},
		{Name: "ronda:licenseConfidence", Value: "declared; third-party components absent"},
	}
	// go.mod declares no external modules: the component list is empty on
	// purpose, and the dependency graph has a single root with no edges.
	b.Components = []component{}
	b.Dependencies = []struct {
		Ref          string   `json:"ref"`
		Dependencies []string `json:"dependsOn"`
	}{{Ref: comp.BOMRef, Dependencies: []string{}}}

	data, err := json.MarshalIndent(&b, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "gensbom: %v\n", err)
		os.Exit(1)
	}
	data = append(data, '\n')
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "gensbom: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("gensbom: wrote %s\n", *out)
}
