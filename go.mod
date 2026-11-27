module github.com/Lutfifakee-Project/ronda

go 1.21

// The authoritative release build toolchain. RONDA ships as a standalone
// binary, so this line pins the compiler/standard library that builds the
// release artifacts: with GOTOOLCHAIN=auto (the default) any Go >= 1.21
// selects go1.27.4 for this module; with GOTOOLCHAIN=local it fails closed.
// The module language level stays 1.21: the source uses no newer language
// features, and this is a minimum, not a requirement on the binary runtime.
//
// Upgrade history: go1.27.3 -> go1.27.4 (GO-2026-6859, net/http
// MaxBytesReader header race; fixed in net/http@go1.27.4). Toolchain archive
// sha256-verified against the official go.dev download JSON before use.
toolchain go1.27.4
