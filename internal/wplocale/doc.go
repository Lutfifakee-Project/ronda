// Package wplocale performs static, read-only analysis of WordPress
// package-locale metadata and derives a confidence-qualified locale used by
// checksum verification.
//
// # Scope and guarantees
//
//   - Pure static analysis: PHP files are read as bytes and tokenized; PHP is
//     never executed and no database connections are made.
//   - Read-only: nothing in this package writes to scanned files.
//   - Standard library only.
//
// # Locale semantics implemented
//
// WordPress localized distributions (ja, de_DE, ...) are produced from the
// en_US source tree by substituting $wp_local_package in
// wp-includes/version.php at build time. The official en_US distribution does
// NOT contain the marker at all. Consequently a missing marker is inherently
// ambiguous: it may be an official en_US installation, or a modified/stripped
// file. This package therefore never treats missing metadata as proof of
// en_US.
//
// Precedence, highest first:
//
//  1. Explicit --wp-locale override (operator-provided, validated).
//  2. Reliable $wp_local_package marker in wp-includes/version.php.
//  3. Nothing. Runtime WPLANG (wp-config.php) is recorded separately and
//     never establishes the package locale.
//
// If the package locale cannot be established reliably (marker missing,
// empty, dynamic, malformed, or conflicting), the assessment is UNVERIFIED.
// A legacy checksum flow may opt into an en_US assumption via
// Options.AllowEnUSFallback; such assessments remain UNVERIFIED, are marked
// Inferred with low confidence, and any checksum verdict must be reported as
// provisional (see ChecksumGate).
package wplocale
