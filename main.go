// Command ronda is the RONDA local Linux security scanner.
//
// RONDA is read-only: it never modifies scanned files, never executes scanned
// PHP and never changes system configuration.
package main

import (
	"os"

	"github.com/Lutfifakee-Project/ronda/cmd"
)

func main() {
	os.Exit(cmd.Execute(os.Args[1:]))
}
